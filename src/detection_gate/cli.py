"""detection-gate command line.

  scan-sensor   which rules die because the sensor config never emits the
                event they need. Needs no SIEM at all.
  snapshot      capture a SIEM's schema and field population to a file, so
                later runs and the stage demo work offline.
  scan          full check: sensor config, then schema presence, then data
                population, producing FIREABLE / DEAD-ON-ARRIVAL / STARVED.

Exit codes, so a crash in CI does not read as a gate failure:

  0  ran, and nothing new is broken
  1  the gate found failures the baseline does not accept
  2  bad usage, or a missing dependency
  3  the tool itself failed
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import typer

from .explain import (
    EGRESS_CONTENTS,
    Explainer,
    Explanation,
    ExplanationCache,
    collect_causes,
    explain_run,
    strip_userinfo,
)
from .ingest import load_ingest_map
from . import __version__
from .gate import Baseline, apply_baseline, to_sarif
from .report import render_html, render_table
from .rules import ROUTING_FIELDS, find_rule_files, load_corpus, tree_fields
from .schema import DEFAULT_BATCH_SIZE, ElasticSchemaSource, SchemaReadError, SchemaSnapshot
from .sysmon import (
    load_profile,
    parse_unfilterable_event_ids,
    merge_event_id_maps,
    parse_event_id_map,
    parse_event_id_map_from_dirs,
    sysmon_event_id_space,
)
from .verdict import evaluate, summarise

EXIT_OK = 0
EXIT_NEW_FAILURES = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

# The one place a credential may come from. Not a flag: a flag lands in ps
# output, /proc/<pid>/cmdline, shell history and any CI log running under
# set -x, and a SIEM read credential is worth all three.
ELASTIC_API_KEY_ENV = "ELASTIC_API_KEY"

app = typer.Typer(add_completion=False, pretty_exceptions_show_locals=False)
log = logging.getLogger("detection-gate")

SYSMON_CHANNELS = {"Microsoft-Windows-Sysmon/Operational"}


# Named on the report, because the pipeline is the single most load-bearing
# input: a different one resolves different field names and produces a
# different number, and a reader who cannot see which was used cannot
# reproduce anything.
PIPELINE_NAME = "pySigma sysmon_pipeline() + ecs_windows()"


def _version(show: bool) -> None:
    if show:
        typer.echo(f"detection-gate {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def options(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log at DEBUG"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Log warnings and worse only"),
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Print the version and exit"
    ),
):
    """Find detections that cannot fire.

    Exit codes: 0 nothing new is broken, 1 the gate found new failures, 2 bad
    usage or a missing dependency, 3 the tool itself failed.
    """
    if verbose and quiet:
        raise typer.BadParameter("pass either --verbose or --quiet, not both")
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")


def _atomic(path: Path, writer, *, private: bool = False) -> None:
    """Write through a sibling temp file, so an interrupted run leaves no half file.

    The previous version wrote in place, and a Ctrl-C partway through left a
    truncated baseline.json that the next run read as gospel. `private`
    pre-creates the temp file 0600 rather than chmod-ing it afterwards, so the
    content is never briefly world-readable under the default umask.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        if private:
            os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        writer(tmp)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _write_text(path: Path, text: str, *, private: bool = False) -> None:
    _atomic(path, lambda p: p.write_text(text, encoding="utf-8"), private=private)


def _build_pipeline():
    from sigma.pipelines.elasticsearch import ecs_windows
    from sigma.pipelines.sysmon import sysmon_pipeline

    return sysmon_pipeline() + ecs_windows()


def _event_id_map(reference_config: Path, modular_root: Path | None):
    maps = [parse_event_id_map(reference_config)]
    if modular_root and modular_root.exists():
        maps.append(parse_event_id_map_from_dirs(modular_root))
    return merge_event_id_maps(*maps)


def _rules_from_file(path: Path) -> list[Path]:
    """Read rule paths from a file, one per line or NUL-separated.

    NUL separation is the reason this option exists: it lets a pull-request
    workflow hand over `git diff -z --name-only` output without the list ever
    becoming a shell word, and it survives a filename containing a space.
    """
    raw = path.read_bytes()
    parts = raw.split(b"\0") if b"\0" in raw else raw.splitlines()
    names = [p.decode("utf-8", "surrogateescape").strip() for p in parts]
    return [Path(n) for n in names if n and not n.startswith("#")]


@app.command("scan-sensor")
def scan_sensor(
    rules_dir: Path = typer.Option(..., help="SigmaHQ rules directory"),
    config: list[Path] = typer.Option(..., "--config", help="Sysmon config XML, repeatable"),
    reference_config: Path = typer.Option(
        ..., help="Config whose documented section headers supply the event ID map"
    ),
    modular_root: Path = typer.Option(
        None, help="sysmon-modular checkout, for event IDs newer than the reference"
    ),
    subdir: list[str] = typer.Option(["windows"], help="Rule subdirectories to scan"),
    html_out: Path = typer.Option(None, help="Write an HTML report here"),
    json_out: Path = typer.Option(None, help="Write machine-readable results here"),
):
    """Which rules die because the sensor never emits the event they need."""
    rule_files = find_rule_files(rules_dir, list(subdir))
    typer.echo(f"resolving {len(rule_files)} rule files through the pipeline")
    corpus = load_corpus(rule_files, _build_pipeline)

    id_map = _event_id_map(reference_config, modular_root)
    id_space = sysmon_event_id_space(id_map)

    profiles = {}
    for path in config:
        profile = load_profile(
            path.stem, path, id_map,
            unfilterable=parse_unfilterable_event_ids(reference_config),
        )
        verdicts = [
            evaluate(
                rule,
                profile=profile,
                sensor_scope_channels=SYSMON_CHANNELS,
                sensor_event_id_space=id_space,
                ignore_fields=set(ROUTING_FIELDS),
            )
            for rule in corpus
        ]
        profiles[profile.name] = (profile, verdicts, summarise(verdicts))

    typer.echo(render_table(profiles))

    if html_out:
        _write_text(html_out, render_html(profiles), private=True)
        typer.echo(f"wrote {html_out}")
    if json_out:
        payload = {
            name: {
                "summary": summary,
                "dead": [
                    {
                        "rule_id": v.rule_id,
                        "title": v.title,
                        "cause": v.cause.value if v.cause else None,
                        "missing_event_ids": v.missing_event_ids,
                        "missing_fields": v.missing_fields,
                        "detail": v.detail,
                    }
                    for v in verdicts
                    if v.is_dead
                ],
            }
            for name, (_p, verdicts, summary) in profiles.items()
        }
        _write_text(json_out, json.dumps(payload, indent=2), private=True)
        typer.echo(f"wrote {json_out}")


def _checked_url(url: str) -> str:
    """Refuse a URL carrying a secret, and say where the secret belongs instead."""
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise typer.BadParameter(
            "the URL carries a username or password. Anything on the command line "
            f"is visible in ps output and in CI logs: put the credential in "
            f"${ELASTIC_API_KEY_ENV} and pass --url with the host only, as "
            f"{strip_userinfo(url)}",
            param_hint="--url",
        )
    if not parsed.hostname:
        raise typer.BadParameter(f"no host in {url!r}", param_hint="--url")
    return url


def _population_target(corpus) -> set[str]:
    """Every field the corpus's conditions read, on any branch.

    Not RuleFields.fields: that is the required set, the intersection across OR
    branches. A field read only on one branch was then never asked about, came
    back as unpopulated by omission, and produced a STARVED verdict nothing had
    measured.
    """
    target: set[str] = set()
    for rule in corpus:
        target |= tree_fields(rule.condition_tree)
        target |= rule.fields | rule.filter_only_fields
    return target


@app.command("snapshot")
def snapshot(
    url: str = typer.Option("http://localhost:9200", help="Elasticsearch or OpenSearch URL"),
    index_pattern: str = typer.Option(..., help="Index pattern to inspect"),
    out: Path = typer.Option(..., help="Where to write the snapshot"),
    window: str = typer.Option("now-90d", help="Population window"),
    time_field: str = typer.Option("@timestamp", help="Time field for the window filter"),
    rules_dir: Path = typer.Option(None, help="Limit population checks to fields this corpus reads"),
    subdir: list[str] = typer.Option(["windows"], help="Rule subdirectories"),
    ca_cert: Path = typer.Option(
        None, help="CA bundle for a cluster with a private certificate authority"
    ),
    request_timeout: float = typer.Option(60.0, help="Seconds to wait for one request"),
    batch_size: int = typer.Option(
        DEFAULT_BATCH_SIZE, help="Fields per population request. Lower it on a busy cluster"
    ),
    request_pause: float = typer.Option(
        0.0, help="Seconds to wait between population requests"
    ),
    dry_run: bool = typer.Option(
        False, help="Say what would be asked of the cluster, and connect to nothing"
    ),
):
    """Capture a SIEM's schema and field population so runs can go offline.

    The API key is read from $ELASTIC_API_KEY and from nowhere else. TLS
    verification is always on; point --ca-cert at your bundle if the cluster
    uses a private certificate authority.
    """
    _checked_url(url)
    safe_url = strip_userinfo(url)
    api_key = os.environ.get(ELASTIC_API_KEY_ENV, "").strip()

    fields_of_interest = None
    if rules_dir:
        corpus = load_corpus(find_rule_files(rules_dir, list(subdir)), _build_pipeline)
        fields_of_interest = _population_target(corpus)
        typer.echo(f"corpus reads {len(fields_of_interest)} distinct fields")

    if dry_run:
        count = len(fields_of_interest) if fields_of_interest is not None else 0
        requests = -(-count // batch_size)
        typer.echo(f"would read {safe_url}, index pattern {index_pattern}")
        typer.echo("  field_caps: 1 request")
        typer.echo(
            "  population: every field in the index pattern"
            if fields_of_interest is None
            else f"  population: {count} fields over {window}, in "
                 f"{requests} request{'' if requests == 1 else 's'} of {batch_size}"
        )
        typer.echo(f"  authenticating with ${ELASTIC_API_KEY_ENV}"
                   if api_key else
                   f"  no ${ELASTIC_API_KEY_ENV} set, so the request would be unauthenticated")
        typer.echo(f"  would write {out}")
        return

    if not api_key:
        host = urlparse(url).hostname or ""
        if host not in ("localhost", "127.0.0.1", "::1"):
            typer.echo(
                f"no ${ELASTIC_API_KEY_ENV} in the environment. Create a read-only API "
                f"key on the index pattern and export it as ${ELASTIC_API_KEY_ENV}; "
                "it is deliberately not accepted as a flag.",
                err=True,
            )
            raise typer.Exit(EXIT_USAGE)
        log.warning("no %s set; connecting to %s unauthenticated", ELASTIC_API_KEY_ENV, safe_url)

    try:
        from elasticsearch import Elasticsearch
    except ModuleNotFoundError:
        typer.echo(
            'the snapshot command needs the Elasticsearch client: '
            'pip install "detection-gate[live]"',
            err=True,
        )
        raise typer.Exit(EXIT_USAGE)

    client_args: dict = {"request_timeout": request_timeout, "verify_certs": True}
    if api_key:
        client_args["api_key"] = api_key
    if ca_cert:
        client_args["ca_certs"] = str(ca_cert)

    source = ElasticSchemaSource(
        Elasticsearch(url, **client_args),
        index_pattern,
        batch_size=batch_size,
        request_pause=request_pause,
    )
    try:
        snap = source.snapshot(
            fields_of_interest=fields_of_interest, window=window, time_field=time_field
        )
    except SchemaReadError as exc:
        typer.echo(f"{safe_url} could not be read: {exc}", err=True)
        raise typer.Exit(EXIT_INTERNAL)

    _atomic(out, snap.save, private=True)
    if snap.populated is None:
        # No population measured is not the same as nothing populated, and a
        # snapshot that confused the two turned an empty window into a page of
        # starved rules.
        typer.echo(f"schema: {len(snap.fields)} fields, population not measured -> {out}")
        for note in snap.notes:
            typer.echo(f"  {note}")
    else:
        typer.echo(
            f"schema: {len(snap.fields)} fields, populated: "
            f"{len(snap.populated)} of {len(snap.checked_fields or [])} checked "
            f"in {window} -> {out}"
        )


@app.command("scan")
def scan(
    rules_dir: Path = typer.Option(None, help="Rules directory to scan in full"),
    rules: list[Path] = typer.Option(
        None, "--rules", help="Specific rule files to scan, repeatable. In a pull "
                              "request, pass the files the change touched: scanning "
                              "three rules takes a second, the whole corpus minutes"
    ),
    rules_from: Path = typer.Option(
        None, "--rules-from", help="File listing rule paths, one per line or "
                                   "NUL-separated. For a pull request, write "
                                   "`git diff -z --name-only` straight to it rather "
                                   "than expanding the list on a command line"
    ),
    base_dir: Path = typer.Option(
        None, help="Report rule paths relative to this directory, so SARIF lands on "
                   "a file the repository has. Defaults to the working directory"
    ),
    snapshot_file: Path = typer.Option(..., help="Schema snapshot from the snapshot command"),
    ingest_pipeline: Path = typer.Option(
        None,
        help="SIEM ingest pipeline definition, to tell mismapped fields from missing ones",
    ),
    config: Path = typer.Option(None, help="Sysmon config XML for the event-level check"),
    reference_config: Path = typer.Option(None, help="Config supplying the event ID map"),
    modular_root: Path = typer.Option(None, help="sysmon-modular checkout"),
    subdir: list[str] = typer.Option(["windows"], help="Rule subdirectories"),
    html_out: Path = typer.Option(None, help="Write an HTML report here"),
    explanations_file: Path = typer.Option(
        None,
        help="Cached advisory notes to include in the report. Not defaulted: a "
             "notes file shipped with the tool describes the environment it was "
             "written for, not yours",
    ),
    no_ai: bool = typer.Option(
        False, "--no-ai", help="Render with no advisory notes at all. Verdicts are "
                              "identical either way, and a test enforces that"
    ),
    reviewed: bool = typer.Option(
        False, help="State in the report that a human reviewed the advisory notes. "
                    "Only pass this if one did"
    ),
    baseline_file: Path = typer.Option(
        None, "--baseline", help="Failures already known and accepted. The gate "
                                 "reports only what got worse than this"
    ),
    fail_on_new: bool = typer.Option(
        False, "--fail-on-new", help="Exit non-zero when a rule fails that the "
                                     "baseline does not already accept"
    ),
    sarif_out: Path = typer.Option(
        None, help="Write SARIF here, so a code review annotates the rule file itself"
    ),
    json_out: Path = typer.Option(None, help="Write machine-readable results here"),
):
    """Full check: sensor config, schema presence, then data population."""
    sources = [bool(rules_dir), bool(rules), bool(rules_from)]
    if sum(sources) > 1:
        raise typer.BadParameter("pass one of --rules-dir, --rules or --rules-from")
    if not any(sources):
        raise typer.BadParameter(
            "pass --rules-dir to scan a corpus, or --rules / --rules-from to scan files"
        )

    scoped = not rules_dir
    if rules_from:
        rule_files = _rules_from_file(rules_from)
    elif rules:
        rule_files = list(rules)
    else:
        rule_files = find_rule_files(rules_dir, list(subdir))
    if not rule_files:
        typer.echo("no rule files matched; nothing to check")
        raise typer.Exit(EXIT_OK)

    corpus = load_corpus(rule_files, _build_pipeline)
    snap = SchemaSnapshot.load(snapshot_file)
    ingest_map = load_ingest_map(ingest_pipeline) if ingest_pipeline else None
    if ingest_map:
        typer.echo(
            f"ingest pipeline: {len(ingest_map.renamed)} renames, "
            f"{len(ingest_map.dropped)} fields removed after transformation"
        )

    profile = None
    id_space = None
    if config and reference_config:
        id_map = _event_id_map(reference_config, modular_root)
        id_space = sysmon_event_id_space(id_map)
        profile = load_profile(
            config.stem, config, id_map,
            unfilterable=parse_unfilterable_event_ids(reference_config),
        )

    verdicts = [
        evaluate(
            rule,
            profile=profile,
            schema_fields=snap.fields,
            populated_fields=snap.populated,
            checked_fields=snap.checked_fields,
            sensor_scope_channels=SYSMON_CHANNELS if profile else None,
            sensor_event_id_space=id_space,
            ingest_map=ingest_map,
            ignore_fields=set(ROUTING_FIELDS),
        )
        for rule in corpus
    ]
    summary = summarise(verdicts)
    name = profile.name if profile else snap.index_pattern
    typer.echo(render_table({name: (profile, verdicts, summary)}))

    if html_out:
        explanations = {}
        if not no_ai and explanations_file and explanations_file.exists():
            cache = ExplanationCache(explanations_file)
            explanations = {
                key: Explanation(**value) for key, value in cache.entries.items()
            }
            wanted = {c.key for c in collect_causes(verdicts)}
            missing = len(wanted - set(explanations))
            stale = len(set(explanations) - wanted)
            typer.echo(
                f"{len(explanations)} advisory notes loaded from {explanations_file}; "
                f"{len(wanted & set(explanations))} of {len(wanted)} causes covered, "
                f"{missing} without a note, {stale} not used by this run"
            )
        _write_text(
            html_out,
            render_html(
                {name: (profile, verdicts, summary)},
                explanations,
                snapshot={
                    "window": snap.window,
                    "taken_at": snap.taken_at,
                    "index_pattern": snap.index_pattern,
                },
                pipeline=PIPELINE_NAME,
                reviewed=reviewed,
            ),
            private=True,
        )
        typer.echo(f"wrote {html_out}")

    if json_out:
        _write_text(
            json_out,
            json.dumps(
                {
                    "summary": summary,
                    "verdicts": [
                        {
                            "rule_id": v.rule_id, "title": v.title, "path": v.path,
                            "verdict": v.verdict.value, "detail": v.detail,
                        }
                        for v in verdicts
                    ],
                },
                indent=2,
            ),
            private=True,
        )
        typer.echo(f"wrote {json_out}")

    # ------------------------------------------------------------- the gate
    #
    # Everything above answers "what is true". This answers "does this change
    # make it worse", which is the only question a pull request can act on.
    if not (baseline_file or fail_on_new or sarif_out):
        return

    baseline = Baseline.load(baseline_file) if baseline_file else Baseline()
    if baseline_file and not baseline_file.exists():
        typer.echo(
            f"{baseline_file} does not exist yet, so every failure counts as new. "
            "Run `detection-gate baseline` once to record what is already broken."
        )
    outcome = apply_baseline(verdicts, baseline, scoped=scoped)

    typer.echo("")
    typer.echo(f"  gate: {len(outcome.new_failures)} new, "
               f"{len(outcome.accepted_failures)} already accepted"
               + (f", {len(outcome.fixed)} fixed since the baseline" if outcome.fixed else ""))
    for item in outcome.new_failures[:20]:
        typer.echo(f"    {item.verdict.value:16} {item.title}")
        typer.echo(f"    {'':16} {item.detail}")
        if item.path:
            typer.echo(f"    {'':16} {item.path}")
    if len(outcome.new_failures) > 20:
        typer.echo(f"    ... and {len(outcome.new_failures) - 20} more")
    if outcome.not_assessed:
        # Said out loud rather than swallowed: a rule we could not judge is not
        # a rule that passed, and a gate that quietly treats it as one is worse
        # than no gate.
        typer.echo(f"  {len(outcome.not_assessed)} rules could not be assessed and were not judged")

    if sarif_out:
        # to_sarif reports item.path as it stands, so the paths are made
        # relative here rather than there. An absolute path is both unusable to
        # code scanning, which cannot place it on a line, and a disclosure: it
        # publishes the runner's directory layout into the repository's
        # security tab.
        _relativise(verdicts, base_dir or Path.cwd())
        _write_text(
            sarif_out,
            json.dumps(to_sarif(verdicts, outcome, tool="detection-gate", version=__version__), indent=2),
            private=True,
        )
        typer.echo(f"wrote {sarif_out}")

    if fail_on_new and not outcome.passed:
        raise typer.Exit(EXIT_NEW_FAILURES)


def _relativise(verdicts, base_dir: Path) -> None:
    base = base_dir.resolve()
    for item in verdicts:
        if not item.path:
            continue
        try:
            item.path = Path(item.path).resolve().relative_to(base)
            item.rel_path = str(item.path)
        except ValueError:
            # Outside the base directory, so there is no relative form that
            # names the same file. Leaving it absolute is wrong in the report
            # and worse in SARIF, but inventing a path would be worse still.
            log.warning("%s is outside %s; leaving the path as it is", item.path, base)


@app.command("baseline")
def baseline(
    rules_dir: Path = typer.Option(..., help="Rules directory"),
    snapshot_file: Path = typer.Option(..., help="Schema snapshot"),
    out: Path = typer.Option(Path("baseline.json"), help="Where to write the baseline"),
    ingest_pipeline: Path = typer.Option(None, help="SIEM ingest pipeline definition"),
    config: Path = typer.Option(None, help="Sysmon config XML"),
    reference_config: Path = typer.Option(None, help="Config supplying the event ID map"),
    modular_root: Path = typer.Option(None, help="sysmon-modular checkout"),
    subdir: list[str] = typer.Option(["windows"], help="Rule subdirectories"),
):
    """Record what is already broken, so the gate can fail only on what gets worse.

    Run this once when you adopt the gate. Every failure it records is a
    failure the gate will stop reporting, so read the file before committing
    it: this is the list of things the team is deciding to live with, and it
    should get shorter over time rather than longer.
    """
    verdicts = _run_verdicts(
        rules_dir, subdir, snapshot_file, ingest_pipeline, config, reference_config, modular_root
    )
    current = Baseline.from_verdicts(verdicts)
    previous = Baseline.load(out) if out.exists() else None
    _atomic(out, current.save)
    typer.echo(f"wrote {out} with {len(current.entries)} accepted failures")
    if previous:
        added = len(set(current.entries) - set(previous.entries))
        removed = len(set(previous.entries) - set(current.entries))
        typer.echo(f"  {added} added, {removed} removed since the previous baseline")


@app.command("diff")
def diff(
    rules_dir: Path = typer.Option(..., help="SigmaHQ rules directory"),
    before: Path = typer.Option(..., help="Schema snapshot taken earlier"),
    after: Path = typer.Option(..., help="Schema snapshot taken now"),
    ingest_pipeline: Path = typer.Option(None, help="SIEM ingest pipeline definition"),
    config: Path = typer.Option(None, help="Sysmon config XML"),
    reference_config: Path = typer.Option(None, help="Config supplying the event ID map"),
    modular_root: Path = typer.Option(None, help="sysmon-modular checkout"),
    subdir: list[str] = typer.Option(["windows"], help="Rule subdirectories"),
):
    """Show which rules changed verdict between two schema snapshots.

    Same rules, same sensor config, two points in time. Anything that moves
    here moved because the telemetry changed, which is the question a coverage
    map cannot answer.
    """
    corpus = load_corpus(find_rule_files(rules_dir, list(subdir)), _build_pipeline)
    snap_before = SchemaSnapshot.load(before)
    snap_after = SchemaSnapshot.load(after)
    ingest_map = load_ingest_map(ingest_pipeline) if ingest_pipeline else None

    profile = None
    id_space = None
    if config and reference_config:
        id_map = _event_id_map(reference_config, modular_root)
        id_space = sysmon_event_id_space(id_map)
        profile = load_profile(
            config.stem, config, id_map,
            unfilterable=parse_unfilterable_event_ids(reference_config),
        )

    def run(snap):
        return [
            evaluate(
                rule,
                profile=profile,
                schema_fields=snap.fields,
                populated_fields=snap.populated,
                checked_fields=snap.checked_fields,
                sensor_scope_channels=SYSMON_CHANNELS if profile else None,
                sensor_event_id_space=id_space,
                ingest_map=ingest_map,
                ignore_fields=set(ROUTING_FIELDS),
            )
            for rule in corpus
        ]

    old = run(snap_before)
    new = run(snap_after)

    changes: dict[tuple[str, str], list] = {}
    for was, now in zip(old, new):
        if was.verdict is not now.verdict:
            changes.setdefault((was.verdict.value, now.verdict.value), []).append(now)

    if not changes:
        typer.echo("No rule changed verdict between the two snapshots.")
        return

    typer.echo(f"{before.name} -> {after.name}\n")
    for (was, now), items in sorted(changes.items(), key=lambda kv: -len(kv[1])):
        typer.echo(f"{len(items):5}  {was} -> {now}")
    typer.echo("")

    for (was, now), items in sorted(changes.items(), key=lambda kv: -len(kv[1])):
        typer.echo(f"{was} -> {now}")
        for item in items[:12]:
            typer.echo(f"   {item.title}")
            if item.detail:
                typer.echo(f"      {item.detail}")
        if len(items) > 12:
            typer.echo(f"   ... and {len(items) - 12} more")
        typer.echo("")


def _announce_egress(explainer: Explainer, calls: int, yes: bool) -> None:
    """Say what is about to leave the host, then get permission for it.

    Printed every time rather than once in the documentation: --model reads
    like a choice of wording, and the person running it in a regulated estate
    is the one who has to know that schema detail crosses the boundary.
    """
    typer.echo("")
    plural = "question" if calls == 1 else "questions"
    typer.echo(f"{calls} {plural} would go to {explainer.endpoint_host} "
               f"({explainer.base_url}), model {explainer.model}")
    typer.echo("each one carries:")
    for line in EGRESS_CONTENTS:
        typer.echo(f"  - {line}")
    typer.echo("nothing else: no rule logic, no event data, no query results, no credentials.")
    typer.echo(
        "--base-url points this at a model on your own network, and "
        "--dry-run lists the questions without asking anything."
    )

    if yes:
        return
    if not sys.stdin.isatty():
        typer.echo(
            "refusing to send without consent: pass --yes to confirm, or drop --model "
            "to use only what is already cached.",
            err=True,
        )
        raise typer.Exit(EXIT_USAGE)
    if not typer.confirm("send these?"):
        raise typer.Exit(EXIT_OK)


@app.command("explain")
def explain(
    rules_dir: Path = typer.Option(..., help="SigmaHQ rules directory"),
    snapshot_file: Path = typer.Option(..., help="Schema snapshot"),
    ingest_pipeline: Path = typer.Option(None, help="SIEM ingest pipeline definition"),
    config: Path = typer.Option(None, help="Sysmon config XML"),
    reference_config: Path = typer.Option(None, help="Config supplying the event ID map"),
    modular_root: Path = typer.Option(None, help="sysmon-modular checkout"),
    subdir: list[str] = typer.Option(["windows"], help="Rule subdirectories"),
    cache: Path = typer.Option(Path("explanations.json"), help="Where advisory notes are stored"),
    model: str = typer.Option(
        None, help="Model to call; omit to use only what is cached. Passing this "
                   "sends schema detail to the endpoint, which is listed before "
                   "the first call"
    ),
    provider: str = typer.Option("anthropic", help="anthropic or openai-compatible"),
    base_url: str = typer.Option(
        None, help="Endpoint to call instead of the provider's own. An OpenAI-compatible "
                   "local model keeps every question on your network"
    ),
    yes: bool = typer.Option(
        False, "--yes", help="Confirm the egress listed before the first call. Required "
                             "when there is no terminal to ask"
    ),
    refresh: bool = typer.Option(False, help="Re-ask even for causes already cached"),
    dry_run: bool = typer.Option(False, help="List the causes and stop, without calling anything"),
):
    """Write advisory notes for each distinct cause. Never changes a verdict.

    Notes are keyed by cause rather than by rule, so a corpus with hundreds of
    failing rules costs a couple of dozen calls. They are cached to disk so
    later runs, and the demo, need no API access at all.

    Passing --model sends telemetry schema detail to a third party. The exact
    list is printed before the first call. --base-url sends it to a model you
    host instead, which is how this runs in an estate that cannot export it.
    """
    verdicts = _run_verdicts(
        rules_dir, subdir, snapshot_file, ingest_pipeline, config, reference_config, modular_root
    )
    causes = collect_causes(verdicts)
    pairs = sum(len(v) for v in causes.values())
    typer.echo(f"{len(causes)} distinct causes across {pairs} rule-and-reason pairs")

    if dry_run:
        for cause, titles in sorted(causes.items(), key=lambda kv: -len(kv[1])):
            typer.echo(f"  {len(titles):5}  {cause.key}")
        return

    explainer = None
    if model:
        try:
            explainer = Explainer(model, provider=provider, base_url=base_url)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--base-url")
        if not explainer.api_key:
            typer.echo(f"no API key found for provider '{provider}'", err=True)
            raise typer.Exit(EXIT_USAGE)

        cached = set() if refresh else set(ExplanationCache(cache).entries)
        pending = [c for c in causes if c.key not in cached]
        if not pending:
            typer.echo("every cause is already cached; nothing to send")
            explainer = None
        else:
            _announce_egress(explainer, len(pending), yes)

    explanations, calls = explain_run(verdicts, cache, explainer, refresh=refresh)
    typer.echo(f"{len(explanations)} advisory notes available, {calls} new calls made")
    typer.echo(f"cache: {cache}")

    if not model and not explanations:
        typer.echo("nothing cached yet; pass --model to generate")


def _run_verdicts(rules_dir, subdir, snapshot_file, ingest_pipeline, config, reference_config, modular_root):
    """Shared verdict run for the commands that need one."""
    corpus = load_corpus(find_rule_files(rules_dir, list(subdir)), _build_pipeline)
    snap = SchemaSnapshot.load(snapshot_file)
    ingest_map = load_ingest_map(ingest_pipeline) if ingest_pipeline else None

    profile = None
    id_space = None
    if config and reference_config:
        id_map = _event_id_map(reference_config, modular_root)
        id_space = sysmon_event_id_space(id_map)
        profile = load_profile(
            config.stem, config, id_map,
            unfilterable=parse_unfilterable_event_ids(reference_config),
        )

    return [
        evaluate(
            rule,
            profile=profile,
            schema_fields=snap.fields,
            populated_fields=snap.populated,
            checked_fields=snap.checked_fields,
            sensor_scope_channels=SYSMON_CHANNELS if profile else None,
            sensor_event_id_space=id_space,
            ingest_map=ingest_map,
            ignore_fields=set(ROUTING_FIELDS),
        )
        for rule in corpus
    ]


def main() -> None:
    """Entry point, so a crash exits 3 instead of sharing 1 with a failed gate."""
    try:
        app()
    except SystemExit:
        raise
    except Exception as exc:
        log.error("detection-gate failed: %s: %s", type(exc).__name__, exc)
        log.debug("traceback", exc_info=True)
        raise SystemExit(EXIT_INTERNAL)


if __name__ == "__main__":
    main()
