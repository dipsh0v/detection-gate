"""Reporting.

The report has one job: a detection engineer opens it and, without asking
anyone, knows how many rules cannot fire, why, and what to do about each
reason.

The organising idea is the firing chain. A rule fires only if the sensor emits
the event, the schema holds the field, and data arrives in it. Every verdict is
a break at one link, so showing where the chain broke answers "what is wrong"
and "who fixes it" in the same glance.

Findings are grouped by cause, not listed per rule. A list of rules is data;
"one rename accounts for 113 of the 167 rules in scope" is a finding. The
rules are still there, one level down, for whoever needs them.

Type and colour are deliberately plain. No web fonts are loaded, because this
report is opened on stage and inside air-gapped estates and anything needing
the network is a liability. The palette is near-monochrome with colour reserved
for where the chain broke, so colour always carries meaning.
"""

from __future__ import annotations

import collections
import html
import os
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone

# Cause belongs in verdict.py, not explain.py; the renderer needs only its key.
from .explain import Cause
from .verdict import DeadCause, Evidence, ScopeReason, Verdict

# The chain a rule depends on. Drives the diagram, the colour of each finding,
# and the order they are reported in: a break at the sensor is a different
# conversation from a break at the pipeline.
CHAIN = ("event", "field", "data")


@dataclass
class Finding:
    # Several keys per finding: one advisory note per missing event id.
    causes: list[str]
    label: str
    count: int
    broken_at: str          # event | field | data | filter
    action: str
    owner: str
    rules: list[str] = dc_field(default_factory=list)
    extra: str = ""

    @property
    def cause(self) -> str:
        return self.causes[0]


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "0.0%"


def _findings(verdicts) -> list[Finding]:
    """Reduce verdicts to causes, which is the level a reader can act on.

    Grouped by the individual field or event, not by the set of them a rule
    happened to be missing. Grouping by the set splits one cause across several
    rows: the registry rules showed up once under "EventType" and again under
    "EventType, NewName", so the reader saw two small problems instead of one
    missing field. A rule may therefore appear under more than one
    cause, and the report says so rather than making the column sum to the
    headline by accident.
    """
    buckets: dict[tuple, list] = collections.defaultdict(list)

    for item in verdicts:
        if item.verdict is Verdict.DEAD_ON_ARRIVAL:
            if item.cause is DeadCause.EVENT_NOT_COLLECTED:
                for element in item.missing_event_elements or ["this event"]:
                    buckets[("event", element)].append(item)
            else:
                for field in item.missing_fields:
                    buckets[("field", field)].append(item)
        elif item.verdict is Verdict.MISMAPPED:
            for source, destination in item.mismapped_fields:
                buckets[("mismap", source, destination)].append(item)
        elif item.verdict is Verdict.STARVED:
            for field in item.starved_fields:
                buckets[("starved", field)].append(item)
        for field in item.degraded_filters:
            buckets[("degraded", field, "")].append(item)
        for field, destination in item.degraded_mismaps:
            buckets[("degraded", field, destination)].append(item)

    findings: list[Finding] = []
    for key, items in buckets.items():
        kind, subject = key[0], key[1]
        titles = sorted({i.title for i in items})

        if kind == "event":
            event_ids = sorted({e for i in items for e in i.missing_event_ids})
            findings.append(Finding(
                causes=[Cause.of("event", e).key for e in event_ids]
                       or [Cause.of("event", subject).key],
                label=f"{subject} is not collected",
                count=len(titles), broken_at="event",
                action="Turn this event on in the sensor configuration, or retire "
                       "the rules that need it.",
                owner="Sensor configuration",
                rules=titles,
                extra=f"EventID {', '.join(map(str, event_ids))}." if event_ids else "",
            ))

        elif kind == "field":
            dropped = any(subject in i.dropped_fields for i in items)
            extra = ""
            if dropped:
                # Worth saying plainly: the pipeline deletes this field and
                # never states where the value goes. Earlier versions treated
                # the deletion as proof of relocation and printed a destination
                # that did not exist.
                extra = ("The ingest pipeline removes this field without stating "
                         "where the value goes, so there is nothing to repoint the "
                         "rules at.")
            findings.append(Finding(
                causes=[Cause.of("field", subject).key],
                label=f"{subject} is absent from the schema",
                count=len(titles), broken_at="field",
                action="Collect this field, or confirm these rules were written "
                       "for a source you do not run.",
                owner="Collection",
                rules=titles, extra=extra,
            ))

        elif kind == "mismap":
            destination = key[2]
            evidence = {i.evidence.get(subject) for i in items} - {None}
            derived = Evidence.DECLARED_RENAME not in evidence
            candidates = sorted({
                c for i in items for c in i.destination_candidates.get(subject, [])
            })
            empty = any(
                d == destination for i in items for _s, d in i.unpopulated_destinations
            )

            if derived and candidates:
                action = (
                    "The pipeline builds this from a script rather than declaring "
                    f"a rename, so confirm which of {', '.join(candidates)} holds "
                    "this value, then repoint the rules at it."
                )
            elif derived:
                action = (
                    f"Confirm in the pipeline definition that the value lands in "
                    f"{destination}, then repoint the rules at it."
                )
            else:
                action = f"Point the rules at {destination}, where the pipeline stores the value."

            notes = []
            if derived:
                notes.append(
                    "Derived: read from a pipeline script and confirmed against the "
                    "schema, not declared by the pipeline as a rename."
                )
            if empty:
                notes.append(
                    f"{destination} carried no data in the window either, so "
                    "repointing the rules is necessary but not sufficient."
                )
            rewritten = [i for i in items if i.rewritten_values]
            if rewritten:
                literals = sorted({lit for i in rewritten for _f, lit in i.rewritten_values})[:3]
                shown = "; ".join(literals)
                notes.append(
                    f"{len(rewritten)} of these match on a literal the pipeline parses "
                    f"into another form (for example: {shown}), so the matched value "
                    "has to change as well, not just the field name."
                )
            findings.append(Finding(
                causes=[Cause.of("mismap", subject, destination).key],
                label=f"{subject} is stored as {destination}",
                count=len(titles), broken_at="field",
                action=action, owner="Conversion pipeline",
                rules=titles, extra=" ".join(notes),
            ))

        elif kind == "starved":
            findings.append(Finding(
                causes=[Cause.of("starved", subject).key],
                label=f"{subject} carried no data in the window",
                count=len(titles), broken_at="data",
                action="Find out whether it ever carried data: agent health, a "
                       "configuration change, retention, or an index rollover. A "
                       "field mapped by a template may never have been populated.",
                owner="Pipeline operations",
                rules=titles,
            ))

        else:
            destination = key[2]
            if destination:
                label = f"{subject} is stored as {destination}, so an exception misses it"
                owner = "Conversion pipeline"
                action = (f"Repoint the exception at {destination}. Until then these "
                          "rules fire more often than their authors intended.")
            else:
                label = f"{subject} is absent, so an exception cannot apply"
                owner = "Collection"
                action = ("These rules still fire, and fire more than intended. "
                          "Expect false positives until the field returns.")
            findings.append(Finding(
                causes=[Cause.of("degraded", subject, destination).key],
                label=label, count=len(titles), broken_at="filter",
                action=action, owner=owner, rules=titles,
            ))

    order = {"event": 0, "field": 1, "data": 2, "filter": 3}
    findings.sort(key=lambda f: (order[f.broken_at], -f.count, f.label))
    return findings


# ----------------------------------------------------------------- plain text


def render_table(profiles: dict) -> str:
    lines: list[str] = []
    for name, (_profile, verdicts, summary) in profiles.items():
        in_scope = summary["in_scope"]
        dead = summary[Verdict.DEAD_ON_ARRIVAL.value] + summary[Verdict.MISMAPPED.value]
        starved = summary[Verdict.STARVED.value]
        degraded = sum(1 for v in verdicts if v.degraded_filters or v.degraded_mismaps)
        fireable = summary[Verdict.FIREABLE.value]

        lines.append(name)
        lines.append("=" * len(name))
        lines.append(f"  {dead} of {in_scope} in-scope rules cannot fire ({_pct(dead, in_scope)}); {fireable} can.")
        lines.append(
            f"    {summary[Verdict.DEAD_ON_ARRIVAL.value]} the telemetry is not there, "
            f"{summary[Verdict.MISMAPPED.value]} it is there under another name."
        )
        if starved:
            lines.append(f"  {starved} more read fields that carried no data in the window.")
        if degraded:
            lines.append(f"  {degraded} fire more than intended; an exception is broken.")
        lines.append("")
        lines.append(f"  {'rules':>6}  {'break':<7} cause")
        lines.append(f"  {'-' * 6}  {'-' * 7} {'-' * 52}")
        for finding in _findings(verdicts):
            lines.append(f"  {finding.count:>6}  {finding.broken_at:<7} {finding.label}")
        lines.append("")

        # One bucket, four different reasons, counted under the profile they
        # were measured against: with several --config profiles, not per run.
        lines.append("  Set aside, and why")
        lines.append(f"  {'-' * 6}  {'-' * 52}")
        set_aside = [
            (reason, summary.get(f"scope:{reason.name}", 0)) for reason in ScopeReason
        ]
        for reason, count in set_aside:
            if count:
                lines.append(f"  {count:>6}  {reason.value}")
        if not any(count for _reason, count in set_aside):
            lines.append("          Nothing was set aside.")
        lines.append("")

    lines.append("  Rules serving another log source leave the denominator. Rules this")
    lines.append("  tool could not assess stay in it, because removing our own failures")
    lines.append("  would raise the percentage.")
    return "\n".join(lines)


# ----------------------------------------------------------------------- html

_CSS = """
:root {
  color-scheme: light;
  --paper:#FBFBF9; --ink:#17181A; --ink-2:#4A4D52; --ink-3:#6B6F76;
  --rule:#DEDDD8; --rule-2:#C4C3BC; --panel:#FFFFFF;
  --event:#A32019; --field:#8A4B12; --data:#7A5D08; --filter:#5C5A1C;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --paper:#131416; --ink:#E7E8EA; --ink-2:#A5A8AE; --ink-3:#8B8E95;
    --rule:#26282C; --rule-2:#3A3D42; --panel:#191B1E;
    --event:#F08078; --field:#DDA05C; --data:#D9BC57; --filter:#BDBB6E;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --paper:#131416; --ink:#E7E8EA; --ink-2:#A5A8AE; --ink-3:#8B8E95;
  --rule:#26282C; --rule-2:#3A3D42; --panel:#191B1E;
  --event:#F08078; --field:#DDA05C; --data:#D9BC57; --filter:#BDBB6E;
}
* { box-sizing: border-box; }
body {
  background: var(--paper); color: var(--ink);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  padding-inline: 20px; padding-block: 26px 64px; -webkit-font-smoothing: antialiased;
}
main { max-width: 980px; margin: 0 auto; }
h1,h2,h3 { margin:0; font-weight:600; text-wrap:balance; }
h1 { font-size:20px; letter-spacing:-0.01em; }
h2 { font-size:11.5px; text-transform:uppercase; letter-spacing:.09em; color:var(--ink-3); }
p { margin:0; }
.mono, code, td.n, .chain, .meta {
  font-family: ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  font-variant-numeric: tabular-nums;
}
.masthead {
  display:flex; flex-wrap:wrap; gap:4px 20px; align-items:baseline;
  border-bottom:2px solid var(--ink); padding-bottom:9px; margin-bottom:24px;
}
.meta { margin-left:auto; font-size:11.5px; color:var(--ink-3); }
.lede { font-size:16.5px; line-height:1.45; max-width:60ch; }
.lede b { font-family:ui-monospace,Menlo,monospace; font-size:18px; font-weight:600; }
.sub { color:var(--ink-2); font-size:13px; max-width:68ch; margin-top:5px; }
section { margin-top:30px; }
section > h2 { margin-bottom:11px; }
.chainbox { border:1px solid var(--rule); background:var(--panel); padding:12px 15px; }
.crow { display:grid; gap:2px; font-size:12.5px; padding:6px 0; }
.crow + .crow { border-top:1px dotted var(--rule); }
.chain { font-size:12px; letter-spacing:.01em; }
.chain .ok { color:var(--ink-3); }
.chain .x { font-weight:700; }
.crow .say { color:var(--ink-2); }
.k-event,.break-event .x { color:var(--event); }
.k-field,.break-field .x { color:var(--field); }
.k-data,.break-data .x { color:var(--data); }
.k-filter,.break-filter .x { color:var(--filter); }
.tablewrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:13px; min-width:640px; }
thead th {
  text-align:left; font-size:10.5px; text-transform:uppercase; letter-spacing:.07em;
  color:var(--ink-3); font-weight:600; border-bottom:1px solid var(--rule-2);
  padding:0 12px 6px 0;
}
tbody td { padding:9px 12px 9px 0; border-bottom:1px solid var(--rule); vertical-align:top; }
td.n { text-align:right; width:1%; white-space:nowrap; font-weight:600; padding-right:14px; }
td.brk {
  width:1%; white-space:nowrap; font-size:10.5px; text-transform:uppercase;
  letter-spacing:.05em; font-weight:600; padding-right:14px; padding-top:11px;
}
td.what { width:42%; }
td.what .extra { color:var(--ink-2); font-size:12.5px; margin-top:3px; }
td.act { color:var(--ink-2); }
td.act .owner { display:block; color:var(--ink-3); font-size:11px;
  text-transform:uppercase; letter-spacing:.05em; margin-top:4px; }
details { border-bottom:1px solid var(--rule); }
summary { cursor:pointer; padding:9px 0; list-style:none; display:flex; gap:12px; align-items:baseline; }
summary::-webkit-details-marker { display:none; }
summary::before { content:"+"; font-family:ui-monospace,monospace; color:var(--ink-3); width:11px; flex:none; }
details[open] > summary::before { content:"\\2212"; }
summary .count { font-family:ui-monospace,monospace; font-weight:600; min-width:3.2em; text-align:right; }
summary .name { flex:1; }
.body { padding:2px 0 18px 23px; display:flex; flex-direction:column; gap:15px; }
.advisory { border-left:2px solid var(--rule-2); padding-left:14px; }
.advisory .tag { font-size:10px; text-transform:uppercase; letter-spacing:.11em;
  color:var(--ink-3); display:block; margin-bottom:7px; }
.advisory dl { margin:0; display:grid; grid-template-columns:auto 1fr; gap:5px 14px; }
@media (max-width:560px) { .advisory dl { grid-template-columns:1fr; gap:1px 0; } }
.advisory dt { font-size:10.5px; text-transform:uppercase; letter-spacing:.05em;
  color:var(--ink-3); white-space:nowrap; padding-top:2px; }
.advisory dd { margin:0; color:var(--ink-2); font-size:13px; }
.advisory .src { font-size:11px; color:var(--ink-3); margin-top:9px; }
.subhead { font-size:10.5px; text-transform:uppercase; letter-spacing:.06em;
  color:var(--ink-3); margin-bottom:6px; }
.rules { columns:2; column-gap:26px; font-size:12.5px; color:var(--ink-2); }
@media (max-width:720px) { .rules { columns:1; } }
.rules div { break-inside:avoid; padding:1.5px 0; }
.method { display:grid; grid-template-columns:repeat(auto-fit,minmax(215px,1fr)); gap:0; margin:0; }
.method > div { border-top:1px solid var(--rule); padding:9px 20px 11px 0; }
.method dt { font-size:10.5px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-3); }
.method dd { margin:3px 0 0; font-size:12.5px; color:var(--ink-2); }
.note { font-size:12.5px; color:var(--ink-2); max-width:76ch; }
.note + .note { margin-top:7px; }
"""


def _chain_row(broken: str, label: str, meaning: str) -> str:
    """One line of the firing chain, with a cross at the link that breaks."""
    if broken == "filter":
        marks = [f"<span class='ok'>✓ {link}</span>" for link in CHAIN]
        marks.append("<span class='x'>✗ exception</span>")
    else:
        marks = []
        for link in CHAIN:
            if link == broken:
                marks.append(f"<span class='x'>✗ {link}</span>")
                break
            marks.append(f"<span class='ok'>✓ {link}</span>")
    drawn = " <span class='ok'>·</span> ".join(marks)
    return (
        f"<div class='crow break-{broken}'>"
        f"<span class='chain'>{drawn}</span>"
        f"<span class='say'><b class='k-{broken}'>{html.escape(label)}</b>"
        f" — {html.escape(meaning)}</span></div>"
    )


def _advisory_html(explanation, reviewed: bool = False) -> str:
    """Render one advisory note, or nothing.

    The review line used to be printed on every report whether or not anyone
    had reviewed anything. A report that attests to a process the tool cannot
    observe is making a claim of exactly the kind this project exists to catch,
    so it is now a flag the operator sets, and its absence says so plainly.
    """
    if explanation is None:
        return ""
    pairs = [
        ("what it is", explanation.what),
        ("how it is collected", explanation.how_to_collect),
        ("expected volume", explanation.noise),
        ("why it is missing", explanation.why_absent),
        ("is zero plausible", explanation.frequency_note),
    ]
    rows = "".join(
        f"<dt>{label}</dt><dd>{html.escape(value)}</dd>"
        for label, value in pairs if value
    )
    if not rows:
        return ""
    source = html.escape(explanation.model) if explanation.model else "an unnamed model"
    review = (
        "reviewed by a human before publication"
        if reviewed
        else "not reviewed by a human"
    )
    cut = (
        "<p class='src'>This note was cut short by a length limit and may be "
        "incomplete.</p>"
        if getattr(explanation, "truncated", False)
        else ""
    )
    return (
        "<div class='advisory'><span class='tag'>Advisory &middot; not measurement</span>"
        f"<dl>{rows}</dl>{cut}"
        f"<p class='src'>Written by {source}, {review}. "
        "It explains the finding above; it never alters it.</p></div>"
    )


def render_html(
    profiles: dict,
    explanations: dict | None = None,
    *,
    snapshot: dict | None = None,
    pipeline: str = "",
    model: str = "",
    reviewed: bool = False,
    generated_at: datetime | None = None,
) -> str:
    """Render the report.

    `snapshot` carries the measurement parameters the engine already knows and
    the page used to omit: the window, when it was taken, and which index it
    was taken from. A reader cannot judge "carried no data in the window"
    without knowing whether the window was a day or a decade, and a reader who
    cannot reproduce a number has to take it on trust.

    `generated_at` fixes the one value on the page that is not a measurement.
    Left unset it falls back to SOURCE_DATE_EPOCH, then to the clock, so two
    runs over identical inputs can be diffed byte for byte without losing the
    line that says when the page was made.
    """
    explanations = explanations or {}
    snapshot = snapshot or {}
    if generated_at is None:
        stamp = os.environ.get("SOURCE_DATE_EPOCH")
        generated_at = (
            datetime.fromtimestamp(int(stamp), timezone.utc)
            if stamp and stamp.strip().isdigit()
            else datetime.now(timezone.utc)
        )
    generated = generated_at.astimezone(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    blocks: list[str] = []

    for name, (profile, verdicts, summary) in profiles.items():
        in_scope = summary["in_scope"]
        dead = summary[Verdict.DEAD_ON_ARRIVAL.value] + summary[Verdict.MISMAPPED.value]
        starved = summary[Verdict.STARVED.value]
        degraded = sum(1 for v in verdicts if v.degraded_filters or v.degraded_mismaps)
        fireable = summary[Verdict.FIREABLE.value]
        findings = _findings(verdicts)

        # "Coverage" is the word this project exists to argue with: a count of
        # rules is not a measure of detection value, and using it here hands an
        # audience the tool's own critique. Say what was counted.
        lead = (
            f"<p class='lede'><b>{dead}</b> of <b>{in_scope}</b> in-scope detection "
            f"rules cannot fire as this environment is configured, which is "
            f"<b>{_pct(dead, in_scope)}</b> of the rules in scope. "
            f"<b>{fireable}</b> can.</p>"
        )
        split = []
        if summary[Verdict.DEAD_ON_ARRIVAL.value]:
            split.append(
                f"{summary[Verdict.DEAD_ON_ARRIVAL.value]} because the telemetry is "
                "not there"
            )
        if summary[Verdict.MISMAPPED.value]:
            split.append(
                f"{summary[Verdict.MISMAPPED.value]} because the telemetry is there "
                "under a name the rule does not use"
            )
        if split:
            lead += f"<p class='sub'>Of those, {', and '.join(split)}.</p>"
        second = []
        if starved:
            second.append(
                f"{starved} more read fields that carried no data in the window"
            )
        if degraded:
            second.append(
                f"{degraded} fire more often than intended, because a field they use "
                "to rule out noise is missing or renamed"
            )
        if second:
            lead += f"<p class='sub'>{'. '.join(x.capitalize() for x in second)}.</p>"

        chain = "".join([
            _chain_row("event", "Not collected",
                       "the sensor never emits the event, so nothing can match"),
            _chain_row("field", "Absent or renamed",
                       "the event arrives, but the field the rule reads is not in the schema"),
            _chain_row("data", "Silent",
                       "the field exists, but nothing arrived in it during the window"),
            _chain_row("filter", "Exception broken",
                       "the rule fires, and fires too often, because an exclusion cannot apply"),
        ])

        rows = "".join(
            f"<tr><td class='n k-{f.broken_at}'>{f.count}</td>"
            f"<td class='brk k-{f.broken_at}'>{f.broken_at}</td>"
            f"<td class='what'>{html.escape(f.label)}"
            + (f"<div class='extra'>{html.escape(f.extra)}</div>" if f.extra else "")
            + f"</td><td class='act'>{html.escape(f.action)}"
            f"<span class='owner'>{html.escape(f.owner)}</span></td></tr>"
            for f in findings
        )

        details = "".join(
            f"<details{' open' if index < 3 else ''}><summary>"
            f"<span class='count k-{f.broken_at}'>{f.count}</span>"
            f"<span class='name'>{html.escape(f.label)}</span></summary>"
            f"<div class='body'>"
            + "".join(
                _advisory_html(explanations.get(c), reviewed) for c in f.causes
            )
            + "<div><div class='subhead'>Rules affected</div>"
            f"<div class='rules'>"
            + "".join(f"<div>{html.escape(t)}</div>" for t in sorted(set(f.rules)))
            + "</div></div></div></details>"
            for index, f in enumerate(findings)
        )

        sensor = html.escape(profile.name) if profile else "schema only"

        taken = "not recorded"
        if snapshot.get("taken_at"):
            try:
                taken = datetime.fromtimestamp(
                    float(snapshot["taken_at"]), timezone.utc
                ).strftime("%d %B %Y, %H:%M UTC")
            except (TypeError, ValueError):
                taken = html.escape(str(snapshot["taken_at"]))

        # The bucket held 548 of the 2,410 rules in the corpus under one
        # sentence true of only two of them, so the four reasons print separately.
        scope_counts = [
            (reason, summary.get(f"scope:{reason.name}", 0)) for reason in ScopeReason
        ]
        scope_rows = "".join(
            f"<tr><td class='n'>{count}</td><td class='what'>{html.escape(reason.value)}</td></tr>"
            for reason, count in scope_counts if count
        ) or "<tr><td class='what'>Nothing was set aside.</td></tr>"

        filtered = sum(1 for v in verdicts if v.filtered_event_ids)
        filtered_note = (
            f"{filtered} of the rules in scope sit on an event this configuration "
            "collects only through include rules."
            if filtered else ""
        )
        blocks.append(
            f"<section><h2>{html.escape(name)}</h2>{lead}</section>"
            f"<section><h2>How a rule fails</h2><div class='chainbox'>{chain}</div>"
            "<p class='note' style='margin-top:9px'>A rule fires only when all three "
            "links hold, and which link broke is also what decides who can fix it. "
            "The fourth row is not a break in the chain: those rules do fire, and "
            "fire too often, because an exclusion they rely on cannot apply.</p>"
            "<p class='note'>Rules set aside before the chain is reached are listed "
            "under Scope and method.</p></section>"
            "<section><h2>Findings, by cause</h2><div class='tablewrap'><table><thead><tr>"
            "<th style='text-align:right;padding-right:14px'>rules</th>"
            "<th style='padding-right:14px'>break</th><th>what is wrong</th>"
            f"<th>what to do</th></tr></thead><tbody>{rows}</tbody></table></div></section>"
            f"<section><h2>Detail</h2>{details}</section>"
            "<section><h2>Scope and method</h2><dl class='method'>"
            f"<div><dt>Sensor profile</dt><dd>{sensor}</dd></div>"
            f"<div><dt>Conversion pipeline</dt><dd>{html.escape(pipeline) or 'not recorded'}</dd></div>"
            f"<div><dt>Index</dt><dd>{html.escape(str(snapshot.get('index_pattern','not recorded')))}</dd></div>"
            f"<div><dt>Window</dt><dd>{html.escape(str(snapshot.get('window','not recorded')))}</dd></div>"
            f"<div><dt>Schema read</dt><dd>{taken}</dd></div>"
            f"<div><dt>Rules examined</dt><dd>{summary['total']}</dd></div>"
            f"<div><dt>Rules in scope</dt><dd>{in_scope}</dd></div>"
            "<div><dt>Detections run</dt><dd>None; only schema metadata and field "
            "population counts were read</dd></div></dl>"
            f"<div class='subhead' style='margin-top:16px'>Set aside, and why</div>"
            f"<div class='tablewrap'><table><tbody>{scope_rows}</tbody></table></div>"
            "<p class='note' style='margin-top:14px'>Rules serving another log source "
            "leave the denominator, because counting them would inflate the result "
            "with problems this sensor was never responsible for. Rules this tool "
            "could not assess do not get that treatment: dropping them would shrink "
            "the denominator and raise the percentage on the strength of our own "
            "failures, so they are counted and named above.</p>"
            "<p class='note'>The event and field checks are facts about configuration "
            "and schema: the sensor either emits an event or it does not, the schema "
            "either holds a field or it does not, and data either arrived in the "
            "window or it did not. Where a value's destination is marked "
            "<i>derived</i>, it was read out of a pipeline script and confirmed "
            "against the schema rather than declared by the pipeline as a rename; "
            "that is weaker evidence and the finding says so.</p>"
            "<p class='note'>Field names are resolved through the same conversion "
            "pipeline used to deploy these rules. A different pipeline resolves "
            "different names and produces a different result, so this report "
            "describes the pipeline it was run with.</p>"
            "<p class='note'>The event check asks whether the configuration collects "
            "an event at all. It does not evaluate how narrowly an include rule "
            f"scopes that event, so a rule counted here as able to fire may still "
            f"never see the activity it describes. {filtered_note}</p>"
            "<p class='note'>A rule can break in more than one way, so it may appear "
            "under more than one cause above. The cause counts are therefore not "
            "disjoint and do not sum to the headline.</p></section>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection coverage report</title>
<style>{_CSS}</style>
</head>
<body>
<main>
  <div class="masthead">
    <h1>Detections that cannot fire</h1>
    <span class="meta">detection-gate &middot; generated {generated}</span>
  </div>
  {''.join(blocks)}
</main>
</body>
</html>
"""
