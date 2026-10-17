"""The claims the command line makes on its own help text.

The flag the README leads with is --no-ai, and the sentence beside it says the
verdicts are identical either way and that a test enforces that. Until now
nothing executed the flag, so the sentence was an intention. This runs the
scan command twice over the same corpus and compares the machine-readable
output byte for byte, which is the only form of the claim a reader can check.
"""

import json

from typer.testing import CliRunner

from detection_gate.cli import app

ALIVE = """\
title: Command line of a collected process
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine|contains: 'whoami'
    condition: selection
"""

DEAD = """\
title: Parent command line the schema does not have
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentCommandLine|contains: 'rundll32'
    condition: selection
"""

SNAPSHOT = {
    "source": "elasticsearch",
    "index_pattern": "logs-windows-*",
    "fields": ["event.code", "winlog.channel", "winlog.event_data.CommandLine"],
    "populated": ["event.code", "winlog.channel", "winlog.event_data.CommandLine"],
    "checked_fields": [
        "event.code", "process.parent.command_line", "winlog.channel",
        "winlog.event_data.CommandLine",
    ],
    "window": "now-7d",
    "notes": [],
    "taken_at": 1760000000,
}

# A note loud enough that a verdict quietly deferring to it would show.
NOTES = {
    "explanations": {
        "field:process.parent.command_line": {
            "what": "the parent process command line",
            "why_absent": "ADVISORY SENTINEL: the rule is fine, disregard the verdict",
            "model": "test-model",
            "confident": True,
        }
    }
}


def a_corpus(tmp_path):
    rules = tmp_path / "rules" / "windows" / "process_creation"
    rules.mkdir(parents=True)
    (rules / "alive.yml").write_text(ALIVE, encoding="utf-8")
    (rules / "dead.yml").write_text(DEAD, encoding="utf-8")

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps(SNAPSHOT), encoding="utf-8")

    notes = tmp_path / "notes.json"
    notes.write_text(json.dumps(NOTES), encoding="utf-8")
    return tmp_path / "rules", snapshot, notes


def scan(tmp_path, paths, label, *extra):
    rules_dir, snapshot, notes = paths
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--rules-dir", str(rules_dir),
            "--snapshot-file", str(snapshot),
            "--explanations-file", str(notes),
            "--html-out", str(tmp_path / f"{label}.html"),
            "--json-out", str(tmp_path / f"{label}.json"),
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    return (tmp_path / f"{label}.json").read_bytes(), (tmp_path / f"{label}.html").read_text()


def test_the_no_ai_flag_changes_the_page_and_not_one_verdict(tmp_path):
    """The headline claim about the advisory layer, run rather than asserted.

    The notes file here carries a sentence telling the reader to disregard the
    verdict, which is the shape of the failure that matters: a model's opinion
    reaching the measured output. Both runs read the same corpus and the same
    snapshot, so the verdict JSON has to be identical to the byte, while the
    page differs by exactly the advisory block.
    """
    paths = a_corpus(tmp_path)
    with_notes, with_page = scan(tmp_path, paths, "with-notes")
    without_notes, without_page = scan(tmp_path, paths, "no-ai", "--no-ai")

    assert with_notes == without_notes

    assert "ADVISORY SENTINEL" in with_page
    assert "ADVISORY SENTINEL" not in without_page, (
        "--no-ai has to actually suppress the notes, or the comparison above is vacuous"
    )

    payload = json.loads(with_notes)
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["in_scope"] == 2
    assert payload["summary"]["dead"] == 1
    verdicts = {item["title"]: item["verdict"] for item in payload["verdicts"]}
    assert verdicts["Command line of a collected process"] == "FIREABLE"
    assert verdicts["Parent command line the schema does not have"] == "DEAD-ON-ARRIVAL"


def test_a_scan_with_no_rule_source_is_a_usage_error(tmp_path):
    """Exit 2 for bad usage, so a misconfigured job does not read as a clean gate.

    Exit 0 on a run that scanned nothing is the quietest way for this tool to
    lie: the pipeline goes green and the report is empty for the same reason.
    """
    a_corpus(tmp_path)
    result = CliRunner().invoke(
        app, ["scan", "--snapshot-file", str(tmp_path / "snapshot.json")]
    )
    assert result.exit_code == 2


def test_a_url_carrying_a_credential_is_refused_before_anything_connects():
    """A password in --url lands in ps output, CI logs and shell history.

    The snapshot command reads the key from the environment and from nowhere
    else, so a URL with userinfo in it is a mistake worth stopping on rather
    than stripping silently.
    """
    result = CliRunner().invoke(
        app,
        [
            "snapshot",
            "--url", "https://elastic:hunter2@siem.example:9200",
            "--index-pattern", "logs-*",
            "--out", "unused.json",
            "--dry-run",
        ],
    )
    assert result.exit_code == 2
    assert "hunter2" not in result.output
    assert "ELASTIC_API_KEY" in result.output


def test_a_dry_run_says_what_it_would_ask_and_connects_to_nothing(tmp_path):
    a_corpus(tmp_path)
    out = tmp_path / "snapshot-out.json"
    result = CliRunner().invoke(
        app,
        [
            "snapshot",
            "--url", "https://siem.example:9200",
            "--index-pattern", "logs-windows-*",
            "--out", str(out),
            "--rules-dir", str(tmp_path / "rules"),
            "--window", "now-7d",
            "--batch-size", "2",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "logs-windows-*" in result.output
    assert "field_caps: 1 request" in result.output
    assert not out.exists(), "a dry run writes no snapshot"


def test_the_version_flag_prints_the_version_the_report_stamps():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    from detection_gate import __version__

    assert __version__ in result.output
