"""The line between what the pipeline states and what we would like it to mean.

The project's whole claim is that a verdict is a measured fact. Each test here
guards a place where an inference once crossed that line and came out of the
report wearing a fact's clothes.
"""

from pathlib import Path

import pytest

from detection_gate.ingest import FieldMove, IngestFieldMap, load_ingest_map
from detection_gate.rules import RuleFields
from detection_gate.sysmon import Collection, EventStatus, SysmonProfile, load_profile
from detection_gate.verdict import DeadCause, Evidence, ScopeReason, Verdict, evaluate


def rule(fields, *, tree=None, event_ids=None, channel="Microsoft-Windows-Sysmon/Operational"):
    values = {}
    if channel:
        values["winlog.channel"] = {channel}
    if event_ids:
        values["event.code"] = {str(e) for e in event_ids}
    node = tree or ("and", tuple(("field", f) for f in fields))
    return RuleFields(
        rule_id="r", title="T", path=None, logsource="windows/sysmon",
        fields=set(fields), condition_tree=node, field_values=values,
    )


IGNORE = {"event.code", "winlog.channel", "winlog.provider_name"}


# --------------------------------------------------------------- ingest map


def test_a_deleted_field_is_not_a_moved_field():
    """A remove processor is proof of deletion and nothing else.

    Treating it as proof of relocation sent 51 rules to the conversion team
    with a destination that did not exist, under the sentence "X is stored as
    removed by the pipeline after transforming it".
    """
    ingest = IngestFieldMap(dropped={"winlog.event_data.Gone"})
    result = evaluate(
        rule({"winlog.event_data.Gone"}),
        schema_fields={"event.code", "winlog.channel"},
        ingest_map=ingest,
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.DEAD_ON_ARRIVAL
    assert result.cause is DeadCause.FIELD_ABSENT
    assert result.mismapped_fields == []
    assert "winlog.event_data.Gone" in result.dropped_fields


def test_a_declared_rename_is_reported_as_declared():
    ingest = IngestFieldMap(renamed={"winlog.event_data.CommandLine": "process.command_line"})
    result = evaluate(
        rule({"winlog.event_data.CommandLine"}),
        schema_fields={"process.command_line", "event.code", "winlog.channel"},
        ingest_map=ingest,
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.MISMAPPED
    assert result.evidence["winlog.event_data.CommandLine"] is Evidence.DECLARED_RENAME


def test_a_staged_rename_is_followed_to_its_real_destination():
    """Hashes is staged into _temp.hashes and renamed out of there.

    Reading only the first hop reported a scratch name in no schema, so a
    recoverable destination was reported as unknown and the rule as dead.
    """
    ingest = IngestFieldMap(
        namespaces={"winlog.event_data.Hashes": "temp.hashes"},
        renamed={"_temp.hashes": "process.hash"},
    )
    destination, kind = ingest.resolve("winlog.event_data.Hashes", {"process.hash"})
    assert destination == "process.hash"
    assert kind == "STAGED_RENAME"


def test_a_guarded_rename_does_not_apply_to_other_events():
    """Type becomes message only on event 25.

    Recorded as unconditional, it would tell every Type-reading rule on every
    event that its value lives in message, on any index where message exists.
    """
    ingest = IngestFieldMap(
        renamed={"winlog.event_data.Type": "message"},
        rename_event_codes={"winlog.event_data.Type": {25}},
    )
    assert ingest.resolve("winlog.event_data.Type", {"message"}, [25])[0] == "message"
    assert ingest.resolve("winlog.event_data.Type", {"message"}, [1])[0] is None


def test_a_multi_hop_declared_chain_is_followed_to_its_endpoint():
    """Hash becomes Hashes, Hashes is staged, the staged name becomes process.hash.

    Each hop is a rename, so each one empties the field before it and only the
    last name holds the value. A walk that stopped after one hop answered
    winlog.event_data.Hashes, a name no schema has, and the rule was then
    reported as reading absent telemetry rather than as pointing at the wrong
    field. Both the intermediate names have to stay out of the answer.
    """
    ingest = IngestFieldMap(
        moves=[
            FieldMove(
                source="winlog.event_data.Hash",
                target="winlog.event_data.Hashes",
                index=0, processor="rename", removes_source=True,
            ),
            FieldMove(
                source="winlog.event_data.Hashes",
                target="_temp.hashes",
                index=1, processor="rename", removes_source=True,
            ),
            FieldMove(
                source="_temp.hashes", target="process.hash",
                index=2, processor="rename", removes_source=True,
            ),
        ]
    )
    names, evidence, namespace_only = ingest.resolve_fields(
        "winlog.event_data.Hash", {"process.hash"}
    )
    assert names == ["process.hash"]
    assert evidence == "DECLARED_RENAME"
    assert not namespace_only
    assert "_temp.hashes" not in names
    assert "winlog.event_data.Hashes" not in names


def test_a_namespace_destination_reaches_the_verdict_as_candidates():
    """The weakest evidence tier, and the one that most wants to overstate itself.

    A script writes somewhere under registry.*; which leaf holds Details is
    not something the pipeline states. Rendering that at the same strength as
    a declared rename turns our reading of a Painless script into a fact about
    the customer's data, and sends someone to repoint a rule at a field that
    may not be the one. The verdict has to carry the tier and the candidates
    the schema confirms, so the report can show the claim as derived.
    """
    schema = {
        "registry.path", "registry.key", "registry.value", "registry.hive",
        "registry.data", "registry.data.strings", "event.code", "winlog.channel",
    }
    ingest = IngestFieldMap(
        namespaces={"winlog.event_data.Details": "registry"},
        namespace_targets={
            "winlog.event_data.Details": ["registry.data.strings", "registry.data.type"],
        },
    )
    result = evaluate(
        rule({"winlog.event_data.Details"}, event_ids=[13]),
        schema_fields=schema,
        ingest_map=ingest,
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.MISMAPPED
    assert result.evidence["winlog.event_data.Details"] is Evidence.NAMESPACE
    assert result.mismapped_fields == [("winlog.event_data.Details", "registry.*")]
    assert result.destination_fields["winlog.event_data.Details"] == []
    assert result.destination_candidates["winlog.event_data.Details"] == [
        "registry.data.strings"
    ]
    assert "registry.data.type" not in result.destination_candidates[
        "winlog.event_data.Details"
    ], "a path the script writes but the schema does not have is not a candidate"


FIXTURE = Path(__file__).resolve().parents[1] / "lab" / "pipeline" / "sysmon_operational.yml"

# A subset of ECS as an Elastic Windows index actually reports it, so the
# destinations below are names a reader could go and look at.
LAB_SCHEMA = {
    "process.command_line", "process.executable", "process.pe.original_file_name",
    "process.hash.md5", "process.hash.sha1", "process.hash.sha256",
    "process.hash.imphash",
    "file.pe.original_file_name", "file.hash.md5", "file.hash.sha256",
    "dll.hash.md5", "dll.hash.sha256", "dll.code_signature.status",
    "registry.hive", "registry.key", "registry.path", "registry.value",
    "message", "rule.name", "event.code", "winlog.channel",
}


def test_the_lab_pipeline_parses_into_the_moves_it_declares():
    """Every hand-built map in this file is a claim about a real pipeline.

    This is the pipeline the lab runs, 1,491 lines of Elastic's own Sysmon
    processors, and until now no test read it. A parser that works on a map
    written in a test and not on this file proves nothing about any run.
    """
    ingest = load_ingest_map(FIXTURE)

    assert ingest.resolve("winlog.event_data.CommandLine", LAB_SCHEMA) == (
        "process.command_line", "DECLARED_RENAME",
    )
    assert ingest.resolve("winlog.event_data.Image", LAB_SCHEMA) == (
        "process.executable", "DECLARED_RENAME",
    )

    # Removed after being read, which is proof of deletion and of nothing more.
    assert "winlog.event_data.Hashes" in ingest.dropped
    assert "winlog.event_data.Details" in ingest.dropped
    assert ingest.resolve("winlog.event_data.Archived", LAB_SCHEMA)[0] is None

    assert ingest.namespaces["winlog.event_data.TargetObject"] == "registry"
    assert ingest.namespaces["winlog.event_data.Hashes"] == "temp.hashes"
    assert ingest.namespace_targets["winlog.event_data.QueryResults"] == [
        "dns.answers", "dns.resolved_ip", "related.hosts",
    ]

    # A guarded move states where a value goes for the events the guard admits
    # and nothing about any other event.
    assert ingest.resolve("winlog.event_data.Type", LAB_SCHEMA, [25])[0] == "message"
    assert ingest.resolve("winlog.event_data.Type", LAB_SCHEMA, [1])[0] is None


def test_the_lab_pipeline_reads_an_inequality_guard_as_an_exclusion():
    """`ctx.event.code != "7"` restricts a move; an empty code set does not.

    Read as "names no event code", the processor comes out unrestricted, which
    is its exact inverse: the one event it was written to skip becomes the one
    event it claims to serve. OriginalFileName is where it shows, because the
    pipeline moves it to the process namespace for everything except event 7
    and to the file namespace for event 7 alone.
    """
    ingest = load_ingest_map(FIXTURE)
    moves = [m for m in ingest.moves if m.source == "winlog.event_data.OriginalFileName"]
    assert len(moves) == 2
    by_target = {m.target: m.scope for m in moves}
    assert by_target["process.pe.original_file_name"].excluded == frozenset({7})
    assert by_target["process.pe.original_file_name"].included is None
    assert by_target["file.pe.original_file_name"].included == frozenset({7})


def test_the_lab_pipeline_answers_a_colliding_source_per_event():
    """Two fields the pipeline moves twice, under guards that disagree.

    This is the case a flat source-to-target mapping cannot hold, and getting
    it wrong does not look like an error: it produces a confident destination
    that is correct for a different event. An ImageLoad rule gets told its
    hashes are in process.hash, which exists, is populated, and is not where
    its data went.
    """
    ingest = load_ingest_map(FIXTURE)

    assert ingest.resolve("winlog.event_data.OriginalFileName", LAB_SCHEMA, [1]) == (
        "process.pe.original_file_name", "DECLARED_RENAME",
    )
    assert ingest.resolve("winlog.event_data.OriginalFileName", LAB_SCHEMA, [7]) == (
        "file.pe.original_file_name", "DECLARED_RENAME",
    )

    process_hashes, evidence, _ns = ingest.resolve_fields(
        "winlog.event_data.Hashes", LAB_SCHEMA, [1]
    )
    assert evidence == "NAMESPACE"
    assert all(name.startswith("process.hash.") for name in process_hashes)

    load_hashes, _evidence, _ns = ingest.resolve_fields(
        "winlog.event_data.Hashes", LAB_SCHEMA, [7]
    )
    assert load_hashes == ["dll.hash.md5", "dll.hash.sha256", "file.hash.md5", "file.hash.sha256"]
    assert not any(name.startswith("process.hash") for name in load_hashes)


# ------------------------------------------------------------- value rewrite


def test_a_wildcarded_literal_makes_no_rewrite_claim():
    """A Sigma wildcard stands for a set of values, not a value.

    Some members of that set would be rewritten and some would not, so the
    honest answer is silence. Substring matching said yes to all of them.

    The pattern and the literal here are chosen so the wildcard is the only
    thing that can decide the answer: `re.fullmatch` matches this literal
    end to end, so dropping the wildcard check returns a pattern and claims a
    rewrite. The first version of this test used a literal that fullmatch
    rejected on its own, so it passed with the check deleted.
    """
    ingest = IngestFieldMap(value_patterns={"f": [r"DWORD .*"]})
    assert ingest.rewrites_value("f", "DWORD (*)") is None
    assert ingest.rewrites_value("f", "DWORD (0x00000000)") is not None


def test_matching_is_full_match_not_substring():
    """Painless calls matcher.matches(), which anchors both ends."""
    ingest = IngestFieldMap(value_patterns={"f": ["Binary Data"]})
    assert ingest.rewrites_value("f", "Binary Data") is not None
    assert ingest.rewrites_value("f", "some Binary Data here") is None


# ------------------------------------------------------------ sensor mapping


def profile_with(mapping):
    return SysmonProfile(
        name="test-config",
        path=None,
        events={
            element: EventStatus(
                element=element, event_ids=(event_id,), collection=collection
            )
            for event_id, (element, collection) in mapping.items()
        },
        unfilterable={4, 16, 255},
    )


def test_an_event_we_cannot_map_is_not_an_event_the_config_disables():
    """EventID 104 belongs to the Eventlog service, not to Sysmon.

    Reading "no mapping" as "disabled" put a row in the report telling the
    reader to turn 104 on in their Sysmon configuration, which cannot be done.
    """
    result = evaluate(
        rule({"winlog.event_data.Anything"}, event_ids=[104]),
        profile=profile_with({23: ("FileDelete", Collection.FULL)}),
        schema_fields={"winlog.event_data.Anything", "event.code", "winlog.channel"},
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.OUT_OF_SCOPE
    assert result.scope_reason is ScopeReason.UNMAPPED_EVENT
    assert result.cause is not DeadCause.EVENT_NOT_COLLECTED


def test_a_disabled_event_is_still_reported_as_disabled():
    result = evaluate(
        rule({"winlog.event_data.Anything"}, event_ids=[23]),
        profile=profile_with({23: ("FileDelete", Collection.DISABLED)}),
        schema_fields={"winlog.event_data.Anything", "event.code", "winlog.channel"},
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.DEAD_ON_ARRIVAL
    assert result.cause is DeadCause.EVENT_NOT_COLLECTED
    assert result.missing_event_elements == ["FileDelete"]


def test_alternative_event_ids_keep_a_rule_alive():
    result = evaluate(
        rule({"winlog.event_data.Anything"}, event_ids=[23, 11]),
        profile=profile_with({
            23: ("FileDelete", Collection.DISABLED),
            11: ("FileCreate", Collection.FULL),
        }),
        schema_fields={"winlog.event_data.Anything", "event.code", "winlog.channel"},
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.FIREABLE


def test_a_rule_on_many_channels_is_not_this_sensors_rule():
    """pySigma resolves some rules onto several channels at once.

    Mentioning the sensor is not the same as belonging to it, and treating it
    as such is how a System-channel rule reached the Sysmon config check.
    """
    result = evaluate(
        rule({"winlog.event_data.Anything"}, event_ids=[104], channel=None).__class__(
            rule_id="r", title="T", path=None, logsource="windows",
            fields={"winlog.event_data.Anything"},
            condition_tree=("field", "winlog.event_data.Anything"),
            field_values={
                "winlog.channel": {"System", "Security", "Microsoft-Windows-Sysmon/Operational"},
                "event.code": {"104"},
            },
        ),
        profile=profile_with({23: ("FileDelete", Collection.FULL)}),
        schema_fields={"winlog.event_data.Anything", "event.code", "winlog.channel"},
        sensor_scope_channels={"Microsoft-Windows-Sysmon/Operational"},
        sensor_event_id_space=set(range(1, 30)) | {255},
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.OUT_OF_SCOPE
    assert result.scope_reason is ScopeReason.FOREIGN_EVENT_ID


def test_a_rule_on_another_channel_is_another_log_source_not_a_dead_rule():
    """A Security-channel rule judged against a Sysmon config.

    Counting it as dead puts a rule this sensor was never meant to serve into
    the headline number, under a cause the reader cannot act on. It also makes
    the figure grow with the size of the corpus rather than with what is
    broken, which is the first thing an informed audience checks.
    """
    result = evaluate(
        rule({"winlog.event_data.Anything"}, event_ids=[4688], channel="Security"),
        profile=profile_with({23: ("FileDelete", Collection.FULL)}),
        schema_fields={"event.code", "winlog.channel"},
        sensor_scope_channels={"Microsoft-Windows-Sysmon/Operational"},
        sensor_event_id_space=set(range(1, 30)) | {255},
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.OUT_OF_SCOPE
    assert result.scope_reason is ScopeReason.OTHER_CHANNEL
    assert result.cause is None


def test_a_rule_the_pipeline_gave_no_channel_is_not_judged_on_event_id_alone():
    """Event ID numbering is per channel, so 29 alone does not name a sensor.

    It is FileExecutableDetected in Sysmon and something else entirely
    elsewhere. Judging a channel-less rule against a Sysmon config reports
    another log source's rule as this sensor's misconfiguration.
    """
    result = evaluate(
        rule({"winlog.event_data.Anything"}, event_ids=[29], channel=None),
        profile=profile_with({23: ("FileDelete", Collection.FULL)}),
        schema_fields={"event.code", "winlog.channel"},
        sensor_scope_channels={"Microsoft-Windows-Sysmon/Operational"},
        sensor_event_id_space=set(range(1, 30)) | {255},
        ignore_fields=IGNORE,
    )
    assert result.verdict is Verdict.OUT_OF_SCOPE
    assert result.scope_reason is ScopeReason.NO_CHANNEL
    assert not result.is_dead


def write_config(tmp_path, body):
    path = tmp_path / "sysmon.xml"
    path.write_text(
        f'<Sysmon schemaversion="4.90"><EventFiltering>{body}</EventFiltering></Sysmon>',
        encoding="utf-8",
    )
    return path


ELEMENT_IDS = {"ProcessCreate": (1,), "ImageLoad": (7,), "FileDelete": (23,), "DnsQuery": (22,)}


def test_onmatch_decides_whether_an_event_is_collected_at_all(tmp_path):
    """The config authors' own semantics, and a flip here flips every rule.

    SwiftOnSecurity states it inline: an include block with no rules logs
    nothing. Read the other way round, an event nobody collects comes out
    FIREABLE for every rule that needs it, and an event collected in full
    comes out DEAD-ON-ARRIVAL for all of them. There is no partial failure
    here, so it is the single highest-blast-radius reading in the tool.
    """
    path = write_config(
        tmp_path,
        '<ProcessCreate onmatch="include"/>'
        '<FileDelete onmatch="exclude"/>'
        '<ImageLoad onmatch="include"><Image condition="contains">\\Temp\\</Image></ImageLoad>',
    )
    profile = load_profile("test", path, ELEMENT_IDS)

    assert profile.events["ProcessCreate"].collection is Collection.DISABLED
    assert profile.events["FileDelete"].collection is Collection.FULL
    assert profile.events["ImageLoad"].collection is Collection.FILTERED
    assert profile.event_ids_collected() == {7, 23} | profile.unfilterable
    assert profile.status_for_event_id(1).collection is Collection.DISABLED


def test_an_element_appearing_twice_keeps_the_narrower_reading(tmp_path):
    """sysmon-modular merges per-event files, so one element arrives in pieces.

    An exclude block says the event is collected, an include block says only
    what it lists is. Taking the last block seen would report an event as
    collected in full while an include block elsewhere in the same config is
    restricting it to a handful of paths, and every rule outside those paths
    would be called fireable.
    """
    path = write_config(
        tmp_path,
        '<DnsQuery onmatch="include"><QueryName condition="end with">.local</QueryName></DnsQuery>'
        '<DnsQuery onmatch="exclude"><Image condition="is">C:\\agent.exe</Image></DnsQuery>',
    )
    profile = load_profile("test", path, ELEMENT_IDS)

    status = profile.events["DnsQuery"]
    assert status.collection is Collection.FILTERED
    assert status.include_rules == 1
    assert status.exclude_rules == 1
    assert status.produces_events
