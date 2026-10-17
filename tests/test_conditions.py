"""The condition semantics that decide the headline number.

Every case here was a wrong verdict at some point. The disjunctive ones were
wrong in the direction that grows the number, which is the direction nobody
catches by looking at the output.
"""

import pytest
from sigma.collection import SigmaCollection

from detection_gate.rules import extract_rule_fields, tree_fields
from detection_gate.verdict import (
    RuleVerdict,
    ScopeReason,
    Verdict,
    evaluate,
    summarise,
)


class NullPipeline:
    """Leaves field names alone, so a test asserts semantics and not mapping."""

    def apply(self, rule):
        return None


SCHEMA = {"Present", "AlsoPresent", "FilterField", "event.code", "winlog.channel"}


def rule_with(condition: str):
    return SigmaCollection.from_yaml(
        f"""
title: T
id: 00000000-0000-0000-0000-000000000001
status: test
logsource:
    product: windows
    service: sysmon
detection:
    selection_a: {{Missing: 'x'}}
    selection_b: {{Present: 'y'}}
    selection_c: {{AlsoMissing: 'w'}}
    selection_d: {{AlsoPresent: 'v'}}
    filter_main: {{FilterField: 'z'}}
    condition: {condition}
"""
    ).rules[0]


def verdict_for(condition: str):
    fields = extract_rule_fields(rule_with(condition), NullPipeline())
    return evaluate(fields, schema_fields=SCHEMA)


@pytest.mark.parametrize(
    "condition, expected, why",
    [
        # Disjunction: one branch surviving is enough, and Sigma's commonest
        # idioms are disjunctive. Treating these as dead is the bug that put
        # 54 rules into the headline that could fire perfectly well.
        ("selection_a or selection_b", Verdict.FIREABLE, "one branch is intact"),
        ("1 of selection_*", Verdict.FIREABLE, "one branch is intact"),
        ("selection_b or selection_d", Verdict.FIREABLE, "both branches intact"),
        # ... but a rule whose every branch is broken really is dead, so the
        # fix must not simply stop reporting disjunctive rules.
        ("selection_a or selection_c", Verdict.DEAD_ON_ARRIVAL, "no branch survives"),
        # Conjunction: any missing conjunct kills it.
        ("selection_a and selection_b", Verdict.DEAD_ON_ARRIVAL, "missing conjunct"),
        ("all of selection_*", Verdict.DEAD_ON_ARRIVAL, "missing conjunct"),
        ("selection_b and selection_d", Verdict.FIREABLE, "both conjuncts present"),
        # Mixed.
        ("(selection_a or selection_b) and selection_d", Verdict.FIREABLE, "disjunct survives"),
        ("(selection_a or selection_c) and selection_b", Verdict.DEAD_ON_ARRIVAL, "disjunction dead"),
        # Negation describes an exception, never a requirement.
        ("selection_b and not filter_main", Verdict.FIREABLE, "filter is not a requirement"),
        ("selection_a and not filter_main", Verdict.DEAD_ON_ARRIVAL, "selection still missing"),
        # Single selection, both ways.
        ("selection_a", Verdict.DEAD_ON_ARRIVAL, "the only selection is broken"),
        ("selection_b", Verdict.FIREABLE, "the only selection is intact"),
    ],
)
def test_condition_semantics(condition, expected, why):
    assert verdict_for(condition).verdict is expected, why


def test_only_blocking_fields_are_named():
    """A rule is not blamed for a field that was never going to stop it."""
    result = verdict_for("selection_a or selection_c")
    assert set(result.missing_fields) == {"Missing", "AlsoMissing"}
    assert "FilterField" not in result.missing_fields


def test_filter_only_field_degrades_rather_than_kills():
    fields = extract_rule_fields(
        rule_with("selection_b and not filter_main"), NullPipeline()
    )
    result = evaluate(fields, schema_fields={"Present", "event.code", "winlog.channel"})
    assert result.verdict is Verdict.FIREABLE
    assert result.degraded_filters == ["FilterField"]


def test_population_uses_the_same_semantics_as_the_schema_check():
    """A populated alternative keeps a disjunctive rule out of STARVED too."""
    fields = extract_rule_fields(
        rule_with("selection_b or selection_d"), NullPipeline()
    )
    result = evaluate(
        fields,
        schema_fields=SCHEMA,
        populated_fields={"Present", "event.code", "winlog.channel"},
    )
    assert result.verdict is Verdict.FIREABLE


def test_unparseable_condition_is_reported_not_guessed():
    """We say we could not read it, rather than inventing a requirement.

    The old fallback treated every referenced field as required, which turned
    a gap in our parsing into a finding about the customer's environment.
    """
    fields = extract_rule_fields(rule_with("selection_b"), NullPipeline())
    fields.condition_tree = None
    result = evaluate(fields, schema_fields=set())
    assert result.verdict is Verdict.NOT_ASSESSED


def test_a_condition_pysigma_cannot_read_is_not_a_fireable_rule():
    """A condition naming a selection that does not exist.

    The test above fakes the failure by clearing the tree. This one drives the
    real path: pySigma raises while resolving the name, extract_rule_fields
    records that as an error on the rule, and the engine has to carry that
    through to NOT_ASSESSED. Before the fix the error was not read at the
    verdict stage, so this rule came back FIREABLE against an empty schema,
    which is the worst possible direction: a rule nobody could judge counted
    as one that works.
    """
    fields = extract_rule_fields(rule_with("selection_b and no_such_selection"), NullPipeline())
    assert fields.error is not None
    assert fields.condition_tree is None
    assert not fields.is_usable

    result = evaluate(fields, schema_fields=set())
    assert result.verdict is Verdict.NOT_ASSESSED
    assert result.scope_reason is ScopeReason.CONVERSION_FAILED
    assert result.detail == fields.error


def test_a_keyword_only_rule_has_nothing_to_check_and_says_so():
    """`keywords` carries no field name, so there is no schema question to ask.

    satisfiable() answers yes to a tree with no field in it, against any
    schema including an empty one, so such a rule used to arrive at FIREABLE
    by construction rather than by measurement. Every keyword-only rule in a
    corpus took that route, and each one made the environment look better
    checked than it was.
    """
    rule = SigmaCollection.from_yaml(
        """
title: Keyword only
id: 00000000-0000-0000-0000-000000000002
status: test
logsource:
    product: windows
    service: sysmon
detection:
    keywords:
        - 'mimikatz'
    condition: keywords
"""
    ).rules[0]
    fields = extract_rule_fields(rule, NullPipeline())
    assert fields.error is None
    assert not fields.is_usable, "no field in the tree, so there is nothing to check"

    result = evaluate(fields, schema_fields=SCHEMA)
    assert result.verdict is Verdict.NOT_ASSESSED
    assert result.scope_reason is ScopeReason.NOTHING_CHECKED


def test_a_field_the_snapshot_measured_empty_is_starved():
    fields = extract_rule_fields(rule_with("selection_b"), NullPipeline())
    result = evaluate(
        fields,
        schema_fields=SCHEMA,
        populated_fields={"event.code", "winlog.channel"},
        checked_fields={"Present", "event.code", "winlog.channel"},
    )
    assert result.verdict is Verdict.STARVED
    assert result.starved_fields == ["Present"]


def test_a_population_verdict_turning_on_an_unqueried_field_is_not_starvation():
    """AlsoPresent was never in the population query, so nothing measured it.

    A field absent from `populated_fields` because the snapshot never asked
    about it looks exactly like a field measured empty, and the report prints
    the second sentence: "in schema but no data in window". That sentence was
    being written about fields the cluster was never asked for, which is the
    tool stating a measurement it did not take. The rule carries no verdict
    instead, and names what to widen the snapshot with.
    """
    fields = extract_rule_fields(rule_with("selection_b or selection_d"), NullPipeline())
    result = evaluate(
        fields,
        schema_fields=SCHEMA,
        populated_fields=set(),
        checked_fields={"Present"},
    )
    assert result.verdict is Verdict.NOT_ASSESSED
    assert result.scope_reason is ScopeReason.UNCHECKED_FIELD
    assert result.unchecked_fields == ["AlsoPresent"]
    assert result.starved_fields == []


def test_a_snapshot_that_recorded_no_checked_set_keeps_the_old_population_answer():
    """An older snapshot file has no checked_fields, and must still be usable.

    None means we do not know what was asked, not that nothing was. Treating
    it as the empty set would turn every rule in an old snapshot into
    NOT_ASSESSED and make a re-run of a recorded environment unreadable.
    """
    fields = extract_rule_fields(rule_with("selection_b or selection_d"), NullPipeline())
    result = evaluate(
        fields,
        schema_fields=SCHEMA,
        populated_fields=set(),
        checked_fields=None,
    )
    assert result.verdict is Verdict.STARVED
    assert result.starved_fields == ["AlsoPresent", "Present"]


def counted(kind, scope_reason=None):
    return RuleVerdict(
        rule_id=f"id-{kind.value}", title=kind.value, logsource="windows/sysmon",
        verdict=kind, scope_reason=scope_reason,
    )


def test_the_denominator_holds_every_rule_except_the_ones_serving_another_log_source():
    """The headline sentence and the arithmetic behind it have to agree.

    The report prints "N of M in-scope rules cannot fire" and says in print
    that rules we could not assess are counted in M. The code subtracted them
    from it, so M was smaller than the sentence claimed and the percentage was
    larger than the evidence supported, in the one figure anybody quotes. The
    arithmetic is pinned here against a vector holding all six verdicts.
    """
    verdicts = [
        counted(Verdict.FIREABLE),
        counted(Verdict.DEAD_ON_ARRIVAL),
        counted(Verdict.MISMAPPED),
        counted(Verdict.STARVED),
        counted(Verdict.OUT_OF_SCOPE, ScopeReason.OTHER_CHANNEL),
        counted(Verdict.NOT_ASSESSED, ScopeReason.CONVERSION_FAILED),
    ]
    summary = summarise(verdicts)

    assert summary["total"] == 6
    assert summary["in_scope"] == summary["total"] - summary[Verdict.OUT_OF_SCOPE.value]
    assert summary["in_scope"] == 5
    assert summary["dead"] == 2
    assert summary["dead"] == (
        summary[Verdict.DEAD_ON_ARRIVAL.value] + summary[Verdict.MISMAPPED.value]
    )
    assert summary[Verdict.NOT_ASSESSED.value] == 1
    assert summary["scope:OTHER_CHANNEL"] == 1
    assert summary["scope:CONVERSION_FAILED"] == 1


def test_them_reads_every_selection_including_the_filter():
    """`all of them` and `1 of them` include a block named filter_main.

    The keyword means every detection block in the rule, and a rule that uses
    it alongside a filter is common in SigmaHQ. Reading `them` as the
    selections only gave the filter's field the wrong role in the tree, which
    moves the rule between FIREABLE and DEAD-ON-ARRIVAL depending on which
    half of the condition the missing field sits in.
    """
    conjunction = extract_rule_fields(rule_with("all of them"), NullPipeline())
    assert conjunction.fields == {
        "Missing", "Present", "AlsoMissing", "AlsoPresent", "FilterField",
    }
    assert evaluate(conjunction, schema_fields=SCHEMA).verdict is Verdict.DEAD_ON_ARRIVAL

    disjunction = extract_rule_fields(rule_with("1 of them"), NullPipeline())
    assert disjunction.fields == set(), "no single block is required when any will do"
    assert tree_fields(disjunction.condition_tree) == conjunction.fields
    assert evaluate(
        disjunction, schema_fields={"FilterField", "event.code", "winlog.channel"}
    ).verdict is Verdict.FIREABLE, "the filter block is one of the alternatives"


def test_an_analyzer_subfield_is_asked_about_under_its_parent_name():
    """The pipeline emits process.command_line.keyword; the schema has the parent.

    Elasticsearch reports the subfield in field_caps only where a mapping
    declares it, so asking for the spelling the pipeline produced reported a
    field that is plainly collected as absent from the schema.
    """
    rule = SigmaCollection.from_yaml(
        """
title: Subfield spelling
id: 00000000-0000-0000-0000-000000000003
status: test
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        process.command_line.keyword: 'whoami'
    condition: selection
"""
    ).rules[0]
    fields = extract_rule_fields(rule, NullPipeline())
    assert fields.fields == {"process.command_line"}
    assert fields.condition_tree == ("field", "process.command_line")

    result = evaluate(fields, schema_fields={"process.command_line"})
    assert result.verdict is Verdict.FIREABLE
