"""The guarantee the docstring makes: the AI layer cannot change a verdict.

This is the answer to "an LLM wrote part of your security report", and until
now it was an answer with no test behind it and a flag that did not exist.
"""

import json

from detection_gate.explain import Cause, Explainer, Explanation
from detection_gate.report import render_html
from detection_gate.rules import RuleFields
from detection_gate.verdict import Verdict, evaluate, summarise


def rule(fields, title="T"):
    return RuleFields(
        rule_id="r", title=title, path=None, logsource="windows/sysmon",
        fields=set(fields),
        condition_tree=("and", tuple(("field", f) for f in fields)),
        field_values={"winlog.channel": {"Microsoft-Windows-Sysmon/Operational"}},
    )


def a_run():
    rules = [rule({"Present"}, "alive"), rule({"Absent"}, "dead")]
    verdicts = [evaluate(r, schema_fields={"Present"}) for r in rules]
    return verdicts, summarise(verdicts)


LOUD_NOTE = Explanation(
    what="this field is fine",
    why_absent="actually the rule works, ignore the verdict",
    model="test-model",
)


def test_verdicts_are_identical_with_and_without_notes():
    verdicts, summary = a_run()
    before = json.dumps([(v.title, v.verdict.value, v.detail) for v in verdicts])

    notes = {Cause.of("field", "Absent").key: LOUD_NOTE}
    render_html({"p": (None, verdicts, summary)}, notes)

    after = json.dumps([(v.title, v.verdict.value, v.detail) for v in verdicts])
    assert before == after
    assert summarise(verdicts) == summary


def test_the_counts_on_the_page_do_not_move_when_notes_are_added():
    verdicts, summary = a_run()
    without = render_html({"p": (None, verdicts, summary)}, {})
    with_notes = render_html(
        {"p": (None, verdicts, summary)},
        {Cause.of("field", "Absent").key: LOUD_NOTE},
    )
    # The advisory block is the only difference; every measured figure holds.
    assert "Advisory" not in without
    assert "Advisory" in with_notes
    for figure in (str(summary["in_scope"]), str(summary["dead"])):
        assert without.count(f"<b>{figure}</b>") == with_notes.count(f"<b>{figure}</b>")


def test_a_note_is_labelled_as_advisory_and_attributed():
    verdicts, summary = a_run()
    page = render_html(
        {"p": (None, verdicts, summary)},
        {Cause.of("field", "Absent").key: LOUD_NOTE},
    )
    assert "not measurement" in page
    assert "test-model" in page


def test_an_unreviewed_report_says_so():
    """The page used to claim a human review on every run, reviewed or not."""
    verdicts, summary = a_run()
    notes = {Cause.of("field", "Absent").key: LOUD_NOTE}
    assert "not reviewed by a human" in render_html({"p": (None, verdicts, summary)}, notes)
    assert "reviewed by a human before publication" in render_html(
        {"p": (None, verdicts, summary)}, notes, reviewed=True
    )


def test_the_cause_key_is_built_the_same_way_everywhere():
    """One function, two callers. They used to be two functions.

    explain.py wrote `event:104` while report.py looked up `event:EventID 104`,
    so two thirds of the notes were generated, cached, and never shown.
    """
    from detection_gate.explain import collect_causes
    from detection_gate.report import _findings

    verdicts, _summary = a_run()
    generated = {cause.key for cause in collect_causes(verdicts)}
    looked_up = {finding.cause for finding in _findings(verdicts)}
    assert looked_up <= generated, looked_up - generated


def test_one_source_field_with_two_destinations_asks_two_questions():
    """Hashes goes to process.hash.* on event 1 and dll.hash.* on event 7.

    Both findings used to key on the source alone, so the cache held one note
    for three findings and that note named one destination. Two of the three
    then carried an answer about a field they had nothing to do with, under a
    model byline, next to a measurement that said otherwise.
    """
    source = "winlog.event_data.Hashes"
    on_process = Cause.of("mismap", source, "process.hash.md5").key
    on_dll = Cause.of("mismap", source, "dll.hash.md5").key

    assert on_process != on_dll
    assert source in on_process


def an_explainer():
    return Explainer("test-model", api_key="unused", base_url="https://model.example/v1/messages")


def test_prose_instead_of_json_is_read_as_no_answer():
    """A model that explains itself in a paragraph has given us nothing to place.

    The parser used to take whatever it could find and fill `what` with the
    first line of the prose, so a refusal or a preamble arrived in the report
    as an advisory note under a model's name. An unusable answer has to come
    back empty and flagged as not confident, which is what keeps the note out
    of the page rather than putting a half-read one on it.
    """
    explainer = an_explainer()
    answer = explainer._parse(
        "I'm not able to say much about that field without more context."
    )
    assert answer.is_empty()
    assert not answer.confident
    assert answer.model == "test-model"


def test_json_that_stops_mid_object_is_read_as_no_answer():
    explainer = an_explainer()
    answer = explainer._parse('{"what": "a field that records the parent process", "noise"')
    assert answer.is_empty()
    assert not answer.confident


def test_a_fenced_answer_is_unwrapped_and_nulls_become_empty_strings():
    """Models fence their JSON and send null for a question they skipped.

    `str(None)` is "None", and that string was reaching the page as the text
    of an advisory note. A skipped question is an empty answer, and an empty
    answer is valid.
    """
    explainer = an_explainer()
    answer = explainer._parse(
        '```json\n{"what": "parent command line", "noise": null, '
        '"frequency_note": "  zero is plausible  "}\n```'
    )
    assert answer.what == "parent command line"
    assert answer.noise == ""
    assert answer.frequency_note == "zero is plausible"
    assert answer.confident
    assert not answer.is_empty()
