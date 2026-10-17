"""The gate's behaviour in a pull request.

A gate is only as good as the reasons it stays switched on. Each test here
guards one of them: it must not go red for debt the team already accepted, it
must go red for a regression, and it must never quietly pass something it
could not judge.
"""

from detection_gate.gate import Baseline, apply_baseline, to_sarif
from detection_gate.verdict import RuleVerdict, Verdict


def verdict(rule_id, title, kind, path="rules/x.yml", detail="because"):
    return RuleVerdict(
        rule_id=rule_id, title=title, logsource="windows/sysmon",
        verdict=kind, path=path, detail=detail,
    )


DEAD = verdict("a", "Already broken", Verdict.DEAD_ON_ARRIVAL)
NEW = verdict("b", "Newly broken", Verdict.MISMAPPED, path="rules/new.yml")
FINE = verdict("c", "Works", Verdict.FIREABLE)


def test_accepted_debt_does_not_fail_the_gate():
    """Day one has hundreds of inherited failures.

    Failing on the absolute count makes the gate useless immediately.
    """
    baseline = Baseline.from_verdicts([DEAD])
    result = apply_baseline([DEAD, FINE], baseline)
    assert result.passed
    assert result.accepted_failures == [DEAD]
    assert result.new_failures == []


def test_a_new_failure_fails_the_gate():
    baseline = Baseline.from_verdicts([DEAD])
    result = apply_baseline([DEAD, NEW], baseline)
    assert not result.passed
    assert result.new_failures == [NEW]


def test_a_rule_that_got_worse_is_not_covered_by_its_old_entry():
    """MISMAPPED yesterday, DEAD-ON-ARRIVAL today, same rule.

    Accepting it because "that rule was already broken" would hide a real
    regression behind the baseline, which is the failure mode that makes
    baselines dangerous.
    """
    was = verdict("d", "Drifting", Verdict.MISMAPPED)
    now = verdict("d", "Drifting", Verdict.DEAD_ON_ARRIVAL)
    baseline = Baseline.from_verdicts([was])
    result = apply_baseline([now], baseline)
    assert result.new_failures == [now]


def test_starved_never_fails_the_gate():
    """No data in the window is a statement about last night, not about this change.

    A field going quiet overnight is not a property of the change under review.
    """
    starved = verdict("e", "Quiet field", Verdict.STARVED)
    result = apply_baseline([starved], Baseline())
    assert result.passed
    assert result.new_failures == []


def test_a_rule_we_could_not_assess_is_surfaced_not_swallowed():
    unknown = verdict("f", "Unconvertible", Verdict.NOT_ASSESSED)
    result = apply_baseline([unknown], Baseline())
    assert result.not_assessed == [unknown]
    # It is not a failure, but the caller must be able to say so out loud.
    assert result.passed


def test_fixed_rules_are_only_reported_on_a_full_scan():
    """In a pull request the run covers three files, not the corpus.

    A baseline entry missing from a scoped run was not fixed; it was not
    looked at, and reporting it as fixed would let real debt disappear.
    """
    baseline = Baseline.from_verdicts([DEAD, NEW])
    scoped = apply_baseline([NEW], baseline, scoped=True)
    assert scoped.fixed == []

    full = apply_baseline([NEW], baseline, scoped=False)
    assert full.fixed == ["a"]


def test_baseline_round_trips_through_disk(tmp_path):
    path = tmp_path / "baseline.json"
    Baseline.from_verdicts([DEAD, NEW]).save(path)
    loaded = Baseline.load(path)
    assert loaded.accepts(DEAD)
    assert loaded.accepts(NEW)
    assert not loaded.accepts(verdict("z", "Unknown", Verdict.DEAD_ON_ARRIVAL))


def test_a_missing_baseline_file_accepts_nothing(tmp_path):
    """Better to be loudly red than silently green on a typo in the path.

    A path that does not exist has to come back as an empty baseline and leave
    the gate failing, so a renamed or mistyped baseline file is noticed on the
    next pull request. The version of this test before this one asserted that
    Baseline.load is a classmethod and never loaded anything, so it would have
    passed just as happily if load had returned a baseline accepting
    everything.
    """
    loaded = Baseline.load(tmp_path / "not-written-yet.json")
    assert loaded.entries == {}
    assert not loaded.accepts(DEAD)

    result = apply_baseline([DEAD, NEW, FINE], loaded)
    assert not result.passed
    assert result.new_failures == [DEAD, NEW]


def test_sarif_reports_only_new_failures_against_the_right_file():
    baseline = Baseline.from_verdicts([DEAD])
    result = apply_baseline([DEAD, NEW], baseline)
    doc = to_sarif([DEAD, NEW], result, tool="t", version="1")

    results = doc["runs"][0]["results"]
    assert len(results) == 1, "accepted debt must not be annotated on every pull request"
    location = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert location == "rules/new.yml"
    assert "Newly broken" in results[0]["message"]["text"]
    assert doc["version"] == "2.1.0"
