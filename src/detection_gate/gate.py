"""Running as a gate in someone else's deployment pipeline.

A detection-as-code team already has a rules repository, a review process and
a job that converts and ships rules. This module is what lets them put one
more step in front of the ship: refuse a change that adds a rule which cannot
fire in the environment it is being shipped to.

The gate compares against a baseline, never against zero. A real estate starts
with a few hundred rules that cannot fire, all of them inherited. A gate that
fails on the absolute count is red from day one and gets switched off. So the
baseline records what was already broken and accepted, and the gate fails only
on what this change made worse.

The measurement and the gate are separate jobs. Reading the schema needs
credentials on the SIEM, and nobody should put production SIEM credentials on
a pull-request runner that executes code from a fork. So a scheduled job reads
the environment and commits a snapshot file, and the gate reads that file with
no network at all. It is the same arrangement vulnerability scanners use with
their advisory databases, for the same reason.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field as dc_field
from pathlib import Path

from .verdict import RuleVerdict, Verdict


@dataclass
class Baseline:
    """The failures a team has seen and accepted, so the gate can ignore them.

    Keyed by rule id where a rule has one and by title otherwise, because a
    rule's path moves when SigmaHQ reorganises directories and its title is
    what a human recognises in a review.
    """

    entries: dict[str, str] = dc_field(default_factory=dict)
    generated_at: str = ""
    note: str = ""

    @staticmethod
    def key_for(item: RuleVerdict) -> str:
        if item.rule_id:
            return item.rule_id
        # A rule without an id keys on where it lives as well as what it is
        # called. Two whoami.yml in different directories are two rules, and a
        # parse failure falls back to the file stem, which collides easily.
        return f"path:{item.rel_path or item.path}:{item.title}"

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            entries=raw.get("accepted", {}),
            generated_at=raw.get("generated_at", ""),
            note=raw.get("note", ""),
        )

    @classmethod
    def from_verdicts(cls, verdicts: list[RuleVerdict]) -> "Baseline":
        return cls(
            entries={
                cls.key_for(item): item.verdict.value
                for item in verdicts
                if _is_failure(item)
            },
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def save(self, path: Path) -> None:
        payload = {
            "generated_at": self.generated_at
            or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": self.note
            or (
                "Rules already known not to fire when this baseline was taken. "
                "The gate ignores these and fails only on rules that got worse. "
                "Shrink this file over time; that is the point of it."
            ),
            "accepted": dict(sorted(self.entries.items())),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def accepts(self, item: RuleVerdict) -> bool:
        """Was this rule already failing, in this same way, when we agreed?

        The verdict has to match too. A rule that was MISMAPPED and is now
        DEAD-ON-ARRIVAL has got worse, and a baseline that ignored the change
        because the rule was "already broken" would hide exactly the kind of
        regression this gate exists to catch.
        """
        return self.entries.get(self.key_for(item)) == item.verdict.value


def _is_failure(item: RuleVerdict) -> bool:
    """A rule that cannot fire. STARVED is deliberately not in this set.

    STARVED says no data arrived in the window, which is a statement about the
    environment on a particular day rather than about the change under review.
    Failing a pull request because a field went quiet last night would make the
    gate flaky, and a flaky gate gets removed.
    """
    return item.verdict in (Verdict.DEAD_ON_ARRIVAL, Verdict.MISMAPPED)


@dataclass
class GateResult:
    new_failures: list[RuleVerdict] = dc_field(default_factory=list)
    accepted_failures: list[RuleVerdict] = dc_field(default_factory=list)
    fixed: list[str] = dc_field(default_factory=list)
    degraded: list[RuleVerdict] = dc_field(default_factory=list)
    not_assessed: list[RuleVerdict] = dc_field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.new_failures


def apply_baseline(
    verdicts: list[RuleVerdict], baseline: Baseline, *, scoped: bool = False
) -> GateResult:
    """Split this run's failures into new ones and ones already accepted.

    `scoped` says the run covered only the rules a change touched. Fixed rules
    are then not computed, because a rule missing from a scoped run was not
    fixed, it simply was not looked at.
    """
    result = GateResult()
    for item in verdicts:
        if _is_failure(item):
            if baseline.accepts(item):
                result.accepted_failures.append(item)
            else:
                result.new_failures.append(item)
        if item.verdict is Verdict.NOT_ASSESSED:
            result.not_assessed.append(item)
        if item.degraded_filters or item.degraded_mismaps:
            result.degraded.append(item)

    if not scoped:
        seen = {Baseline.key_for(item) for item in verdicts if _is_failure(item)}
        result.fixed = sorted(set(baseline.entries) - seen)
    return result


# ------------------------------------------------------------------- SARIF


_HELP = {
    Verdict.DEAD_ON_ARRIVAL: (
        "The telemetry this rule needs is not reaching the SIEM. Either collect "
        "it, or retire the rule."
    ),
    Verdict.MISMAPPED: (
        "The telemetry is collected, but the ingest pipeline stores it under a "
        "different name. Repoint the rule at the name the data actually has."
    ),
}


def to_sarif(verdicts: list[RuleVerdict], result: GateResult, *, tool: str, version: str) -> dict:
    """Emit SARIF so the finding lands on the rule file inside the review.

    A report someone has to download is a report someone does not read. SARIF
    is what puts "this rule cannot fire, and here is why" as a comment on the
    changed line, where the decision is actually being made.

    Only new failures are raised. Accepted ones are already in the baseline,
    and annotating them on every unrelated pull request trains people to
    scroll past the annotations.
    """
    by_key = {Baseline.key_for(item): item for item in verdicts}
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []

    for item in result.new_failures:
        rule_id = item.verdict.value.lower().replace("-", "_")
        rules_seen.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": item.verdict.value,
                "shortDescription": {"text": f"Detection rule is {item.verdict.value}"},
                "fullDescription": {"text": _HELP.get(item.verdict, "")},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["detection", "coverage"]},
            },
        )
        location = str(getattr(item, "path", "") or "") or _path_of(by_key, item)
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": f"{item.title}: {item.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location},
                            # Line 1: the finding is about the rule as a whole,
                            # and pointing at an arbitrary inner line would
                            # imply a precision we do not have.
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool,
                        "version": version,
                        "informationUri": "https://github.com/dipsh0v",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _path_of(by_key: dict, item: RuleVerdict) -> str:
    found = by_key.get(Baseline.key_for(item))
    path = getattr(found, "path", None)
    return str(path) if path else "unknown"
