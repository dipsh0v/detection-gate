"""Resolve, for every Sigma rule, the exact backend field names it reads.

This is the input to every verdict detection-gate produces. Nothing here guesses:
the field names come out of the same pySigma processing pipeline the user
already runs to convert rules into SIEM queries. If the pipeline renames
Image to process.executable, that is the name we check the schema for.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field as dc_field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionNOT, ConditionOR
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

log = logging.getLogger(__name__)

# pySigma emits multi-field subfields such as process.executable.caseless.
# Elasticsearch reports those in field_caps as their own entries, but the
# telemetry question the user actually cares about is whether the parent
# field is populated. We keep both spellings and let the schema source
# decide which one it can answer for.
_SUBFIELD_SUFFIXES = (".caseless", ".keyword", ".text", ".raw")


@dataclass
class RuleFields:
    """One rule, and the field names it needs after pipeline resolution."""

    rule_id: str
    title: str
    path: Path
    logsource: str
    # Fields the rule needs in order to match. A missing one means the rule
    # cannot fire.
    fields: set[str] = dc_field(default_factory=set)
    # The condition reduced to the shape that decides satisfiability: a tree of
    # ("and", ...) / ("or", ...) / ("field", name) / ("any",) nodes. The engine
    # evaluates this against the set of fields that exist, so a rule dies only
    # when EVERY branch that could match is broken. Keeping the tree rather
    # than a flat set is what separates "reads this field somewhere" from
    # "cannot match without this field".
    condition_tree: tuple | None = None
    # Fields used only inside negated branches, which are exceptions rather
    # than requirements. A missing one does not stop the rule firing; it stops
    # the exception from applying, so the rule fires more often than intended.
    filter_only_fields: set[str] = dc_field(default_factory=set)
    # Values the pipeline resolved per field. Only routing fields such as
    # event.code and winlog.channel are used downstream; the engine never
    # asks whether a rule's other values would match real data.
    field_values: dict[str, set[str]] = dc_field(default_factory=dict)
    # Literals the rule matches on, per field. Used for one narrow question:
    # whether the ingest pipeline rewrites values of that shape. The engine
    # still never asks whether a literal occurs in real telemetry.
    field_literals: dict[str, set[str]] = dc_field(default_factory=dict)
    # The rule's path as the scan was asked for it. Two files named whoami.yml
    # in different directories are different rules, and when neither carries an
    # id this is the only thing that tells them apart downstream.
    rel_path: str = ""
    error: str | None = None

    @property
    def is_usable(self) -> bool:
        """Is there any field in the condition for the engine to check?

        A keyword-only rule, a rule whose fields the pipeline stripped and a
        rule whose condition we could not reduce all come through here with
        nothing to check, and `satisfiable` says yes to all three by
        construction. `fields` is the wrong thing to ask: a disjunctive rule
        has no required field and is still perfectly checkable.
        """
        return (
            self.error is None
            and self.condition_tree is not None
            and bool(tree_fields(self.condition_tree))
        )


ROUTING_FIELDS = ("event.code", "winlog.channel", "winlog.provider_name")


def _normalise_tree(node: tuple) -> tuple:
    """Apply subfield normalisation to every field name in a condition tree."""
    kind = node[0]
    if kind == "field":
        return ("field", normalise_field(node[1]))
    if kind in ("and", "or"):
        return (kind, tuple(_normalise_tree(a) for a in node[1]))
    return node


def _condition_fields(rule: SigmaRule) -> tuple[set[str], set[str], tuple] | None:
    """Split the fields a rule reads by the role the condition gives them.

    Two roles, and conflating them produces a wrong verdict:

    required  present on EVERY path that can satisfy the condition. Absent
              means the rule cannot match at all.
    negated   read only to carve out an exception ("selection and not 1 of
              filter_*"). If that field is absent the exception silently never
              applies and the rule fires MORE, not less.

    So AND unions its children's requirements and OR intersects them, which is
    the same semantics the engine already applies to alternative event IDs. A
    field read by only one branch of a disjunction is in neither role: it is
    not required, and losing it closes one route while the others stay open.
    The condition tree carries that case, so there is no flat set for it.

    Returns None when the condition cannot be parsed, which is a fact about our
    parsing and must not be laundered into a fact about the rule.
    """

    def tree(node, negated: bool) -> tuple:
        """Reduce one subtree to the shape that decides satisfiability.

        `negated` is the parity of the negations above this node, not merely
        whether there was one. At odd parity the subtree is an exception and
        reduces to ("any",), because an exception whose field is absent stops
        excluding rather than blocking. At even parity it requires its fields
        again: `not (not selection)` is `selection`, and collapsing every
        ConditionNOT on sight reported the field inside one as an exception.
        """
        if isinstance(node, ConditionNOT):
            inner = tuple(tree(a, not negated) for a in node.args)
            return inner[0] if len(inner) == 1 else ("and", inner)
        if negated:
            return ("any",)
        if isinstance(node, ConditionAND):
            return ("and", tuple(tree(a, negated) for a in node.args))
        if isinstance(node, ConditionOR):
            return ("or", tuple(tree(a, negated) for a in node.args))
        name = getattr(node, "field", None)
        return ("field", name) if name else ("any",)

    def walk(node, negated: bool) -> tuple[set[str], set[str], set[str]]:
        """Return (required, seen, negated_fields) for one subtree."""
        if isinstance(node, ConditionNOT):
            # Parity again: pass the flip down and let the leaves decide. The
            # children of an even-parity NOT are requirements, so their
            # requirements have to come back up rather than be discarded.
            req: set[str] = set()
            seen: set[str] = set()
            neg: set[str] = set()
            for arg in node.args:
                a_req, a_seen, a_neg = walk(arg, not negated)
                req |= a_req
                seen |= a_seen
                neg |= a_neg
            return req, seen, neg
        if isinstance(node, ConditionAND):
            req: set[str] = set()
            seen: set[str] = set()
            neg = set()
            for arg in node.args:
                a_req, a_seen, a_neg = walk(arg, negated)
                req |= a_req
                seen |= a_seen
                neg |= a_neg
            return req, seen, neg
        if isinstance(node, ConditionOR):
            reqs: list[set[str]] = []
            seen = set()
            neg = set()
            for arg in node.args:
                a_req, a_seen, a_neg = walk(arg, negated)
                reqs.append(a_req)
                seen |= a_seen
                neg |= a_neg
            return (set.intersection(*reqs) if reqs else set()), seen, neg
        name = getattr(node, "field", None)
        if not name:
            return set(), set(), set()
        if negated:
            return set(), set(), {name}
        return {name}, {name}, set()

    parsed_conditions = list(rule.detection.parsed_condition)
    if not parsed_conditions:
        return None

    # A rule may carry several conditions. Sigma fires the rule when any of
    # them matches, so they are alternatives and their requirements intersect.
    per_condition: list[set[str]] = []
    trees: list[tuple] = []
    seen_all: set[str] = set()
    negated_all: set[str] = set()
    for parsed in parsed_conditions:
        try:
            node = parsed.parse()
            req, seen, neg = walk(node, False)
            trees.append(tree(node, False))
        except Exception:
            return None
        per_condition.append(req)
        seen_all |= seen
        negated_all |= neg

    required = set.intersection(*per_condition) if per_condition else set()
    combined = trees[0] if len(trees) == 1 else ("or", tuple(trees))
    return required, negated_all - seen_all, combined


def tree_fields(node: tuple | None) -> set[str]:
    """Every field name in a reduced tree, whatever branch it sits in.

    This is the set to ask the SIEM about. `RuleFields.fields` holds only the
    required intersection, and narrowing a population query to that leaves
    every field of a `1 of selection_*` rule unqueried, which then comes back
    absent and reads as starvation.
    """
    if node is None:
        return set()
    kind = node[0]
    if kind == "field":
        return {node[1]}
    if kind in ("and", "or"):
        found: set[str] = set()
        for arg in node[1]:
            found |= tree_fields(arg)
        return found
    return set()


def satisfiable(node: tuple | None, present: set[str], ignore: set[str]) -> bool:
    """Can this condition still match when only `present` fields exist?

    Routing fields the pipeline injects are in `ignore` and always count as
    available, because they are not telemetry the rule depends on in the same
    sense. Without a tree we cannot answer, and the caller must not pretend we
    could.
    """
    if node is None:
        return True
    kind = node[0]
    if kind == "any":
        return True
    if kind == "field":
        return node[1] in ignore or node[1] in present
    if kind == "and":
        return all(satisfiable(a, present, ignore) for a in node[1])
    if kind == "or":
        return any(satisfiable(a, present, ignore) for a in node[1])
    return True


def blocking_fields(node: tuple | None, present: set[str], ignore: set[str]) -> set[str]:
    """The absent fields that actually stop this condition matching.

    Only the branches that could otherwise have matched are reported, so a rule
    is never blamed for a field in a branch that was already dead for its own
    reasons. Called only once `satisfiable` has said no.
    """
    if node is None:
        return set()
    kind = node[0]
    if kind == "any":
        return set()
    if kind == "field":
        name = node[1]
        return set() if (name in ignore or name in present) else {name}
    if kind == "and":
        # Only the conjuncts that actually failed. A conjunct that still holds
        # contributes nothing, and recursing into it named the absent field of
        # a surviving OR branch inside it as a cause of death.
        found: set[str] = set()
        for arg in node[1]:
            if not satisfiable(arg, present, ignore):
                found |= blocking_fields(arg, present, ignore)
        return found
    if kind == "or":
        # Every alternative failed; each one's missing fields are part of why.
        found = set()
        for arg in node[1]:
            found |= blocking_fields(arg, present, ignore)
        return found
    return set()


def _collect_values(
    detection: SigmaDetection, wanted: tuple[str, ...] | None = None
) -> dict[str, set[str]]:
    """Collect the literals a detection matches on, per field.

    With `wanted` set, only those fields are collected; that is how the routing
    fields (event.code, channel) are read. With it None, every field is
    collected, which the value-rewriting check needs.
    """
    found: dict[str, set[str]] = {}
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            for key, values in _collect_values(item, wanted).items():
                found.setdefault(key, set()).update(values)
        elif isinstance(item, SigmaDetectionItem):
            if item.field and (wanted is None or item.field in wanted):
                found.setdefault(item.field, set()).update(
                    str(v) for v in (item.value or [])
                )
    return found


def normalise_field(name: str) -> str:
    """Strip analyzer subfield suffixes so we ask the schema about the parent."""
    for suffix in _SUBFIELD_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _logsource_str(rule: SigmaRule) -> str:
    ls = rule.logsource
    parts = [p for p in (ls.product, ls.category, ls.service) if p]
    return "/".join(parts) if parts else "unspecified"


def extract_rule_fields(rule: SigmaRule, pipeline) -> RuleFields:
    """Apply the pipeline to one rule and return the fields it reads.

    The pipeline is applied to a copy-by-reload upstream; callers that reuse
    a rule object must not apply a pipeline twice, because pySigma mutates
    the rule in place.
    """
    result = RuleFields(
        rule_id=str(rule.id) if rule.id else "",
        title=rule.title or "",
        path=Path(str(rule.source.path)) if rule.source and rule.source.path else Path(),
        logsource=_logsource_str(rule),
    )
    try:
        pipeline.apply(rule)
    except Exception as exc:  # a rule the configured pipeline cannot handle
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    values: dict[str, set[str]] = {}
    literals: dict[str, set[str]] = {}
    for detection in rule.detection.detections.values():
        for key, found in _collect_values(detection, ROUTING_FIELDS).items():
            values.setdefault(key, set()).update(found)
        for key, found in _collect_values(detection).items():
            literals.setdefault(normalise_field(key), set()).update(found)

    result.field_values = values
    result.field_literals = literals

    split = _condition_fields(rule)
    if split is None:
        # We could not read the condition. That is a gap in our parsing, not a
        # finding about the rule, and guessing in either direction would put an
        # invented number on the page. Say so and let the caller report it.
        result.error = "condition could not be parsed, so its fields cannot be attributed"
        return result

    required, filter_only, tree = split
    result.condition_tree = _normalise_tree(tree)
    result.fields = {normalise_field(f) for f in required}
    result.filter_only_fields = {normalise_field(f) for f in filter_only} - result.fields
    return result


def load_corpus(
    rule_paths: list[Path],
    pipeline_factory,
    *,
    skip_correlation: bool = True,
) -> list[RuleFields]:
    """Load rules and resolve each one's fields under a fresh pipeline.

    pipeline_factory is called per rule because pySigma pipelines carry state
    and rules are mutated in place during application.
    """
    results: list[RuleFields] = []
    for path in rule_paths:
        try:
            # collect_errors, because a SigmaHQ file can hold several rules and
            # without it the first invalid one aborts the whole file. A file of
            # three rules then contributed one entry, so the denominator was no
            # longer the corpus size on disk.
            collection = SigmaCollection.load_ruleset([path], collect_errors=True)
        except Exception as exc:
            # The YAML itself did not parse, so there are no rules to count.
            results.append(
                RuleFields(
                    rule_id="",
                    title=path.stem,
                    path=path,
                    rel_path=str(path),
                    logsource="unparsed",
                    error=f"parse failed: {type(exc).__name__}: {exc}",
                )
            )
            continue

        for rule in collection.rules:
            errors = list(getattr(rule, "errors", None) or [])
            if errors:
                results.append(
                    RuleFields(
                        rule_id=str(getattr(rule, "id", "") or ""),
                        title=getattr(rule, "title", "") or path.stem,
                        path=path,
                        rel_path=str(path),
                        logsource="unparsed",
                        error="parse failed: "
                        + "; ".join(f"{type(e).__name__}: {e}" for e in errors),
                    )
                )
                continue
            if skip_correlation and not isinstance(rule, SigmaRule):
                # Correlation rules describe sequences, not single events, so a
                # field-presence check cannot judge them. They are recorded so
                # the report can state how many there were: dropping them
                # silently would mean the corpus size on the page is not the
                # corpus size on disk.
                results.append(
                    RuleFields(
                        rule_id=str(getattr(rule, "id", "") or ""),
                        title=getattr(rule, "title", "") or path.stem,
                        path=path,
                        rel_path=str(path),
                        logsource="correlation",
                        error="correlation rule: describes a sequence, not a single event",
                    )
                )
                continue
            resolved = extract_rule_fields(rule, pipeline_factory())
            resolved.rel_path = str(path)
            results.append(resolved)
    return results


def find_rule_files(root: Path, subdirs: list[str] | None = None) -> list[Path]:
    """Collect rule files, optionally restricted to subdirectories."""
    roots = [root / s for s in subdirs] if subdirs else [root]
    files: list[Path] = []
    for r in roots:
        if r.exists():
            found: set[Path] = set()
            for pattern in ("*.yml", "*.yaml"):
                found.update(r.rglob(pattern))
            files.extend(sorted(found))
    return files
