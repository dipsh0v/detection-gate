"""Read what the SIEM's ingest pipeline does to field names.

A rule can read a field that is genuinely absent from the schema while the
telemetry it needs is sitting right there under a different name, because the
ingest pipeline renamed it on the way in. Those two situations look identical
from the schema alone and need opposite fixes: one is "collect the telemetry",
the other is "fix your conversion".

Telling them apart stays a matter of fact rather than inference, because the
pipeline states its own renames. This module reads them out of the pipeline
definition and nothing else.

A pipeline is a sequence, not a mapping. The same source field is moved to two
different destinations under two different guards in Elastic's own Sysmon
pipeline, so every move keeps its position and its guard, and a question about
a destination is only ever answered for named event codes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Iterable

import yaml

_ED_SOURCE = re.compile(r"event_data\??\.(\w+)")
# Painless declares its regexes as: Pattern dwordRegex = /(?i)DWORD \((0x...)\)/;
# A pipeline that matches a field against one of these is not only renaming the
# field, it is rewriting the value, which breaks rules that match the raw form.
_PATTERN_DECL = re.compile(r"Pattern\s+\w+\s*=\s*/(.+?)/\s*;")
# A ctx assignment, at whatever depth it writes: ctx.registry.data = [...].
_CTX_ASSIGN = re.compile(r"ctx\.([A-Za-z_][\w.?]*?)\s*=(?!=)")
# set/append name their source as a mustache template: '{{{winlog.event_data.X}}}'.
_TEMPLATE = re.compile(r"^\{\{\{?\s*([A-Za-z_][\w.]*?)\s*\}?\}\}$")

# Patterns and literals both come from somewhere else: the pattern out of the
# pipeline's Painless, the literal out of a Sigma rule. Length is the only
# cheap defence against a pathological pair, so neither side gets to be long.
_MAX_PATTERN = 200
_MAX_LITERAL = 500


@dataclass(frozen=True)
class EventScope:
    """The event codes a claim about a move holds for.

    included  None means the guard names no event code, so the move is not
              restricted by one. A set means only those codes.
    excluded  codes the guard rules out, from `ctx.event.code != "7"`.
    unreadable  the guard talks about event.code in a shape we cannot read.
              That is not the same as no restriction, and treating it as one
              inverts the processor, so such a move supports no claim at all.
    """

    included: frozenset[int] | None = None
    excluded: frozenset[int] = frozenset()
    unreadable: bool = False

    def admits(self, event_ids: Iterable[int] = ()) -> bool:
        if self.unreadable:
            return False
        ids = set(event_ids)
        if not ids:
            # A rule that names no event code could be reading any of them, and
            # we cannot show the guard excludes it.
            return True
        if self.included is not None and not (ids & self.included):
            return False
        if self.excluded and ids <= self.excluded:
            return False
        return True

    def narrow(self, other: "EventScope") -> "EventScope":
        if self.included is None:
            included = other.included
        elif other.included is None:
            included = self.included
        else:
            included = self.included & other.included
        if included is not None:
            included = frozenset(included - self.excluded - other.excluded)
        return EventScope(
            included=included,
            excluded=frozenset(self.excluded | other.excluded),
            unreadable=self.unreadable or other.unreadable,
        )

    @property
    def restricted(self) -> bool:
        return self.included is not None or bool(self.excluded) or self.unreadable


UNRESTRICTED = EventScope()


@dataclass(frozen=True)
class FieldMove:
    """One processor moving one field's value to one other field.

    index is the processor's position in the sequence, which is what makes two
    moves of the same source distinguishable. processor is the processor type,
    kept because `rename` is the pipeline saying so outright while `set` with
    copy_from says the same thing in a different word.
    """

    source: str
    target: str
    index: int
    processor: str
    scope: EventScope = UNRESTRICTED
    # rename takes the value with it; convert, split and set-with-copy_from
    # leave the source where it was. The difference decides whether the chain
    # continues: file.pe.original_file_name is copied onward into dll.* for
    # event 7, and reporting only the end of that chain would send a rule past
    # the field that actually holds its value.
    removes_source: bool = False
    # The move happens only if the processor it hangs off threw. Weaker than a
    # move on the main path and must not be reported at the same strength.
    on_failure: bool = False
    # Guarded by something that is not an event code, so we cannot say whether
    # it ran for a given document.
    conditional: bool = False


@dataclass
class IngestFieldMap:
    """What an ingest pipeline does to field names.

    moves    every declared move, in pipeline order, with its guard. This is
             the pipeline making a statement about itself and the only strong
             evidence here.
    dropped  fields the pipeline deletes. A deletion is proof of deletion and
             nothing else: it does not say the value went anywhere. Where a
             destination cannot be derived from a move or a namespace, the
             honest answer is that the field is gone, not that it moved.
    renamed  flat source -> target view of `moves`, kept for callers that only
             want a count or a quick lookup. It is lossy exactly where the
             pipeline is interesting, so anything deciding a verdict reads
             `moves`.
    """

    renamed: dict[str, str] = dc_field(default_factory=dict)
    dropped: set[str] = dc_field(default_factory=set)
    # Weaker evidence: a script processor reads this field and writes into the
    # named namespace. Reported only when the schema confirms the namespace.
    namespaces: dict[str, str] = dc_field(default_factory=dict)
    # Fields whose VALUES the pipeline parses and rewrites, with the patterns
    # it recognises. Renaming a field is one problem; reshaping what it holds
    # is a second one, and a rule that matches the original text still fails
    # after the name is fixed.
    value_patterns: dict[str, list[str]] = dc_field(default_factory=dict)
    # The full paths a script writes, per field it reads. We cannot say which
    # of them carries this particular value, so they are offered as the
    # candidates to confirm rather than asserted as the destination.
    namespace_targets: dict[str, list[str]] = dc_field(default_factory=dict)
    # Renames the pipeline performs only for certain event codes. A claim about
    # where a value went is only true for the events the guard admits.
    rename_event_codes: dict[str, set[int]] = dc_field(default_factory=dict)
    moves: list[FieldMove] = dc_field(default_factory=list)
    # The guard on the script that produced a namespace claim, same reasoning
    # as rename_event_codes: the script that writes dll.* runs on event 7 only.
    namespace_scopes: dict[str, EventScope] = dc_field(default_factory=dict)
    drop_scopes: dict[str, EventScope] = dc_field(default_factory=dict)
    # Fields removed by a guarded remove processor. The removal is real but not
    # unconditional, and a report that says "the pipeline removes this" without
    # the guard is overstating what the pipeline does.
    conditional_drops: set[str] = dc_field(default_factory=set)
    # Fields removed by a handler that runs only when the processor it hangs
    # off threw. The removal is in the pipeline text, not on its main path.
    on_failure_drops: set[str] = dc_field(default_factory=set)
    # Fields some remove processor deletes unconditionally. Kept apart so a
    # field that is also removed on a failure path is not reported as if the
    # weaker statement were the only one.
    dropped_on_main_path: set[str] = dc_field(default_factory=set)
    # Fields named by a processor type this module does not model. We know
    # something happened to them and not what, which is "not assessed" and not
    # "absent": the difference decides whether a rule is reported dead.
    unassessed: set[str] = dc_field(default_factory=set)
    unmodelled_types: dict[str, int] = dc_field(default_factory=dict)
    source: str = ""

    def __post_init__(self) -> None:
        if self.renamed and not self.moves:
            # Hand-built maps (tests, and callers that know their pipeline)
            # pass renamed/rename_event_codes directly. Fold them into the
            # sequence so there is one code path below.
            for index, (source, target) in enumerate(sorted(self.renamed.items())):
                codes = self.rename_event_codes.get(source)
                self.moves.append(
                    FieldMove(
                        source=source,
                        target=target,
                        index=index,
                        processor="rename",
                        removes_source=True,
                        scope=EventScope(included=frozenset(codes)) if codes else UNRESTRICTED,
                    )
                )

    def _from(self, field: str) -> list[FieldMove]:
        return [m for m in self.moves if m.source == field]

    def destination_of(
        self, field: str, event_ids: Iterable[int] = ()
    ) -> tuple[str | None, EventScope]:
        """Where a field's value ends up, and for which events it goes there.

        Pipelines chain moves (Hash -> Hashes -> _temp.hashes -> process.hash),
        and every hop carries its own guard. The guard on the first hop is not
        the guard on the chain: Hashes is staged for everything and renamed
        onward only for event codes 1, 23, 24 and 25, while event 7 takes the
        same staged value to dll.hash. Reading the first guard and then walking
        the rest of the chain unguarded is how an ImageLoad rule gets told its
        hashes are in process.hash.

        The returned scope is the intersection of the guards along the chain,
        so a caller can intersect it with the events its rule reads.
        """
        destinations = self.destinations_of(field, event_ids)
        if not destinations:
            return None, UNRESTRICTED
        target, scope = destinations[0]
        return target, scope

    def destinations_of(
        self, field: str, event_ids: Iterable[int] = ()
    ) -> list[tuple[str, EventScope]]:
        """Every chain out of this field whose guards admit these events.

        More than one survives when the pipeline moves a source twice under
        different guards, which is the normal case for a rule that names no
        event code: OriginalFileName goes to process.pe.original_file_name for
        everything but event 7 and to file.pe.original_file_name for event 7.
        """
        ids = tuple(event_ids)
        results: list[tuple[str, EventScope]] = []
        for first in self._from(field):
            scope = first.scope
            if not scope.admits(ids):
                continue
            current = first.target
            seen = {field, current}
            while True:
                step = None
                for candidate in self._from(current):
                    merged = scope.narrow(candidate.scope)
                    if not merged.admits(ids) or candidate.target in seen:
                        continue
                    # Only follow a hop that empties the field we are standing
                    # on. A copy leaves the value here as well, and here is
                    # where the rule should be repointed.
                    if not candidate.removes_source and current not in self.dropped:
                        continue
                    step = (candidate, merged)
                    break
                if step is None:
                    break
                current, scope = step[0].target, step[1]
                seen.add(current)
            if current != field:
                results.append((current, scope))
        ordered: list[tuple[str, EventScope]] = []
        for target, scope in results:
            if target not in [t for t, _ in ordered]:
                ordered.append((target, scope))
        return ordered

    def applies_to(self, field: str, event_ids: list[int]) -> bool:
        """Does any of this field's moves happen for the events a rule reads?

        Unguarded moves apply to everything. A guarded one applies only if the
        rule's events overlap what the guard admits; a rule reading no event
        code at all is left alone, since we cannot show it does not.
        """
        moves = self._from(field)
        if not moves:
            return True
        return any(m.scope.admits(event_ids) for m in moves)

    def evidence_note(self, field: str) -> str | None:
        """A qualification the report has to print alongside a destination.

        Both cases here are moves that exist but do not simply happen: one runs
        only when the processor before it threw, the other behind a guard we
        can read but not evaluate.
        """
        moves = self._from(field)
        if moves and all(m.on_failure for m in moves):
            return "only when the primary processor fails"
        if moves and all(m.conditional for m in moves):
            return "only when the processor's condition holds"
        return None

    def removal_note(self, field: str) -> str | None:
        """How firmly the pipeline removes this field, when it is not plain."""
        if field in self.dropped_on_main_path:
            return None
        if field in self.on_failure_drops:
            return "removed only when the primary processor fails"
        if field in self.conditional_drops:
            return "removed only when the processor's condition holds"
        return None

    def is_unassessed(self, field: str) -> bool:
        return field in self.unassessed

    def resolve_fields(
        self, field: str, schema: set[str], event_ids: list[int] | None = None
    ) -> tuple[list[str] | None, str | None, bool]:
        """Where this field's value ends up, and how strongly we know it.

        Returns (names, evidence, namespace_only). names is the field names a
        rule could be repointed at, as names rather than as a sentence, so the
        caller does not have to take a display string apart to use it. When
        namespace_only is true the single name is a namespace and not a field:
        the pipeline writes into it and we cannot say which leaf carries this
        value. The evidence strings match verdict.Evidence.

        Nothing here guesses: every branch requires either a move the pipeline
        declares or a namespace the schema confirms, and a field the pipeline
        merely deletes resolves to nothing.
        """
        ids = list(event_ids or [])
        declared = self.destinations_of(field, ids)
        landed = sorted({target for target, _ in declared if target in schema})
        if landed:
            return landed, "DECLARED_RENAME", False
        if self._from(field) and not declared:
            # The pipeline does move this field, but not for the events this
            # rule reads. Saying where it goes for other events would be a
            # true sentence about the wrong document.
            return None, None, False

        # The chain may end on a field the schema does not have because a later
        # processor stages it onward. Follow the endpoint's namespace.
        for candidate in [field] + [target for target, _ in declared]:
            found: list[tuple[list[str], str, bool]] = []
            for staged, traversed in self._staged_destinations(candidate, ids):
                # A namespace read out of a script, with no move traversed, is
                # the weakest thing this module reports and says so even when
                # the endpoint happens to exist.
                tier = "STAGED_RENAME" if traversed else "NAMESPACE"
                children = sorted(n for n in schema if n.startswith(staged + "."))
                if children:
                    # Naming the namespace is not an action anyone can take.
                    # Name the fields when there are few enough to act on, and
                    # otherwise say the namespace and let the report mark it as
                    # the weaker claim.
                    leaves = [
                        c for c in children
                        if c.count(".") == staged.count(".") + 1
                        and not c.endswith(".keyword")
                    ]
                    if len(leaves) == 1:
                        found.append((leaves, tier, False))
                    elif 2 <= len(leaves) <= 4:
                        found.append((leaves, "NAMESPACE", False))
                    else:
                        found.append(([staged], "NAMESPACE", True))
                elif staged in schema:
                    found.append(([staged], tier, False))
            if not found:
                continue
            concrete = [f for f in found if not f[2]]
            if not concrete:
                return found[0][0], "NAMESPACE", True
            names = sorted({n for entry in concrete for n in entry[0]})
            tier = (
                "STAGED_RENAME"
                if all(entry[1] == "STAGED_RENAME" for entry in concrete)
                else "NAMESPACE"
            )
            return names, tier, False
        return None, None, False

    def resolve(
        self, field: str, schema: set[str], event_ids: list[int] | None = None
    ) -> tuple[str | None, str | None]:
        """resolve_fields as one display string. Prefer resolve_fields."""
        names, evidence, namespace_only = self.resolve_fields(field, schema, event_ids)
        if not names:
            return None, evidence
        if namespace_only:
            return f"{names[0]}.*", evidence
        return ", ".join(names), evidence

    def _staged_destinations(
        self, field: str, event_ids: Iterable[int] = ()
    ) -> list[tuple[str, bool]]:
        """Follow a field's intermediate namespace to where it finally lands.

        Pipelines stage a value into a scratch namespace and rename it out of
        there in a later processor: Hashes is parsed into _temp.hashes, and
        _temp.hashes is then renamed to process.hash. Reading only the first
        hop reports a scratch name that exists in no schema, which is how a
        recoverable destination gets reported as unknown.

        Each entry says whether a move was actually traversed to reach it,
        because a namespace nobody renamed out of is not a staged rename. There
        can be more than one: the staged hashes go to file.hash and dll.hash
        for an ImageLoad event and to process.hash for a process event.
        """
        namespace = self.namespaces.get(field)
        if namespace is None:
            return []
        scope = self.namespace_scopes.get(field, UNRESTRICTED)
        if not scope.admits(event_ids):
            return []
        # The staged name may be recorded with or without its leading
        # underscore; moves are declared against the literal spelling.
        for candidate in (namespace, f"_{namespace}", namespace.lstrip("_")):
            targets = self.destinations_of(candidate, event_ids)
            if targets:
                return [(target, True) for target, _ in targets]
        return [(namespace, False)]

    def rewrites_value(self, field: str, value: str) -> str | None:
        """Return the pattern that rewrites this literal, when one does.

        Two things decide this, and getting either wrong manufactures a
        finding out of nothing.

        Painless calls `matcher.matches()`, which requires the pattern to match
        the WHOLE value. A substring test would say yes to every Sigma literal
        that merely contains a matching fragment, and Sigma literals are full
        of wildcards, so almost all of them contain one. The pipeline's own
        else-branch then stores such a value unchanged, which is the opposite
        of what a substring test would have reported.

        And a Sigma literal carrying a wildcard cannot be compared to a regex
        at all: it stands for a set of values, some of which the pipeline would
        rewrite and some of which it would not. The honest answer there is that
        we do not know, so we say nothing.
        """
        if "*" in value or "?" in value:
            return None
        if len(value) > _MAX_LITERAL:
            return None
        for pattern in self.value_patterns.get(field, []):
            if len(pattern) > _MAX_PATTERN:
                continue
            try:
                if re.fullmatch(pattern, value):
                    return pattern
            except re.error:
                continue
        return None


_GUARD_EQUALS = re.compile(r"ctx\.event\.code\s*(==|!=)\s*[\"'](\d+)[\"']")
_GUARD_CONTAINS = re.compile(r"(!?)\s*\[([^\]]*)\]\s*\.contains\(\s*ctx\.event\.code")


def _guard_scope(guard: str | None) -> EventScope:
    """The event codes an `if:` guard restricts a processor to.

    Only the shapes Elastic's own pipelines use are read: equality, inequality
    and membership in a list, positive or negated. Inequality matters as much
    as equality, because `ctx.event.code != "7"` read as an empty set of codes
    means unrestricted, which is the exact inverse of the processor.
    """
    if not guard:
        return UNRESTRICTED
    included: set[int] = set()
    excluded: set[int] = set()
    for operator, code in _GUARD_EQUALS.findall(guard):
        (included if operator == "==" else excluded).add(int(code))
    for negation, group in _GUARD_CONTAINS.findall(guard):
        codes = {int(c) for c in re.findall(r"[\"'](\d+)[\"']", group)}
        (excluded if negation else included).update(codes)
    if not included and not excluded:
        return EventScope(unreadable="event.code" in guard)
    return EventScope(
        included=frozenset(included) if included else None,
        excluded=frozenset(excluded),
    )


def _tests_field(source: str, field: str, pattern: str) -> bool:
    """Does this script actually match this pattern against this field?

    Painless names the regex, binds it to a variable, and calls .matcher(...)
    on that variable with the value under test. We follow that chain rather
    than assuming every pattern in a script applies to every field it reads:

        Pattern dwordRegex = /.../;      <- the declaration
        def data = ctx.winlog?.event_data?.Details;
        Matcher m = dwordRegex.matcher(data);   <- the binding we need

    Anything we cannot follow returns False, so an unreadable script produces
    no claim instead of a speculative one.
    """
    leaf = field.rsplit(".", 1)[-1]
    declaration = re.search(
        r"Pattern\s+(\w+)\s*=\s*/" + re.escape(pattern) + r"/\s*;", source
    )
    if not declaration:
        return False
    variable = declaration.group(1)

    # The value under test is either the field expression itself or a local
    # variable assigned from it, possibly through one further hop.
    aliases = {leaf}
    for _ in range(3):
        for name, expression in re.findall(r"def\s+(\w+)\s*=\s*([^;]+);", source):
            if any(re.search(rf"\b{re.escape(a)}\b", expression) for a in aliases):
                aliases.add(name)
    binding = None
    for alias in aliases:
        found = re.search(
            rf"{re.escape(variable)}\.matcher\(\s*{re.escape(alias)}\b", source
        )
        if found:
            binding = found
            break
    if binding is None:
        return False

    # Matching is not rewriting. The pipeline's Binary Data branch matches and
    # then stores the value unchanged, while the DWORD and QWORD branches parse
    # it into a decimal string. Only the second kind breaks a rule that matches
    # on the original text, so read what the branch actually stores.
    branch = source[binding.end():]
    end = branch.find("return;")
    if end != -1:
        branch = branch[:end]
    stored = re.findall(r"[\[:=]\s*\[?\s*([A-Za-z_]\w*)\s*\]", branch)
    if stored and all(name in aliases for name in stored):
        return False
    return True


def _statements(source: str) -> list[tuple[int, str]]:
    """Painless source as (block depth, statement) pairs.

    Crude but enough for what follows: a statement ends at `;` or at a brace,
    and the depth is how many open braces it sits inside. An `if (...)` is
    therefore its own statement at the outer depth and its body one deeper,
    which is the distinction we need, because a field read inside a condition
    is a test and a field read on the right of an assignment is a value.
    """
    statements: list[tuple[int, str]] = []
    depth = 0
    buffer: list[str] = []

    def flush(at_depth: int) -> None:
        text = "".join(buffer).strip()
        buffer.clear()
        if text:
            statements.append((at_depth, text))

    for character in source:
        if character == ";":
            flush(depth)
        elif character == "{":
            flush(depth)
            depth += 1
        elif character == "}":
            flush(depth)
            depth = max(0, depth - 1)
        else:
            buffer.append(character)
    flush(depth)
    return statements


def _script_writes(source: str) -> dict[str, list[str]]:
    """Which event_data fields a script writes where, by following its values.

    Reading "the first ctx.* this script assigns" and attaching it to every
    field the script mentions puts SignatureStatus in the dll namespace on the
    strength of a `ctx.dll = ctx.dll ?: [:]` line that does not read it at
    all, while for every event but ImageLoad the value goes to
    file.code_signature.status. So an assignment only counts for the fields its
    own right-hand side reads, directly or through a local in scope.
    """
    # A Painless regex literal can contain the semicolon this walk splits on:
    # /;/.split(ctx.winlog.event_data.QueryResults) would otherwise become two
    # fragments, neither of which is an assignment. The patterns themselves
    # read no fields, so blanking them loses nothing here.
    source = re.sub(r"/(?:\\.|[^/\n\\])+/", "/re/", source)
    reads: dict[str, list[str]] = {}
    # name -> the event_data fields its value came from, with the depth it was
    # declared at so it can be dropped when that block closes.
    aliases: dict[str, tuple[int, set[str]]] = {}

    def sources_in(expression: str) -> set[str]:
        found = {f"winlog.event_data.{name}" for name in _ED_SOURCE.findall(expression)}
        for name, (_depth, fields) in aliases.items():
            if fields and re.search(rf"\b{re.escape(name)}\b", expression):
                found |= fields
        return found

    def bind(name: str, fields: set[str], depth: int) -> None:
        if not fields:
            aliases.setdefault(name, (depth, set()))
            return
        known = aliases.get(name)
        aliases[name] = (known[0] if known else depth, (known[1] if known else set()) | fields)

    for depth, statement in _statements(source):
        for name in [n for n, (declared, _) in aliases.items() if declared > depth]:
            del aliases[name]

        assignment = _CTX_ASSIGN.search(statement)
        if assignment:
            path = assignment.group(1).replace("?", "").strip(".")
            right = statement[assignment.end():]
            for name in sources_in(right):
                reads.setdefault(name, [])
                if path not in reads[name]:
                    reads[name].append(path)
            continue

        local = re.match(r"(?:def|[A-Z]\w*)?\s*(\w+)\s*=(?!=)(.+)", statement)
        if local:
            bind(local.group(1), sources_in(local.group(2)), depth)
            continue
        # A value appended into a collection is that collection's value too:
        # QueryResults reaches dns.answers through answers.add(...).
        appended = re.match(r"(\w+)\s*\.\s*add\((.+)\)\s*$", statement, re.DOTALL)
        if appended and appended.group(1) in aliases:
            bind(appended.group(1), sources_in(appended.group(2)), aliases[appended.group(1)][0])
    return reads


def _record_move(
    out: IngestFieldMap,
    source: str,
    target: str,
    *,
    index: int,
    processor: str,
    scope: EventScope,
    guard: str | None,
    on_failure: bool,
    removes_source: bool,
) -> None:
    out.moves.append(
        FieldMove(
            source=source,
            target=target,
            index=index,
            processor=processor,
            scope=scope,
            removes_source=removes_source,
            on_failure=on_failure,
            conditional=bool(guard) and not scope.restricted,
        )
    )


def _walk_processors(
    processors,
    out: IngestFieldMap,
    *,
    index: int | None = None,
    scope: EventScope = UNRESTRICTED,
    on_failure: bool = False,
) -> None:
    for position, entry in enumerate(processors or []):
        if not isinstance(entry, dict):
            continue
        step = position if index is None else index
        for kind, body in entry.items():
            if not isinstance(body, dict):
                continue
            guard = body.get("if") if isinstance(body.get("if"), str) else None
            here = scope.narrow(_guard_scope(guard))
            name = body.get("field")
            if isinstance(name, str) and name.startswith("_ingest."):
                # Inside a foreach, _ingest._value is the array element, not a
                # field of the document.
                continue
            target = body.get("target_field")
            copy_from = body.get("copy_from")

            def move(source: str, destination: str, processor: str = kind) -> None:
                _record_move(
                    out, source, destination,
                    index=step, processor=processor, scope=here,
                    guard=guard, on_failure=on_failure,
                    removes_source=processor == "rename",
                )

            if kind == "remove":
                names = [name] if isinstance(name, str) else (name or [])
                for dropped in names:
                    if not isinstance(dropped, str) or dropped.startswith("_ingest."):
                        continue
                    out.dropped.add(dropped)
                    out.drop_scopes[dropped] = here
                    if on_failure:
                        out.on_failure_drops.add(dropped)
                    elif guard and not here.restricted:
                        out.conditional_drops.add(dropped)
                    else:
                        out.dropped_on_main_path.add(dropped)
            elif kind == "script":
                _read_script(body, out, scope=here)
            elif kind == "kv" and isinstance(name, str) and isinstance(target, str):
                # kv explodes one string into a sub-document, so the value
                # lands under the target but not under a name we can state.
                out.namespaces.setdefault(name, target.lstrip("_"))
                out.namespace_scopes.setdefault(name, here)
            elif kind in ("foreach", "pipeline"):
                nested = body.get("processor") or body.get("processors")
                if isinstance(nested, dict):
                    nested = [nested]
                if isinstance(nested, list):
                    _walk_processors(
                        nested, out, index=step, scope=here, on_failure=on_failure
                    )
            elif isinstance(copy_from, str) and isinstance(name, str):
                # `set` with copy_from is a move stated as plainly as a rename:
                # set file.hash copy_from _temp.hashes.
                move(copy_from, name)
            elif isinstance(name, str) and isinstance(target, str):
                # convert, split, date, registered_domain: a different verb for
                # the same statement, "this field's value goes to that field".
                move(name, target)
            elif isinstance(name, str) and isinstance(body.get("value"), str):
                template = _TEMPLATE.match(body["value"].strip())
                if template and not template.group(1).startswith("_ingest."):
                    move(template.group(1), name)
            elif isinstance(name, str) and kind not in ("set", "append"):
                # We saw a processor touch this field and cannot say what it
                # did. Recording nothing would let the field be reported absent
                # on our silence.
                out.unassessed.add(name)
                out.unmodelled_types[kind] = out.unmodelled_types.get(kind, 0) + 1

            for handler in (body.get("on_failure") or []):
                _walk_processors(
                    [handler], out, index=step, scope=here, on_failure=True
                )


def _read_script(body: dict, out: IngestFieldMap, *, scope: EventScope) -> None:
    source = body.get("source")
    if not isinstance(source, str):
        return
    for field, paths in _script_writes(source).items():
        namespace = paths[0].split(".")[0]
        out.namespaces.setdefault(field, namespace)
        out.namespace_scopes.setdefault(field, scope)
        deep = sorted(p for p in paths if "." in p)
        if deep:
            out.namespace_targets.setdefault(field, deep)
    patterns = _PATTERN_DECL.findall(source)
    read_fields = {f"winlog.event_data.{n}" for n in set(_ED_SOURCE.findall(source))}
    if not (patterns and read_fields):
        return
    # Attach a pattern only to the field the script tests it against.
    # Spreading every pattern in a script over every field it reads is not
    # conservative, whatever it looks like: it cannot suppress a real finding,
    # only invent one, and it invented the claim that registry TargetObject
    # values are DWORD-shaped.
    for key in read_fields:
        matched = [p for p in patterns if _tests_field(source, key, p)]
        if matched:
            out.value_patterns.setdefault(key, []).extend(matched)


def _flatten(out: IngestFieldMap) -> None:
    out.renamed = {}
    out.rename_event_codes = {}
    for move in out.moves:
        if move.source in out.renamed:
            continue
        out.renamed[move.source] = move.target
        if move.scope.included is not None:
            out.rename_event_codes[move.source] = set(move.scope.included)


def load_ingest_map(path: Path) -> IngestFieldMap:
    """Parse an Elasticsearch ingest pipeline definition (YAML or JSON)."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    result = IngestFieldMap(source=path.name)
    if isinstance(document, dict):
        _walk_processors(document.get("processors"), result)
    _flatten(result)
    return result
