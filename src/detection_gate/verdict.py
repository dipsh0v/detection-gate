"""The verdict engine.

Every verdict here is a fact with a named cause. Nothing is scored, nothing
is inferred, and nothing is probabilistic. A rule needs an event that the
sensor either produces or does not, and fields the schema either has or does
not, carrying data or not.

Two verdicts deliberately do not exist:

  - "probably fires". detection-gate never asks whether the rule's *values* would
    ever match, only whether the field exists and carries data. The value
    question is genuinely fuzzy and is out of scope by design.
  - "broken". A rule outside the configured pipeline's scope is reported as
    OUT_OF_SCOPE, not as dead. Counting those as dead inflates the headline
    and is the first thing an informed audience would catch.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from enum import Enum

from .ingest import IngestFieldMap
from .rules import RuleFields, blocking_fields, satisfiable, tree_fields
from .sysmon import ALWAYS_ON_EVENT_IDS, Collection, SysmonProfile


class Verdict(str, Enum):
    FIREABLE = "FIREABLE"
    DEAD_ON_ARRIVAL = "DEAD-ON-ARRIVAL"
    MISMAPPED = "MISMAPPED"
    STARVED = "STARVED"
    OUT_OF_SCOPE = "OUT-OF-SCOPE"
    # A rule detection-gate could not judge. Kept apart from OUT_OF_SCOPE because
    # "this rule serves another log source" is a finding about the rule and
    # "we could not convert it" is a finding about us. Folding the second into
    # the first would state something false and would take the rule out of the
    # denominator, raising the headline percentage; these stay in it.
    NOT_ASSESSED = "NOT-ASSESSED"


class ScopeReason(str, Enum):
    """Why a rule was set aside, at the resolution a reader needs.

    The report prints these separately. A single count under one sentence is
    the first place a hostile reader looks for things that were hidden.
    """

    OTHER_CHANNEL = "serves another log source"
    FOREIGN_EVENT_ID = "event id outside this sensor"
    NO_CHANNEL = "could not be attributed to a log source"
    UNMAPPED_EVENT = "event id not mappable to this sensor"
    CONVERSION_FAILED = "the conversion pipeline could not process it"
    CORRELATION_RULE = "correlation rule, not a single-event rule"
    NOTHING_CHECKED = "no field or event id left to check it against"
    UNCHECKED_FIELD = "its verdict turns on a field the snapshot never asked about"


class DeadCause(str, Enum):
    EVENT_NOT_COLLECTED = "event-not-collected"
    EVENT_UNMAPPED = "event-not-mappable-to-this-sensor"
    FIELD_ABSENT = "field-absent-from-schema"


class Evidence(str, Enum):
    """How strongly the pipeline supports a claim about where a value went.

    The difference matters to a reader deciding whether to act: a declared
    rename is the pipeline stating what it does, while a namespace is us
    reading a script and matching a prefix against the schema. Rendering both
    with the same confidence is how a careful inference becomes a false fact.
    """

    DECLARED_RENAME = "the pipeline declares this rename"
    STAGED_RENAME = "the pipeline stages the value, then renames it here"
    NAMESPACE = "a script writes this namespace and the schema confirms it"


@dataclass
class RuleVerdict:
    rule_id: str
    title: str
    logsource: str
    verdict: Verdict
    # The file this rule came from. Carried so a finding can be reported
    # against the rule in a code review rather than in a separate document.
    path: str = ""
    # The path as the scan was asked for it, which is what identifies a rule
    # that has no id. Two whoami.yml files in different directories both fall
    # back to the title "whoami", so a baseline keyed on title alone merges
    # them and accepts one rule's failure on behalf of the other.
    rel_path: str = ""
    cause: DeadCause | None = None
    # Why a rule was set aside, when it was. Reported per reason rather than as
    # one total, so nobody has to wonder what is inside the bucket.
    scope_reason: ScopeReason | None = None
    # The specific things that caused this verdict, named so the user can act.
    missing_fields: list[str] = dc_field(default_factory=list)
    # For MISMAPPED: the field the rule reads, and where the ingest pipeline
    # actually put its value.
    mismapped_fields: list[tuple[str, str]] = dc_field(default_factory=list)
    # Fields where the pipeline also rewrites the value, not just the name.
    # Pointing the rule at the new field is then not enough on its own.
    rewritten_values: list[tuple[str, str]] = dc_field(default_factory=list)
    # How strongly the pipeline supports each mismap destination, so the report
    # can show a derived destination as derived rather than as declared.
    evidence: dict[str, "Evidence"] = dc_field(default_factory=dict)
    # Absent fields the pipeline explicitly deletes without stating where the
    # value went. Recorded as context, never as a destination.
    dropped_fields: list[str] = dc_field(default_factory=list)
    # Where the destination is a namespace, the fields inside it the pipeline
    # script actually writes. Offered for the reader to confirm, because which
    # one holds this value is not something the pipeline states.
    destination_candidates: dict[str, list[str]] = dc_field(default_factory=dict)
    # Mismap destinations that exist in the schema but carry no data, so
    # following the advice would trade one dead rule for another.
    unpopulated_destinations: list[tuple[str, str]] = dc_field(default_factory=list)
    # The destination field names behind each mismapped field, kept as data.
    # ingest.resolve() answers with a string built for a human to read, which
    # is one field name, several joined with ", ", or a "ns.*" wildcard. The
    # split happens here, once, while the names are still names; a renderer
    # that split the sentence back apart would be guessing at our own prose.
    # The contract to ask ingest.resolve() for is list[str] plus a flag for
    # the wildcard case, at which point this field is filled directly.
    destination_fields: dict[str, list[str]] = dc_field(default_factory=dict)
    missing_event_ids: list[int] = dc_field(default_factory=list)
    # The config element names behind those IDs, carried as data so the report
    # never recovers them by re-parsing a sentence written for humans.
    missing_event_elements: list[str] = dc_field(default_factory=list)
    starved_fields: list[str] = dc_field(default_factory=list)
    # Fields the population query never asked the cluster about, in a rule
    # whose population verdict turned on them. Named so the fix is obvious:
    # widen the snapshot, then run again.
    unchecked_fields: list[str] = dc_field(default_factory=list)
    # Set when the event is collected but only for a subset of activity.
    filtered_event_ids: list[int] = dc_field(default_factory=list)
    # Event IDs we have no element mapping for. A gap in our knowledge of the
    # sensor, never reported as a statement about the customer's config.
    unmapped_event_ids: list[int] = dc_field(default_factory=list)
    # Fields the rule reads only to carve out exceptions. When these are
    # missing the rule still fires, but the exception never applies, so it
    # fires more often than its author intended.
    degraded_filters: list[str] = dc_field(default_factory=list)
    # Exception fields the conversion moved rather than lost. Same effect on
    # the deployed query, different owner and a different fix.
    degraded_mismaps: list[tuple[str, str]] = dc_field(default_factory=list)
    detail: str = ""

    @property
    def is_dead(self) -> bool:
        """Cannot fire as deployed, whatever the reason."""
        return self.verdict in (Verdict.DEAD_ON_ARRIVAL, Verdict.MISMAPPED)


def _parent_names(schema_fields: set[str]) -> set[str]:
    """Every dotted prefix of every schema field, so a namespace is one lookup."""
    found: set[str] = set()
    for name in schema_fields:
        cut = name.rfind(".")
        while cut > 0:
            parent = name[:cut]
            if parent in found:
                break
            found.add(parent)
            cut = parent.rfind(".")
    return found


def _destination_fields(destination: str) -> list[str]:
    """The field names inside a destination ingest.resolve() built for a reader.

    One name, several joined with ", ", or a "ns.*" wildcard, which names no
    field at all. See RuleVerdict.destination_fields for the contract that
    would make this unnecessary.
    """
    if destination.endswith(".*"):
        return []
    return [part.strip() for part in destination.split(",") if part.strip()]


def required_event_ids(rule: RuleFields, event_code_field: str = "event.code") -> list[int]:
    """Event IDs the rule requires, as the pipeline resolved them."""
    values = rule.field_values.get(event_code_field, set())
    ids: list[int] = []
    for value in values:
        text = str(value).strip()
        if text.isdigit():
            ids.append(int(text))
    return sorted(set(ids))


def evaluate(
    rule: RuleFields,
    *,
    profile: SysmonProfile | None = None,
    schema_fields: set[str] | None = None,
    populated_fields: set[str] | None = None,
    checked_fields: set[str] | None = None,
    sensor_scope_channels: set[str] | None = None,
    sensor_event_id_space: set[int] | None = None,
    ingest_map: IngestFieldMap | None = None,
    ignore_fields: set[str] | None = None,
) -> RuleVerdict:
    """Decide one rule's fate against a sensor config and a schema.

    profile          which Sysmon config is deployed (event-level check)
    schema_fields    field names the SIEM schema knows about
    populated_fields field names that actually carry data in the window
    checked_fields   field names the population query actually asked about.
                     None means an older snapshot that did not record it, and
                     then the population check behaves as it always did. When
                     it is given, a field outside it is unknown rather than
                     empty, and a rule whose fate turns on one is NOT_ASSESSED
    sensor_scope_channels  channels the profile speaks for; a rule reading
                     another channel is OUT_OF_SCOPE rather than dead
    ignore_fields    routing fields such as winlog.channel and event.code,
                     which the pipeline injects and which are not telemetry
                     the rule depends on in the same sense
    """
    ignore = ignore_fields or set()
    result = RuleVerdict(
        rule_id=rule.rule_id,
        title=rule.title,
        logsource=rule.logsource,
        path=str(rule.path) if rule.path else "",
        rel_path=rule.rel_path or (str(rule.path) if rule.path else ""),
        verdict=Verdict.FIREABLE,
    )

    if rule.error:
        # We could not convert or parse this rule. That is our failure, not a
        # property of the rule, and it must not be counted as "serves another
        # log source" nor silently removed from the denominator.
        result.verdict = Verdict.NOT_ASSESSED
        result.scope_reason = (
            ScopeReason.CORRELATION_RULE
            if rule.logsource == "correlation"
            else ScopeReason.CONVERSION_FAILED
        )
        result.detail = rule.error
        return result

    channels = {str(v) for v in rule.field_values.get("winlog.channel", set())}
    event_ids = required_event_ids(rule)

    # A rule the configured pipeline did not resolve to this sensor's channel
    # is not this sensor's failure. Say so instead of counting it as dead.
    if sensor_scope_channels is not None and channels:
        if not (channels & sensor_scope_channels):
            result.verdict = Verdict.OUT_OF_SCOPE
            result.scope_reason = ScopeReason.OTHER_CHANNEL
            result.detail = f"channel outside sensor scope: {sorted(channels)}"
            return result

    # Without a channel we cannot say which log source the rule belongs to, and
    # event IDs alone do not settle it: numbering is per-channel, so EventID 29
    # is FileExecutableDetected in Sysmon and something else entirely in
    # IIS-Configuration. Judging such a rule against a Sysmon config would
    # report an IIS rule as a Sysmon failure.
    if sensor_scope_channels is not None and not channels:
        result.verdict = Verdict.OUT_OF_SCOPE
        result.scope_reason = ScopeReason.NO_CHANNEL
        result.detail = (
            "the pipeline resolved no channel for this rule, so it cannot be "
            "attributed to this sensor on event id alone"
        )
        return result

    # A rule asking for an event ID this sensor cannot emit is asking a
    # different log source. This check is deliberately skipped once the rule
    # sits on this sensor's own channel: an unknown event ID there means our
    # event map is incomplete, not that the rule belongs elsewhere, and
    # Sysmon's newer events (FileBlockExecutable, FileBlockShredding) are
    # exactly that case. Those go on to the config check and are reported as
    # not collected, which is the truthful answer.
    # Skipping the event-space check requires the rule to be unambiguously this
    # sensor's, not merely to mention it. pySigma resolves some rules onto
    # several channels at once: "Eventlog Cleared" comes back as System,
    # Security, three PowerShell channels AND Sysmon/Operational. Treating that
    # as "on the sensor's channel" waves a System-channel rule past the event
    # check and into the Sysmon config, where EventID 104 is then reported as
    # an event this config fails to collect. It is not a Sysmon event at all.
    on_sensor_channel = (
        sensor_scope_channels is not None
        and bool(channels)
        and channels <= sensor_scope_channels
    )
    if sensor_event_id_space is not None and event_ids and not on_sensor_channel:
        foreign = [e for e in event_ids if e not in sensor_event_id_space]
        if foreign and len(foreign) == len(event_ids):
            result.verdict = Verdict.OUT_OF_SCOPE
            result.scope_reason = ScopeReason.FOREIGN_EVENT_ID
            result.detail = (
                f"EventID {', '.join(map(str, foreign))} is outside this sensor's "
                "event space, so this rule is served by another log source"
            )
            return result

    # Event-level check: does the sensor emit the event at all?
    if profile is not None and event_ids:
        missing = []
        filtered = []
        unmapped = []
        unfilterable = profile.unfilterable or ALWAYS_ON_EVENT_IDS
        always_on = [e for e in event_ids if e in unfilterable]
        for event_id in event_ids:
            if event_id in unfilterable:
                # Service status events cannot be filtered by config.
                continue
            status = profile.status_for_event_id(event_id)
            if status is None:
                # We have no element for this event ID. That is a gap in our
                # own map of the sensor, not a statement the config made, and
                # collapsing the two is how "we do not know" becomes "your
                # sensor is misconfigured, go turn it on". EventID 104 is the
                # case that exposes it: it belongs to the Eventlog service, no
                # Sysmon configuration can produce it, and telling someone to
                # enable it in Sysmon is advice they cannot act on.
                unmapped.append(event_id)
            elif status.collection is Collection.DISABLED:
                missing.append(event_id)
            elif status.collection is Collection.FILTERED:
                filtered.append(event_id)

        result.filtered_event_ids = filtered
        result.unmapped_event_ids = unmapped

        # An event the config cannot filter is available by definition, and
        # Sigma reads several event ids as alternatives, so one of those is
        # enough to keep the rule alive at the event level whatever happens to
        # the rest. A rule on EventID 4 and 23 was coming out DEAD-ON-ARRIVAL
        # because 4 was dropped from the alternatives before they were counted.
        # The statuses gathered above are still reported as context.
        filterable_ids = [] if always_on else [e for e in event_ids if e not in unfilterable]

        # Every event the rule could use is one we cannot attribute. Say that,
        # rather than attributing it to this sensor's configuration.
        if unmapped and filterable_ids and len(unmapped) == len(filterable_ids):
            result.verdict = Verdict.OUT_OF_SCOPE
            result.scope_reason = ScopeReason.UNMAPPED_EVENT
            result.cause = DeadCause.EVENT_UNMAPPED
            result.detail = (
                f"EventID {', '.join(map(str, unmapped))} does not map to any element "
                f"of {profile.name}, so this rule cannot be attributed to this sensor. "
                "It is most likely served by another provider on this channel"
            )
            return result

        # Sigma treats multiple event ids in one rule as alternatives, so the
        # rule only dies when every event it could use is missing.
        if missing and filterable_ids and len(missing) + len(unmapped) == len(filterable_ids):
            result.verdict = Verdict.DEAD_ON_ARRIVAL
            result.cause = DeadCause.EVENT_NOT_COLLECTED
            result.missing_event_ids = missing
            # Carried as data so the report never has to recover it by
            # splitting this sentence back apart.
            result.missing_event_elements = sorted(
                {profile.status_for_event_id(e).element for e in missing}
            )
            result.detail = (
                f"{profile.name} does not collect "
                f"{', '.join(result.missing_event_elements)} "
                f"(EventID {', '.join(map(str, missing))})"
            )
            if unmapped:
                result.detail += (
                    f"; EventID {', '.join(map(str, unmapped))} could not be "
                    "mapped to an element and was not judged"
                )
            return result

    # Nothing left to check. A keyword-only rule, a rule whose fields the
    # pipeline stripped and a rule whose condition we could not reduce all
    # arrive here with a tree that holds no field, and satisfiable() says yes
    # to that tree against any schema at all, including an empty one. The
    # event checks above are a real measurement and keep their verdict; past
    # them there is no evidence left, so the answer is that we did not assess
    # this rule.
    if not rule.is_usable and not event_ids:
        result.verdict = Verdict.NOT_ASSESSED
        result.scope_reason = ScopeReason.NOTHING_CHECKED
        result.detail = (
            "the condition names no field and the rule names no event id, so "
            "there was nothing to check it against"
            if rule.condition_tree is not None
            else "the condition could not be reduced, so there was nothing to check"
        )
        return result

    # Field-level check: can the condition still match against this schema?
    #
    # This asks the condition, not a flat list of names. Sigma's commonest
    # idioms are disjunctive ("selection_a or selection_b", "1 of selection_*"),
    # and a field read by only one branch is not a requirement: losing it closes
    # one route while the others stay open. The rule dies only when EVERY
    # branch is broken, which is the same rule already applied to alternative
    # event IDs a few lines above.
    if schema_fields is not None and rule.condition_tree is not None:
        if satisfiable(rule.condition_tree, schema_fields, ignore):
            absent = []
        else:
            absent = sorted(blocking_fields(rule.condition_tree, schema_fields, ignore))
        if absent:
            # An absent field whose value the ingest pipeline moved elsewhere is
            # a different failure from telemetry that was never collected. The
            # rule still cannot fire, but the fix is the conversion, not the
            # sensor. Only the pipeline's own statements are used here.
            moved: list[tuple[str, str]] = []
            truly_absent: list[str] = []
            parents: set[str] | None = None
            for field in absent:
                destination = None
                evidence = None
                if ingest_map is not None:
                    destination, kind = ingest_map.resolve(field, schema_fields, event_ids)
                    evidence = Evidence[kind] if kind else None
                if destination:
                    moved.append((field, destination))
                    if evidence is not None:
                        result.evidence[field] = evidence
                    result.destination_fields[field] = _destination_fields(destination)
                    if evidence is Evidence.NAMESPACE and ingest_map is not None:
                        if parents is None:
                            # One pass over the schema, not one per absent
                            # field per rule. With 2,400 rules the inner scan
                            # was the run's hot spot.
                            parents = _parent_names(schema_fields)
                        candidates = [
                            name for name in ingest_map.namespace_targets.get(field, [])
                            if name in schema_fields or name in parents
                        ]
                        if candidates:
                            result.destination_candidates[field] = sorted(candidates)
                else:
                    # The pipeline deletes this field and says nothing about
                    # where the value went, or never mentions it at all. Either
                    # way there is nowhere to point the rule, so this is absent
                    # telemetry and the owner is collection, not conversion.
                    truly_absent.append(field)
                    if ingest_map is not None and field in ingest_map.dropped:
                        result.dropped_fields.append(field)

            if truly_absent:
                result.verdict = Verdict.DEAD_ON_ARRIVAL
                result.cause = DeadCause.FIELD_ABSENT
                result.missing_fields = truly_absent
                result.mismapped_fields = moved
                result.detail = f"fields not present in schema: {', '.join(truly_absent)}"
                return result

            result.verdict = Verdict.MISMAPPED
            result.mismapped_fields = moved
            if ingest_map is not None:
                for source, _destination in moved:
                    # Sorted, because iterating a set and breaking on the first
                    # hit makes the literal we cite change between runs on
                    # identical inputs. A tool whose selling point is that its
                    # output is a fact cannot print a different fact each time.
                    for literal in sorted(rule.field_literals.get(source, set())):
                        pattern = ingest_map.rewrites_value(source, literal)
                        if pattern:
                            result.rewritten_values.append((source, literal))
                            break
            # Telling someone to repoint a rule at a field that carries no data
            # trades a mismapped rule for a starved one. Check before advising.
            if populated_fields is not None:
                for source, destination in moved:
                    candidates = result.destination_fields.get(source, [])
                    if not candidates:
                        # A namespace, so we know the script writes in there but
                        # not which field inside it carries this value. Asking
                        # whether "the namespace" is populated answers a
                        # different question: registry.path is busy while
                        # registry.data.strings is empty, and reporting the
                        # namespace as alive on that basis would be the same
                        # confident guess this check exists to avoid.
                        continue
                    if not any(d in populated_fields for d in candidates):
                        result.unpopulated_destinations.append((source, destination))

            parts = [f"{source} is stored as {destination}" for source, destination in moved]
            result.detail = (
                "the telemetry is collected, under a different name: "
                + ", ".join(parts)
            )
            if result.unpopulated_destinations:
                names = ", ".join(d for _s, d in result.unpopulated_destinations)
                result.detail += (
                    f". {names} carried no data in the window either, so "
                    "repointing the rule is necessary but not sufficient"
                )
            if result.rewritten_values:
                examples = ", ".join(f"{lit}" for _f, lit in result.rewritten_values[:2])
                result.detail += (
                    ". The pipeline also parses this value, so renaming the "
                    f"field is not enough; literals like {examples} no longer "
                    "appear in that form"
                )
            return result

    # Exceptions that can no longer apply. This is not a coverage failure and
    # never changes the verdict: the rule fires, and fires too much.
    filter_only = {f for f in rule.filter_only_fields if f not in ignore}
    if schema_fields is not None and filter_only:
        for field in sorted(filter_only):
            if field in schema_fields:
                continue
            # Run the same ingest resolution the field check uses. Without it
            # the report says both "CommandLine is stored as process.command_line"
            # and "CommandLine is absent" a few rows apart, and sends the second
            # one to the collection team, who have nothing to fix.
            destination = None
            if ingest_map is not None:
                destination, _kind = ingest_map.resolve(field, schema_fields, event_ids)
            if destination:
                result.degraded_mismaps.append((field, destination))
            else:
                result.degraded_filters.append(field)

    # Population check: the fields exist but nothing is arriving. Asked of the
    # condition for the same reason as the field check above, so a rule with a
    # populated alternative is not reported as starved.
    #
    # A field the population query never asked about is absent from
    # `populated_fields` for that reason alone, and the two cases are not the
    # same claim. Narrowing the query to the required intersection left every
    # field of a `1 of selection_*` rule unqueried, and the rule was then
    # reported as carrying no data on fields the cluster was never asked about.
    # So the unqueried fields are granted for the satisfiability test, and a
    # rule whose answer changes because of that grant is one we cannot judge.
    if populated_fields is not None and rule.condition_tree is not None:
        unchecked: set[str] = set()
        if checked_fields is not None:
            unchecked = tree_fields(rule.condition_tree) - checked_fields - ignore
        if satisfiable(rule.condition_tree, populated_fields, ignore):
            starved = []
        elif satisfiable(rule.condition_tree, populated_fields | unchecked, ignore):
            blocking = blocking_fields(rule.condition_tree, populated_fields, ignore)
            decisive = sorted(blocking & unchecked)
            result.verdict = Verdict.NOT_ASSESSED
            result.scope_reason = ScopeReason.UNCHECKED_FIELD
            result.unchecked_fields = decisive
            result.detail = (
                "the population snapshot did not ask the cluster about "
                f"{', '.join(decisive)}, and this rule's population verdict "
                "turns on them, so it carries no verdict rather than a "
                "starvation one"
            )
            result.degraded_filters = []
            result.degraded_mismaps = []
            return result
        else:
            starved = sorted(
                blocking_fields(rule.condition_tree, populated_fields | unchecked, ignore)
            )
        if starved:
            result.verdict = Verdict.STARVED
            result.starved_fields = starved
            result.detail = f"in schema but no data in window: {', '.join(starved)}"
            # A rule receiving no data cannot also be firing too often. Keeping
            # both would put this rule in two findings at once and draw it with
            # a data link that holds, which is not true of a starved rule.
            result.degraded_filters = []
            result.degraded_mismaps = []
            return result

    if result.degraded_filters or result.degraded_mismaps:
        parts = []
        if result.degraded_filters:
            parts.append(f"{', '.join(result.degraded_filters)} absent from the schema")
        for field, destination in result.degraded_mismaps:
            parts.append(f"{field} is stored as {destination}, so the exception misses it")
        result.detail = "fires, but its exceptions cannot apply: " + "; ".join(parts)
    elif result.filtered_event_ids:
        result.detail = (
            "collected, but the config only includes a subset of this event "
            f"(EventID {', '.join(map(str, result.filtered_event_ids))})"
        )
    return result


def summarise(verdicts: list[RuleVerdict]) -> dict[str, int]:
    """Count the verdicts, and show the working behind the denominator.

    in_scope is the denominator of the headline percentage: total minus the
    rules that serve another log source, which genuinely are not this sensor's
    failure. Rules we could not assess stay in it. Taking them out would
    shrink the denominator and raise the headline on the strength of our own
    failures, and the report says in print that they are counted, so they are.
    """
    counts: dict[str, int] = {v.value: 0 for v in Verdict}
    for item in verdicts:
        counts[item.verdict.value] += 1
    counts["total"] = len(verdicts)
    counts["in_scope"] = counts["total"] - counts[Verdict.OUT_OF_SCOPE.value]
    counts["dead"] = counts[Verdict.DEAD_ON_ARRIVAL.value] + counts[Verdict.MISMAPPED.value]
    for reason in ScopeReason:
        counts[f"scope:{reason.name}"] = sum(
            1 for item in verdicts if item.scope_reason is reason
        )
    return counts
