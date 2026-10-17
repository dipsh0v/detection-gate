"""Work out which Sysmon events a given config actually produces.

Everything here is read off the config file itself. The event-ID-to-element
mapping is not hand written either: it is parsed out of the section headers
SwiftOnSecurity documents in the reference config, so the mapping has a
citable public source rather than being asserted.

The filtering semantics detection-gate applies come from the config authors, not
from us. SwiftOnSecurity states it inline:

    <!--NOTE: Using "include" with no rules means nothing in this section
             will be logged-->

There is deliberately no model of "Sysmon installed with no config file". A
caller who wants that case supplies a config file representing it, so every
number detection-gate reports traces back to a file on disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from enum import Enum
from pathlib import Path

from defusedxml.ElementTree import parse as parse_xml

# Sysmon emits some events whatever the config says, so a config that never
# mentions them has not disabled them. Which ones is not asserted here: it is
# read out of the reference config, which documents each of them with the line
# "Cannot be filtered." The set below is only the fallback for a config that
# carries no such documentation.
ALWAYS_ON_EVENT_IDS = {4, 16, 255}

# The reference config documents each event under a header of its own, and
# "Cannot be filtered." sits in the prose below the header it belongs to. So
# the file is cut at the headers first and each section searched on its own.
# One DOTALL pattern spanning the whole file does the same job, but on a config
# that never says "Cannot be filtered." it backtracks across the remainder of
# the file from every header it finds.
_SECTION_START = re.compile(r"SYSMON EVENT ID ([0-9]+)")

_HEADER = re.compile(
    r"SYSMON EVENT ID ([0-9]+(?:\s*[,&/]\s*[0-9]+)*)\s*:\s*([^\[\]\n]+?)\s*\[([A-Za-z]+)\]"
)


class Collection(str, Enum):
    """How completely a config collects one event type."""

    FULL = "full"            # onmatch=exclude, so everything except listed
    FILTERED = "filtered"    # onmatch=include with rules, subset only
    DISABLED = "disabled"    # include with no rules, or absent from config


@dataclass
class EventStatus:
    element: str
    event_ids: tuple[int, ...]
    collection: Collection
    include_rules: int = 0
    exclude_rules: int = 0

    @property
    def produces_events(self) -> bool:
        return self.collection is not Collection.DISABLED


@dataclass
class SysmonProfile:
    """One Sysmon configuration, reduced to what it emits."""

    name: str
    path: Path
    schema_version: str | None = None
    events: dict[str, EventStatus] = dc_field(default_factory=dict)
    # Read from the reference config rather than assumed; falls back to the
    # module constant when the config documents nothing.
    unfilterable: set[int] = dc_field(default_factory=lambda: set(ALWAYS_ON_EVENT_IDS))

    def event_ids_collected(self) -> set[int]:
        ids = set(self.unfilterable)
        for status in self.events.values():
            if status.produces_events:
                ids.update(status.event_ids)
        return ids

    def status_for_event_id(self, event_id: int) -> EventStatus | None:
        for status in self.events.values():
            if event_id in status.event_ids:
                return status
        return None


def _documented_sections(text: str):
    starts = list(_SECTION_START.finditer(text))
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        yield int(match.group(1)), text[match.end() : end]


def parse_unfilterable_event_ids(reference_config: Path) -> set[int]:
    """Event IDs the reference config documents as impossible to filter."""
    text = reference_config.read_text(encoding="utf-8", errors="replace")
    return {
        event_id
        for event_id, section in _documented_sections(text)
        if "Cannot be filtered." in section
    }


def parse_event_id_map(reference_config: Path) -> dict[str, tuple[int, ...]]:
    """Derive element name to event ID mapping from documented section headers."""
    text = reference_config.read_text(encoding="utf-8", errors="replace")
    mapping: dict[str, tuple[int, ...]] = {}
    for match in _HEADER.finditer(text):
        raw_ids, _desc, element = match.groups()
        ids = tuple(int(n) for n in re.findall(r"[0-9]+", raw_ids))
        mapping.setdefault(element, ids)
    return mapping


def parse_event_id_map_from_dirs(modular_root: Path) -> dict[str, tuple[int, ...]]:
    """Derive additional mappings from sysmon-modular's directory names.

    Directories are named like 29_file_executable_detected, which gives the
    event ID for elements that are newer than the reference config and so are
    not documented in its section headers. Without this, a newer event type
    would look uncollectable in every profile, which would be a false
    dead-on-arrival.
    """
    mapping: dict[str, tuple[int, ...]] = {}
    if not modular_root.exists():
        return mapping
    for entry in modular_root.iterdir():
        if not entry.is_dir():
            continue
        match = re.match(r"^((?:\d+_)+)([a-z0-9_]+)$", entry.name)
        if not match:
            continue
        ids = tuple(int(n) for n in match.group(1).rstrip("_").split("_"))
        element = "".join(part.capitalize() for part in match.group(2).split("_"))
        mapping[element] = ids
    return mapping


def merge_event_id_maps(*maps: dict[str, tuple[int, ...]]) -> dict[str, tuple[int, ...]]:
    """Combine mappings, earliest source winning, matching case-insensitively."""
    merged: dict[str, tuple[int, ...]] = {}
    lowered: dict[str, str] = {}
    for mapping in maps:
        for element, ids in mapping.items():
            key = element.lower()
            if key in lowered:
                continue
            lowered[key] = element
            merged[element] = ids
    return merged


def resolve_element_ids(
    element: str, event_id_map: dict[str, tuple[int, ...]]
) -> tuple[int, ...]:
    """Look up an element's event IDs, tolerating capitalisation differences."""
    if element in event_id_map:
        return event_id_map[element]
    target = element.lower()
    for known, ids in event_id_map.items():
        if known.lower() == target:
            return ids
    return ()


def sysmon_event_id_space(event_id_map: dict[str, tuple[int, ...]]) -> set[int]:
    """Every event ID Sysmon itself can emit, per the parsed sources."""
    ids = set(ALWAYS_ON_EVENT_IDS)
    for value in event_id_map.values():
        ids.update(value)
    return ids


def _iter_filter_elements(node):
    """Yield event filter elements, descending through RuleGroup wrappers."""
    for child in node:
        if child.tag == "RuleGroup":
            yield from _iter_filter_elements(child)
        else:
            yield child


def load_profile(
    name: str,
    path: Path,
    event_id_map: dict[str, tuple[int, ...]],
    unfilterable: set[int] | None = None,
) -> SysmonProfile:
    # Vendor configs are third-party files. forbid_dtd rejects a document type
    # declaration outright, which is the only route to entity expansion in a
    # file that has no legitimate reason to carry one.
    root = parse_xml(path, forbid_dtd=True).getroot()
    profile = SysmonProfile(
        name=name,
        path=path,
        schema_version=root.get("schemaversion"),
        unfilterable=set(unfilterable) if unfilterable else set(ALWAYS_ON_EVENT_IDS),
    )

    filtering = root.find("EventFiltering")
    if filtering is None:
        return profile

    for element in _iter_filter_elements(filtering):
        tag = element.tag
        onmatch = (element.get("onmatch") or "include").lower()
        rule_count = len(list(element))

        existing = profile.events.get(tag)
        include_rules = existing.include_rules if existing else 0
        exclude_rules = existing.exclude_rules if existing else 0
        if onmatch == "include":
            include_rules += rule_count
        else:
            exclude_rules += rule_count

        # An exclude block means the event is collected and some cases are
        # dropped. An include block only collects what it lists, so an empty
        # include collects nothing at all.
        if exclude_rules > 0 or onmatch == "exclude":
            collection = Collection.FULL if include_rules == 0 else Collection.FILTERED
        elif include_rules > 0:
            collection = Collection.FILTERED
        else:
            collection = Collection.DISABLED

        profile.events[tag] = EventStatus(
            element=tag,
            event_ids=resolve_element_ids(tag, event_id_map),
            collection=collection,
            include_rules=include_rules,
            exclude_rules=exclude_rules,
        )

    return profile
