"""Ask the SIEM what it knows, as cheaply as possible.

Two questions only, and neither one runs a detection search:

  1. Which fields exist?   Elastic field_caps, one call for a whole index
     pattern, whatever the rule count.
  2. Which fields carry data in the window?   A size:0 exists count per
     unique field, batched into a single aggregation request.

The cost is driven by the number of distinct fields the corpus reads, not by
the number of rules: the population check costs one request per batch of
fields, so adding rules that read fields already covered costs nothing. The
run logs the field count it actually saw.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 50

_RETRY_STATUS = (429, 502, 503, 504)


class SchemaReadError(RuntimeError):
    pass


class EmptyWindowError(SchemaReadError):
    pass


@dataclass
class SchemaSnapshot:
    """What the SIEM reported, captured so a run can be replayed offline.

    checked_fields is the set the population query asked about. A field that is
    not in it was not measured, and "not measured" is not "carries no data".
    None means an older snapshot that did not record the distinction.
    """

    source: str
    index_pattern: str
    fields: set[str] = dc_field(default_factory=set)
    populated: set[str] | None = None
    window: str | None = None
    taken_at: float = dc_field(default_factory=time.time)
    notes: list[str] = dc_field(default_factory=list)
    checked_fields: set[str] | None = None

    def to_json(self) -> dict[str, Any]:
        content = self.content_json()
        content["taken_at"] = round(self.taken_at)
        return content

    def content_json(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "index_pattern": self.index_pattern,
            "fields": sorted(self.fields),
            "populated": sorted(self.populated) if self.populated is not None else None,
            "checked_fields": (
                sorted(self.checked_fields) if self.checked_fields is not None else None
            ),
            "window": self.window,
            "notes": self.notes,
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "SchemaSnapshot":
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            source=raw["source"],
            index_pattern=raw["index_pattern"],
            fields=set(raw.get("fields") or []),
            populated=set(raw["populated"]) if raw.get("populated") is not None else None,
            window=raw.get("window"),
            taken_at=raw.get("taken_at", 0.0),
            notes=raw.get("notes") or [],
            checked_fields=(
                set(raw["checked_fields"]) if raw.get("checked_fields") is not None else None
            ),
        )


def _chunk(items: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _elastic_errors():
    try:
        from elasticsearch import exceptions
    except ImportError:
        return ()
    return (exceptions.ApiError, exceptions.TransportError)


def _status_of(error: Exception) -> int | None:
    for attribute in ("status_code", "status", "meta"):
        value = getattr(error, attribute, None)
        if isinstance(value, int):
            return value
        status = getattr(value, "status", None)
        if isinstance(status, int):
            return status
    return None


def _is_transient(error: Exception) -> bool:
    status = _status_of(error)
    if status is not None:
        return status in _RETRY_STATUS
    return type(error).__name__ in ("ConnectionError", "ConnectionTimeout", "TransportError")


def _check_shards(response: dict, context: str) -> int:
    shards = response.get("_shards") or {}
    failed = shards.get("failed") or 0
    if failed:
        failures = shards.get("failures") or []
        raise SchemaReadError(
            f"{context}: {failed} of {shards.get('total')} shards failed: {failures}"
        )
    if response.get("timed_out"):
        raise SchemaReadError(f"{context}: the cluster timed out before answering")
    return shards.get("successful") or 0


class ElasticSchemaSource:
    """Read-only schema and population reader for Elasticsearch or OpenSearch.

    Needs only read privileges on the index pattern. It never retrieves
    documents: every population query is size:0, so the cluster answers from
    the index rather than by scanning and returning data.
    """

    def __init__(
        self,
        client,
        index_pattern: str,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
        request_pause: float = 0.0,
    ):
        self.client = client
        self.index_pattern = index_pattern
        self.batch_size = batch_size
        self.request_pause = request_pause

    def fetch_fields(self) -> set[str]:
        """One call, every field in the index pattern."""
        response = self.client.field_caps(index=self.index_pattern, fields="*")
        if hasattr(response, "body"):
            response = response.body
        _check_shards(response, f"field_caps on {self.index_pattern}")
        fields = set((response.get("fields") or {}).keys())
        if not fields:
            raise SchemaReadError(
                f"field_caps returned no fields for {self.index_pattern}. "
                "A mistyped pattern, an index that has rolled over and a "
                "credential without privileges on the pattern all answer this "
                "way, and every rule would be reported dead on the strength of "
                "it. Check the pattern and the privilege before rerunning."
            )
        log.info("field_caps returned %d fields for %s", len(fields), self.index_pattern)
        return fields

    def fetch_populated(
        self,
        fields: Iterable[str],
        *,
        window: str = "now-90d",
        time_field: str = "@timestamp",
    ) -> set[str]:
        """Which of these fields actually carry data in the window.

        Fields are batched into one aggregation request each round, so the
        request count is len(fields) / batch_size, not len(rules).

        Raises EmptyWindowError when the window holds no documents at all. Every
        exists count is then zero, which reads as a dead corpus and is in fact a
        wrong time field, a window older than retention, or an outage.
        """
        wanted = sorted(set(fields))
        populated: set[str] = set()
        documents = 0

        for batch in _chunk(wanted, self.batch_size):
            aggs = {
                f"f{index}": {"filter": {"exists": {"field": name}}}
                for index, name in enumerate(batch)
            }
            response = self._search_with_backoff(
                size=0,
                track_total_hits=True,
                query={"range": {time_field: {"gte": window, "lte": "now"}}},
                aggs=aggs,
            )
            _check_shards(response, f"search on {self.index_pattern}")
            total = (response.get("hits") or {}).get("total") or {}
            documents = max(documents, total.get("value", 0) if isinstance(total, dict) else total)
            buckets = response.get("aggregations") or {}
            for index, name in enumerate(batch):
                if (buckets.get(f"f{index}") or {}).get("doc_count", 0) > 0:
                    populated.add(name)
            if self.request_pause:
                time.sleep(self.request_pause)

        if wanted and documents == 0:
            raise EmptyWindowError(
                f"{self.index_pattern} holds no documents between {window} and now "
                f"on {time_field}, so no field can be shown to be unpopulated."
            )

        log.info("%d of %d fields carry data in %s", len(populated), len(wanted), window)
        return populated

    def _search_with_backoff(self, *, attempts: int = 5, **body) -> dict:
        """Retry only what the cluster reports as transient, by status code.

        The elasticsearch package is an optional extra, so its exception
        classes may not be importable here; a client that is not the
        elasticsearch one still carries a status code. What never decides this
        is the text of the message, because an index named 503-archive is not a
        rate limit and a connection timeout does not say 429.
        """
        delay = 1.0
        last_error: Exception | None = None
        retryable = _elastic_errors()
        for attempt in range(attempts):
            try:
                response = self.client.search(
                    index=self.index_pattern,
                    allow_partial_search_results=False,
                    **body,
                )
                return response.body if hasattr(response, "body") else response
            except Exception as exc:
                known = isinstance(exc, retryable) if retryable else True
                if not (known and _is_transient(exc)):
                    raise
                last_error = exc
                if attempt == attempts - 1:
                    break
                time.sleep(delay)
                delay *= 2
        raise SchemaReadError(f"search kept failing after backoff: {last_error}")

    def snapshot(
        self,
        *,
        fields_of_interest: Iterable[str] | None = None,
        window: str = "now-90d",
        time_field: str = "@timestamp",
    ) -> SchemaSnapshot:
        schema_fields = self.fetch_fields()
        target = (
            sorted(set(fields_of_interest) & schema_fields)
            if fields_of_interest is not None
            else sorted(schema_fields)
        )
        snap = SchemaSnapshot(
            source="elasticsearch",
            index_pattern=self.index_pattern,
            fields=schema_fields,
            window=window,
            checked_fields=set(target),
        )
        try:
            snap.populated = self.fetch_populated(
                target, window=window, time_field=time_field
            )
        except EmptyWindowError as exc:
            snap.populated = None
            snap.notes.append(f"population not measured: {exc}")
            log.warning("%s", exc)
        else:
            snap.notes.append(
                f"population checked for {len(target)} fields the rule corpus reads, "
                f"batched {self.batch_size} per request"
            )
        return snap
