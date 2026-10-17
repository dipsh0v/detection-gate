"""What the SIEM reader does when the cluster answers oddly.

This is the boundary where every number in the report is produced, and the
cheap failures all point the same way: a cluster that answers with nothing
looks exactly like a cluster where nothing exists. One empty field_caps
response reported as a schema would put the whole corpus on the page as
DEAD-ON-ARRIVAL, and it would look like a finding rather than like an outage.

The client here is a stand-in, so none of this touches a network.
"""

import pytest

from detection_gate.schema import (
    ElasticSchemaSource,
    EmptyWindowError,
    SchemaReadError,
    SchemaSnapshot,
)

FIELD_CAPS = {
    "_shards": {"total": 3, "successful": 3, "failed": 0},
    "fields": {
        "@timestamp": {"date": {"type": "date", "searchable": True, "aggregatable": True}},
        "event.code": {"keyword": {"type": "keyword"}},
        "process.command_line": {"text": {"type": "text"}},
        "process.command_line.keyword": {"keyword": {"type": "keyword"}},
        "process.parent.command_line": {"text": {"type": "text"}},
        "winlog.channel": {"keyword": {"type": "keyword"}},
    },
}


class FakeClient:
    """Answers field_caps and search from canned payloads, recording the calls."""

    def __init__(self, field_caps=None, *, hits=5, populated=()):
        self.field_caps_payload = FIELD_CAPS if field_caps is None else field_caps
        self.hits = hits
        self.populated = set(populated)
        self.field_caps_calls = []
        self.searches = []

    def field_caps(self, **kwargs):
        self.field_caps_calls.append(kwargs)
        return self.field_caps_payload

    def search(self, **kwargs):
        self.searches.append(kwargs)
        aggregations = {}
        for key, body in kwargs["aggs"].items():
            name = body["filter"]["exists"]["field"]
            aggregations[key] = {"doc_count": 7 if name in self.populated else 0}
        return {
            "_shards": {"total": 3, "successful": 3, "failed": 0},
            "hits": {"total": {"value": self.hits, "relation": "eq"}},
            "aggregations": aggregations,
        }


def test_field_caps_is_one_call_for_the_whole_index_pattern():
    client = FakeClient()
    source = ElasticSchemaSource(client, "logs-windows-*")

    fields = source.fetch_fields()

    assert "process.command_line" in fields
    assert "process.command_line.keyword" in fields
    assert len(client.field_caps_calls) == 1
    assert client.field_caps_calls[0] == {"index": "logs-windows-*", "fields": "*"}


def test_an_empty_field_caps_response_is_refused_rather_than_read_as_a_schema():
    """A mistyped pattern, a rolled-over index and a credential without
    privileges on the pattern all answer with no fields at all.

    Taken as the schema, every rule in the corpus comes back
    DEAD-ON-ARRIVAL on a cause the reader cannot distinguish from real
    absence, and the report reads as the worst environment anybody has
    scanned. The run has to stop instead.
    """
    client = FakeClient({"_shards": {"total": 3, "successful": 3, "failed": 0}, "fields": {}})
    source = ElasticSchemaSource(client, "logs-typo-*")

    with pytest.raises(SchemaReadError) as raised:
        source.fetch_fields()
    assert "logs-typo-*" in str(raised.value)
    assert client.searches == [], "no population query on a schema we could not read"


def test_a_shard_failure_is_an_unreadable_answer_not_a_partial_one():
    """Fields missing because a shard did not answer are not fields that
    do not exist.

    A partial response is still a 200, and the fields the failed shard would
    have reported are simply not in it. Reading it would report whichever
    rules happen to depend on those fields as dead, and the set would change
    between runs on an unchanged corpus.
    """
    client = FakeClient(
        {
            "_shards": {
                "total": 3, "successful": 2, "failed": 1,
                "failures": [{"index": "logs-windows-000003", "reason": {"type": "shard_failure"}}],
            },
            "fields": FIELD_CAPS["fields"],
        }
    )
    source = ElasticSchemaSource(client, "logs-windows-*")

    with pytest.raises(SchemaReadError) as raised:
        source.fetch_fields()
    assert "1 of 3 shards failed" in str(raised.value)


def test_population_is_batched_and_the_window_is_bounded_at_both_ends():
    client = FakeClient(populated={"event.code", "process.command_line"})
    source = ElasticSchemaSource(client, "logs-windows-*", batch_size=2)

    populated = source.fetch_populated(
        [
            "event.code", "process.command_line", "process.parent.command_line",
            "winlog.channel", "winlog.event_data.Hashes",
        ],
        window="now-7d",
    )

    assert populated == {"event.code", "process.command_line"}
    assert len(client.searches) == 3, "five fields, two per request"
    first = client.searches[0]
    assert first["size"] == 0, "the population check never retrieves documents"
    assert first["track_total_hits"] is True
    assert first["allow_partial_search_results"] is False
    assert first["query"]["range"]["@timestamp"] == {"gte": "now-7d", "lte": "now"}


def test_a_window_holding_no_documents_measures_no_population_at_all():
    """Every exists count is zero, and the reason is that there is nothing there.

    A wrong time field, a window older than retention and an ingest outage all
    produce this, and reading it as a measurement puts the whole corpus on the
    page as STARVED, each row claiming a field "carried no data in the window".
    That sentence is true and useless: no field could have.
    """
    client = FakeClient(hits=0)
    source = ElasticSchemaSource(client, "logs-windows-*")

    with pytest.raises(EmptyWindowError) as raised:
        source.fetch_populated(["event.code", "process.command_line"], window="now-1d")
    assert "no documents" in str(raised.value)


def test_a_snapshot_over_an_empty_window_records_that_it_measured_nothing():
    """populated is None, which is not the same object as an empty set.

    An empty set says every field was checked and none carried data. None says
    the question was not answered, and the engine's population check is then
    skipped rather than applied to a measurement nobody took.
    """
    client = FakeClient(hits=0)
    source = ElasticSchemaSource(client, "logs-windows-*")

    snap = source.snapshot(fields_of_interest={"process.command_line"}, window="now-1d")

    assert snap.populated is None
    assert snap.checked_fields == {"process.command_line"}
    assert any("population not measured" in note for note in snap.notes)


def test_a_snapshot_records_which_fields_the_population_query_asked_about():
    """checked_fields is what separates "empty" from "never asked"."""
    client = FakeClient(populated={"process.command_line"})
    source = ElasticSchemaSource(client, "logs-windows-*")

    snap = source.snapshot(
        fields_of_interest={"process.command_line", "process.parent.command_line", "not.a.field"},
        window="now-30d",
    )

    assert snap.populated == {"process.command_line"}
    assert snap.checked_fields == {"process.command_line", "process.parent.command_line"}
    assert "not.a.field" not in (snap.checked_fields or ())
    assert snap.window == "now-30d"


def test_a_snapshot_round_trips_through_disk_with_its_checked_set(tmp_path):
    client = FakeClient(populated={"process.command_line"})
    source = ElasticSchemaSource(client, "logs-windows-*")
    path = tmp_path / "snapshot.json"

    source.snapshot(fields_of_interest={"process.command_line", "winlog.channel"}).save(path)
    loaded = SchemaSnapshot.load(path)

    assert loaded.checked_fields == {"process.command_line", "winlog.channel"}
    assert loaded.populated == {"process.command_line"}
    assert loaded.fields == set(FIELD_CAPS["fields"])


def test_an_older_snapshot_file_loads_with_no_checked_set(tmp_path):
    """A snapshot written before checked_fields existed still has to load.

    Defaulting the missing key to the empty set would say the run asked the
    cluster about nothing, and every rule in a recorded environment would come
    back NOT-ASSESSED on replay.
    """
    path = tmp_path / "old.json"
    path.write_text(
        '{"source": "elasticsearch", "index_pattern": "logs-*", '
        '"fields": ["process.command_line"], "populated": ["process.command_line"], '
        '"window": "now-90d", "notes": []}',
        encoding="utf-8",
    )

    loaded = SchemaSnapshot.load(path)

    assert loaded.checked_fields is None
    assert loaded.populated == {"process.command_line"}
