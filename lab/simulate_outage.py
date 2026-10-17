"""Stop one event type from arriving, the way a config change would.

This does not fake a STARVED verdict. It causes one, through the same mechanism
a real outage uses: Elasticsearch keeps an index's mapping after the documents
are gone, so a field that was populated last month is still in the schema this
month while carrying nothing. That is precisely the gap between "we collect
this" and "this is arriving", and it is invisible from the schema alone.

The default scenario is ProcessAccess (Sysmon event ID 10) because it is the
one teams actually turn off. It is noisy, SwiftOnSecurity's reference config
disables it outright, and two fields come from it and nowhere else:
winlog.event_data.CallTrace and winlog.event_data.GrantedAccess. The rules that
read them are the LSASS and credential-access detections, so the cost of the
change lands on content nobody intended to give up.

Usage:
    python simulate_outage.py                 # drop event ID 10
    python simulate_outage.py --event-id 7    # drop ImageLoad instead
    python simulate_outage.py --restore       # reload the datasets
"""

from __future__ import annotations

import argparse

from elasticsearch import Elasticsearch

INDEX = "winlogbeat-detection-gate-lab"


def count_for_event(client: Elasticsearch, index: str, event_id: int) -> int:
    body = {"query": {"term": {"event.code": str(event_id)}}}
    return client.count(index=index, body=body)["count"]


def field_population(client: Elasticsearch, index: str, fields: list[str]) -> dict[str, int]:
    aggs = {f"f{i}": {"filter": {"exists": {"field": name}}} for i, name in enumerate(fields)}
    response = client.search(index=index, body={"size": 0, "aggs": aggs})
    buckets = response.get("aggregations", {})
    return {name: buckets.get(f"f{i}", {}).get("doc_count", 0) for i, name in enumerate(fields)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--index", default=INDEX)
    parser.add_argument("--event-id", type=int, default=10)
    parser.add_argument(
        "--watch",
        nargs="*",
        default=["winlog.event_data.CallTrace", "winlog.event_data.GrantedAccess"],
        help="Fields to report before and after, to show the schema stays put",
    )
    parser.add_argument("--restore", action="store_true", help="Reload the datasets instead")
    args = parser.parse_args()

    client = Elasticsearch(args.url, request_timeout=180)

    if args.restore:
        print("Reload the telemetry with:  python load_lab.py --recreate")
        return

    total = client.count(index=args.index)["count"]
    affected = count_for_event(client, args.index, args.event_id)
    before = field_population(client, args.index, args.watch)

    print(f"index holds {total} documents, {affected} of them event {args.event_id}")
    print("\nbefore:")
    for name, count in before.items():
        print(f"  {name:42} {count:>7} documents")

    if affected == 0:
        print(f"\nnothing to remove for event {args.event_id}")
        return

    client.delete_by_query(
        index=args.index,
        body={"query": {"term": {"event.code": str(args.event_id)}}},
        refresh=True,
        conflicts="proceed",
    )
    client.indices.refresh(index=args.index)

    after = field_population(client, args.index, args.watch)
    remaining = client.count(index=args.index)["count"]

    print(f"\nremoved {affected} documents, {remaining} remain")
    print("\nafter:")
    for name, count in after.items():
        print(f"  {name:42} {count:>7} documents")

    # The point of the exercise: the field is still in the schema.
    caps = client.field_caps(index=args.index, fields=args.watch)
    still_mapped = sorted(caps.get("fields", {}).keys())
    print("\nstill present in the schema after the outage:")
    for name in still_mapped:
        print(f"  {name}")
    if not still_mapped:
        print("  (none, which would make these DEAD rather than STARVED)")

    print(
        "\nThe schema did not change. Only the data stopped. Take a fresh "
        "snapshot and rerun the scan to see those rules move to STARVED."
    )


if __name__ == "__main__":
    main()
