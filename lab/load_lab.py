"""Load real Windows telemetry into the lab Elasticsearch, the way Elastic would.

The point of this script is what it does NOT do: it does not invent a field
mapping. Public Sysmon telemetry is reshaped into the envelope Winlogbeat
produces (winlog.event_id plus winlog.event_data.*), and the conversion to ECS
is then performed by Elastic's own published ingest pipeline for Windows Sysmon
logs, shipped in elastic/integrations.

That matters for the result. The schema detection-gate then reads back through
field_caps is the schema a real Elastic deployment would have, produced by
Elastic's code rather than by ours. Nobody has to trust our mapping, because
we do not have one.

Usage:
    pip install elasticsearch pyyaml requests
    python load_lab.py
    python load_lab.py --datasets covenant_dcom_iertutil_dll_hijack
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
import zipfile
from pathlib import Path

import requests
import yaml
from elasticsearch import Elasticsearch, helpers

PIPELINE_NAME = "detection-gate-sysmon"
INDEX_NAME = "winlogbeat-detection-gate-lab"
PIPELINE_FILE = Path(__file__).parent / "pipeline" / "sysmon_operational.yml"

RAW_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

# Chosen for event ID coverage rather than for the attack they contain: between
# them these carry Sysmon 1, 3, 5, 7, 9, 10, 11, 12, 13, 18, 22, 23 and 28, so
# the resulting schema exercises most of what the rule corpus reads.
DATASETS = {
    "covenant_dcom_iertutil_dll_hijack": f"{RAW_BASE}/lateral_movement/host/covenant_dcom_iertutil_dll_hijack.zip",
    "psh_stop_event_logging_controlset_minint_key": f"{RAW_BASE}/defense_evasion/host/psh_stop_event_logging_controlset_minint_key.zip",
    "empire_ninjacopy_dumping_ntds_dit_file": f"{RAW_BASE}/credential_access/host/empire_ninjacopy_dumping_ntds_dit_file.zip",
    "empire_schtasks_creation_execution_elevated_user": f"{RAW_BASE}/persistence/host/empire_schtasks_creation_execution_elevated_user.zip",
}

# Fields Winlogbeat places outside event_data. Everything else in a record is
# EventData and goes under winlog.event_data, which is exactly what Winlogbeat
# does when it reads the EVTX.
ENVELOPE_FIELDS = {
    "EventID": ("winlog", "event_id"),
    "Channel": ("winlog", "channel"),
    "Hostname": ("winlog", "computer_name"),
    "SourceName": ("winlog", "provider_name"),
    "ProviderGuid": ("winlog", "provider_guid"),
    "RecordNumber": ("winlog", "record_id"),
    "ProcessID": ("winlog", "process", "pid"),
    "ThreadID": ("winlog", "process", "thread", "id"),
    "UserID": ("winlog", "user", "identifier"),
    "Task": ("winlog", "task"),
    "Opcode": ("winlog", "opcode"),
    "Level": ("winlog", "level"),
    "Keywords": ("winlog", "keywords"),
    "Version": ("winlog", "version"),
    "TimeCreated": ("winlog", "time_created"),
}

# Present in the published datasets as collection artifacts, not Windows data.
DROP_FIELDS = {
    "EventTime",
    "EventReceivedTime",
    "SourceModuleName",
    "SourceModuleType",
    "SeverityValue",
    "Severity",
    "EventType",
    "ExecutionProcessID",
    "Message",
    "host",
    "@version",
    "type",
    "tags",
    "port",
}


def _place(doc: dict, path: tuple[str, ...], value) -> None:
    node = doc
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def to_winlogbeat_envelope(record: dict) -> dict | None:
    """Reshape a flat Security-Datasets record into Winlogbeat's shape."""
    channel = str(record.get("Channel", ""))
    if "Sysmon" not in channel:
        return None

    doc: dict = {}
    event_data: dict = {}

    timestamp = record.get("@timestamp") or record.get("TimeCreated")
    if timestamp:
        doc["@timestamp"] = timestamp

    for key, value in record.items():
        if key in DROP_FIELDS or key == "@timestamp":
            continue
        if key in ENVELOPE_FIELDS:
            _place(doc, ENVELOPE_FIELDS[key], value)
        else:
            event_data[key] = value

    if event_data:
        doc.setdefault("winlog", {})["event_data"] = event_data

    # The pipeline reads winlog.event_id as a number in some branches and as a
    # string in others; Winlogbeat sends it as a long.
    event_id = doc.get("winlog", {}).get("event_id")
    if event_id is not None:
        try:
            doc["winlog"]["event_id"] = int(event_id)
        except (TypeError, ValueError):
            pass

    return doc


def install_pipeline(client: Elasticsearch) -> None:
    if not PIPELINE_FILE.exists():
        sys.exit(f"pipeline file missing: {PIPELINE_FILE}")
    body = yaml.safe_load(PIPELINE_FILE.read_text(encoding="utf-8"))
    client.ingest.put_pipeline(id=PIPELINE_NAME, body=body)
    count = len(body.get("processors", []))
    print(f"installed Elastic's Sysmon pipeline as '{PIPELINE_NAME}' ({count} processors)")


def fetch_records(url: str) -> list[dict]:
    print(f"  downloading {url.rsplit('/', 1)[-1]}")
    response = requests.get(url, timeout=180)
    response.raise_for_status()
    payload = response.content

    records: list[dict] = []
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = [n for n in archive.namelist() if n.endswith(".json")]
            if not names:
                return records
            raw = archive.read(names[0])
    elif payload[:2] == b"\x1f\x8b":
        raw = gzip.decompress(payload)
    else:
        raw = payload

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--index", default=INDEX_NAME)
    parser.add_argument("--datasets", nargs="*", default=list(DATASETS))
    parser.add_argument("--recreate", action="store_true", help="delete the index first")
    args = parser.parse_args()

    client = Elasticsearch(args.url, request_timeout=120)
    info = client.info()
    print(f"connected to Elasticsearch {info['version']['number']}")

    install_pipeline(client)

    if args.recreate and client.indices.exists(index=args.index):
        client.indices.delete(index=args.index)
        print(f"deleted existing index {args.index}")

    if not client.indices.exists(index=args.index):
        # The one type this lab states, and it states it because leaving it to
        # Elastic breaks the load. Keywords arrives as a number in some of the
        # published captures and as a hex string ("0x8000000000000000") in
        # others; dynamic mapping takes the first document's shape and then
        # rejects every record of the other shape. Winlogbeat's own template
        # maps this field as a keyword, so this is Winlogbeat's answer rather
        # than ours. Everything else is still mapped by Elastic.
        client.indices.create(
            index=args.index,
            mappings={"properties": {"winlog": {"properties": {"keywords": {"type": "keyword"}}}}},
        )
        print(f"created index {args.index}")

    total_indexed = 0
    total_skipped = 0
    total_rejected = 0
    for name in args.datasets:
        url = DATASETS.get(name)
        if not url:
            print(f"  unknown dataset '{name}', skipping")
            continue
        records = fetch_records(url)
        kept = 0

        def actions():
            nonlocal kept, total_skipped
            for record in records:
                doc = to_winlogbeat_envelope(record)
                if doc is None:
                    total_skipped += 1
                    continue
                kept += 1
                yield {"_index": args.index, "_source": doc, "pipeline": PIPELINE_NAME}

        success, errors = helpers.bulk(
            client, actions(), chunk_size=1000, raise_on_error=False, stats_only=False
        )
        if kept == 0:
            print("  no Sysmon records in this dataset")
            continue

        total_indexed += success
        failed = len(errors) if isinstance(errors, list) else 0
        total_rejected += failed
        print(f"  indexed {success} events, {failed} rejected, {len(records) - kept} non-Sysmon")
        if failed:
            first = errors[0]
            reason = json.dumps(first)[:300]
            print(f"  first rejection: {reason}")

    client.indices.refresh(index=args.index)
    count = client.count(index=args.index)["count"]
    print(f"\nindexed {total_indexed} events, skipped {total_skipped} non-Sysmon")
    print(f"{args.index} now holds {count} documents")

    if total_rejected:
        # A rejected record is a hole in the schema this index is supposed to
        # represent, and a hole in the schema is a field detection-gate will
        # report as absent. Loading most of the telemetry and carrying on is
        # how the lab produces a confident wrong number, so it stops here.
        print(f"\n{total_rejected} records were rejected by Elasticsearch.")
        print("The index is incomplete, so any measurement taken against it")
        print("would report fields as absent that the telemetry actually carries.")
        print("Fix the mapping shown in the rejection above, then reload with --recreate.")
        return 1

    print("\nnext:")
    print(f"  detection-gate snapshot --index-pattern '{args.index}' --rules-dir <sigma>/rules --out schema.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
