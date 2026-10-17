# detection-gate lab

A local Elasticsearch holding real Windows Sysmon telemetry, so detection-gate has a
schema to ask questions of.

## Why it is built this way

The lab has one job beyond running: it must not put our own field mapping in
the middle of the result. So the telemetry is reshaped only into the envelope
Winlogbeat produces, meaning `winlog.event_id` and `winlog.event_data.*`, which
is a mechanical move rather than an interpretation. Everything after that,
including every ECS field name detection-gate later reads, is produced by Elastic's
own published ingest pipeline for Windows Sysmon logs from `elastic/integrations`.

That is what makes the numbers defensible. When someone asks whether the dead
rules are an artifact of how we mapped fields, the answer is that we did not map
them. Elastic did.

## Bring it up

```bash
docker compose up -d
curl "localhost:9200/_cluster/health?pretty"
```

Wait for the container to report healthy. `yellow` status is expected on a
single node.

## Load the telemetry

```bash
pip install elasticsearch pyyaml requests
python load_lab.py
```

This installs Elastic's Sysmon pipeline, downloads four public datasets from
OTRF Security-Datasets, and indexes roughly 88,000 Sysmon events covering event
IDs 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 17, 18, 22, 23, 26 and 28.

The datasets were chosen for event ID coverage rather than for the attacks they
contain, since what matters here is how much of the schema they exercise.

Useful flags: `--recreate` to start the index clean, `--datasets <name>` to load
a subset, `--url` for a non-default Elasticsearch.

## Take a schema snapshot

```bash
detection-gate snapshot \
  --index-pattern 'winlogbeat-detection-gate-lab' \
  --rules-dir <path to sigma>/rules \
  --out schema.json
```

The snapshot records which fields exist and which carry data, so later runs and
the stage demo work without a live cluster.

## Tear it down

```bash
docker compose down -v
```

The `-v` removes the data volume, leaving nothing running on the machine.

## Honest limits

This is a lab, not a production estate. Security is disabled and the port is
bound to localhost only, which is acceptable here and nowhere else.

The telemetry is a few captured attack scenarios, not months of an organisation's
normal activity. That matters for STARVED in particular: a field with no data in
this index may simply be a field these four scenarios never triggered, rather
than a broken pipeline. The tool reports the fact and the reason is for the
reader to judge, which is the same limit that applies in a real environment with
a short retention window.
