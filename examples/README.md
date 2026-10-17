# Examples

`github/` holds two workflows for a detection-as-code repository: a pull
request gate, and the scheduled job that refreshes the schema snapshot the
gate reads. The comments in each file explain why they are two jobs rather
than one.

`rule-that-cannot-fire.yml` is a rule that converts cleanly, passes every
lint, and can never match against a Sysmon configuration that does not collect
RawAccessRead. Use it to see the gate go red:

```bash
detection-gate scan \
  --rules examples/rule-that-cannot-fire.yml \
  --snapshot-file schema_after.json \
  --ingest-pipeline lab/pipeline/sysmon_operational.yml \
  --config configs/sysmonconfig-modular-a9ff298.xml \
  --reference-config configs/sysmonconfig-export.xml \
  --baseline baseline.json \
  --fail-on-new
echo "exit: $?"     # 1
```
