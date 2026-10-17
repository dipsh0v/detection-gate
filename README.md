# detection-gate

Prove which of your deployed detections physically cannot fire.

A Sigma rule reads specific log fields from a specific event. If your sensor
never emits that event, or your SIEM never stores that field, the rule cannot
match anything an attacker does. It still passes CI. It still shows green on
your ATT&CK coverage map. It simply runs over nothing, forever, and nothing in
your stack tells the difference between "quiet" and "dead".

detection-gate answers that question as a fact, not an estimate. There is no
matching model, no similarity score, no probability. A field exists or it does
not. An event is collected or it is not. Data arrives or it does not.

## What one run found

SigmaHQ Windows rules at commit `d1c1622`, measured against a lab holding
88,239 Sysmon events, with `olafhartong/sysmon-modular` at `082cba5` as the
deployed sensor config:

```
  167 of 1862 in-scope rules cannot fire (9.0%); 1674 can.
    42 the telemetry is not there, 125 it is there under another name.
  21 more read fields that carried no data in the window.
  64 fire more than intended; an exception is broken.
```

113 of the 167 are a single rename. One line in an ingest pipeline moved
`winlog.event_data.Details` into the `registry.*` namespace, and a hundred and
thirteen registry detections have been querying the old name ever since.

The rendered report is in this repo as `sample-report.html`, and `lab/` holds
everything needed to reproduce it. Two things about those numbers that belong
here and not in a footnote:

The 21 starved rules are there because I caused the outage. `simulate_outage.py`
deletes Sysmon event 10 from the index, which is where `CallTrace` and
`GrantedAccess` come from, the same way a config change would. Loaded clean,
this lab starves nothing. A verdict about missing data is only interesting if
you can show the data going missing.

The window is `now-10y` because the public captures the lab loads were recorded
between September 2020 and July 2023. A short window would report the whole
corpus as starved and prove nothing.

## Every verdict is decided before the LLM is called

The optional advisory layer is asked to describe the telemetry behind a
finding, never to judge whether a rule fires, and `--no-ai` produces identical
verdicts. That is a test, not a promise.

It runs once per cause rather than once per rule, so the whole corpus above
came to 24 questions. Twenty-four is few enough that a person reads all of them
before they ship, and this one did: six were wrong and were corrected by hand,
which `explanations.json` records alongside what was changed. None of the six
moved a verdict, because none of them could.

What leaves your network, and when, is in [the advisory
layer](#the-advisory-layer) further down. Short version: nothing, unless you
pass `--model`, and the command prints the endpoint and the exact contents
before the first call.

## Verdicts

| Verdict | Meaning | Root cause | Fix |
|---|---|---|---|
| `FIREABLE` | Event is collected, fields exist, data is arriving | — | none |
| `DEAD-ON-ARRIVAL` | The rule can never match: the sensor does not emit the event, or the field is absent from the schema | planning gap | collect the telemetry, or retire the rule |
| `MISMAPPED` | The telemetry is collected, but the ingest pipeline stores it under a name the rule does not use | conversion gap | repoint the rule at the name the data actually has |
| `STARVED` | Field exists in the schema but no data arrived in the window | operational gap | find the break: agent down, config change, retention |
| `OUT-OF-SCOPE` | The rule belongs to a different log source than the profile under test | not a failure | check it against the right source |
| `NOT-ASSESSED` | detection-gate could not judge the rule: the conversion pipeline failed on it, it is a correlation rule, or nothing in it was checkable | our gap, not yours | reported and counted, never hidden |

Alongside the verdicts there is one secondary signal, `degraded filters`: the
rule fires, but a field it reads only to carve out an exception is missing or
renamed, so the exception never applies and the rule fires more often than its
author intended. It never changes a verdict.

`OUT-OF-SCOPE` exists for one reason: counting PowerShell or IIS rules as dead
when you are testing a Sysmon config would inflate the number with failures
that config was never responsible for. Those rules leave the denominator, and
the report breaks them down by which of the four reasons applied, because a
single total under one label is where inconvenient rules get hidden.

`NOT-ASSESSED` is deliberately *not* given that treatment. Dropping rules we
failed to convert would shrink the denominator and raise the headline
percentage on the strength of our own failures, so they stay in the count and
are named. A test enforces the arithmetic.

## Evidence strength

Not every statement about where a value went is equally strong, and the report
says which is which:

| Evidence | Meaning |
|---|---|
| declared rename | the pipeline declares a move, and the schema confirms the destination |
| staged rename | the pipeline stages the value into a scratch field and a later move carries it out |
| derived from a script | a pipeline script writes a namespace the schema confirms; which field inside it holds this value is not stated, so the report lists the candidates to confirm instead of naming one |

A field the pipeline merely deletes resolves to nothing. A deletion is proof of
deletion, not proof of relocation, so those rules are reported as absent
telemetry and not given an invented destination.

One source field can also land in different places on different events.
`Hashes` goes to `process.hash.*` on process creation and `dll.hash.*` on an
image load, because the processor that moves it is guarded by event code. The
destination is resolved per event, and the same field can be `MISMAPPED` for
one rule and `DEAD-ON-ARRIVAL` for another.

When a pipeline uses a processor type detection-gate does not model, the field
is reported as not assessed. It is not reported as absent, because a processor
nobody read is not evidence of anything.

## What detection-gate does not do

It never asks whether a rule's *values* would match real activity. A rule can
be `FIREABLE` and still never fire because no command line in your estate
contains the string it looks for. That question is genuinely fuzzy and is
deliberately out of scope. detection-gate only answers the part that has an exact
answer, which is why its output is a fact.

## Install

Python 3.10 or newer.

```bash
pip install -e .           # core
pip install -e ".[live]"   # plus the Elasticsearch client
pip install -e ".[ai]"     # plus the optional advisory layer
pip install -e ".[dev]"    # plus pytest
```

The rule corpus is not vendored here. Clone the one you actually deploy, and
pin it: the answer detection-gate gives is only reproducible against a stated
commit, because SigmaHQ changes weekly.

```bash
git clone https://github.com/SigmaHQ/sigma.git
git -C sigma rev-parse --short HEAD    # record this next to any number you publish
```

## Use

Sensor check, no SIEM required. Which rules die because your Sysmon config
never emits the event they need:

```bash
detection-gate scan-sensor \
  --rules-dir ./sigma/rules \
  --config ./sysmonconfig-export.xml \
  --reference-config ./sysmonconfig-export.xml \
  --modular-root ./sysmon-modular \
  --html-out report.html
```

Capture your SIEM's schema, once, so later runs and demos work offline:

```bash
export ELASTIC_API_KEY='...'
detection-gate snapshot \
  --url https://siem.example:9243 \
  --index-pattern 'winlogbeat-*' \
  --rules-dir ./sigma/rules \
  --out schema.json
```

Full check across sensor, schema and data population:

```bash
detection-gate scan \
  --rules-dir ./sigma/rules \
  --snapshot-file schema.json \
  --ingest-pipeline ./sysmon_operational.yml \
  --config ./sysmonconfig-export.xml \
  --reference-config ./sysmonconfig-export.xml \
  --html-out report.html
```

Exit codes: `0` pass, `1` the gate found a new failure, `2` usage error, `3`
something inside the tool went wrong. In CI a crash and a failed gate are not
the same event and should not share a code.

## Load on your SIEM

detection-gate never runs your detection searches. Running a corpus of rules as
queries would hammer the SIEM; asking the schema does not. Two cheap questions
are all it needs:

- Schema: one `field_caps` call returns every field in an index pattern,
  whatever the rule count.
- Population: fields are deduplicated first, then batched into aggregation
  requests with `size: 0`, which count from the index instead of returning
  documents.

The cost is driven by the number of distinct fields the corpus reads, not by
the number of rules. The run above read 186 distinct fields across 2,410 rules
and asked about 47 of them, which is one `field_caps` call and one aggregation
request. `--batch-size` and `--request-pause` are there for clusters that want
to be asked more gently.

Everything is read-only. It needs read access on the index pattern and touches
no production data.

## Credentials

The Elasticsearch API key is read from `$ELASTIC_API_KEY` and is deliberately
not accepted as a flag. A credential on a command line lands in `ps`, in
`/proc`, in shell history, and in any CI log running under `set -x`. A URL
carrying a username or password is refused with a message saying where the
credential belongs instead.

TLS verification is always on. There is no `--insecure`. A private CA goes in
`--ca-cert`.

## In a pull request

`examples/github/` holds two workflows. One is a scheduled job that holds the
SIEM credential, takes a snapshot and commits it. The other is the pull request
gate, which reads that file and never sees a credential, because a job that
executes code from a fork has no business holding one.

The gate compares against a baseline of what the team has already accepted, so
day one is not a wall of inherited failures, and it fails only on what a change
made worse. With `--sarif-out` the finding lands on the changed line in the
review rather than in a report someone has to download.

## The advisory layer

There is an optional step that asks a model to describe the telemetry behind a
finding: what the field is, how it is collected, what the volume looks like.
Three things hold it in place.

It is told the fact and never asked for one. Every verdict is decided before
the model is called, and `--no-ai` produces identical verdicts. That is a test,
not a claim.

It is keyed by cause, not by rule. The run above produced 24 distinct causes
across 265 rule-and-reason pairs, so the whole report is 24 answers. That is
few enough that a person can read every one before it ships, and the notes in
this repo were read: six of them were wrong and were corrected by hand, which
`explanations.json` records.

It discloses what leaves your network before it leaves. The command prints the
endpoint, the call count and the exact list of what each question carries,
then waits. `--base-url` points it at a model on your own network, and
`--dry-run` lists the questions without asking anything.

Every note in the report is labelled advisory, names the model that wrote it,
and states whether a human reviewed it.

## Where the sensor knowledge comes from

Nothing about Sysmon is hard coded from memory:

- The event ID to element mapping is parsed from the section headers
  SwiftOnSecurity documents in the reference config, plus the directory names
  in `olafhartong/sysmon-modular` for events newer than that config.
- The filtering semantics come from the config authors. SwiftOnSecurity states
  it inline: *"Using `include` with no rules means nothing in this section will
  be logged."*

If a config uses an element detection-gate cannot map to an event ID, it says so
instead of guessing. There is no model of what Sysmon does with no config file
at all, because that number would not be traceable to a file on disk.

## Honest limits

- Field resolution is only as good as the pySigma pipeline you configure. A
  different pipeline gives different field names and therefore a different
  answer. Run it with the pipeline you actually convert with.
- A statically documented schema is not enough for the field check. Winlogbeat
  creates `winlog.event_data.*` fields dynamically as data arrives, so they are
  absent from the published field definitions while being present at runtime.
  This is exactly why the field check reads live `field_caps` instead of a
  published schema file.
- Sigma correlation rules describe sequences of events and are outside a
  single-event field-presence check. They are counted as `NOT-ASSESSED` and
  reported under "Set aside, and why".
- The event check asks whether a configuration collects an event at all. It
  does not evaluate how narrowly an `include` rule scopes that event, so a rule
  counted as able to fire may still never see the activity it describes. The
  report states how many rules this applies to.
- Sigma conditions are evaluated as conditions, not as a flat list of field
  names: a rule dies only when every branch that could match is broken. A field
  read by one branch of a disjunction is not a requirement.
- Presence in the schema does not prove a field was ever populated. An index
  template can map a field no document has ever carried, so `STARVED` means
  "no data in this window", never "collection stopped".
- A field the population query never asked about cannot be called empty. Those
  rules are `NOT-ASSESSED`, with the undecided field names printed.
- Some fields are genuinely rare, and a rare field is not a broken one. Widen
  the window before treating a starved verdict as an incident.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite guards the places where an inference could quietly become a fact:
condition semantics, the ingest map's evidence rules, the separation of "we
have no mapping" from "your config disables this", the denominator arithmetic,
and the guarantee that the advisory layer cannot move a verdict. It also parses
the real Elastic ingest pipeline in `lab/`, so the evidence rules are tested
against a pipeline somebody actually ships rather than against a fixture that
agrees with them.

## Licence

MIT. The lab, the tests, the raw counts and the exact rule set commit are all
here, so you can run it against your own corpus and disagree with the result.
