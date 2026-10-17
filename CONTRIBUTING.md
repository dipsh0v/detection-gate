# Contributing

## The one rule

This tool's output is only worth anything if it is a fact. A change that makes
a verdict easier to reach is a change that makes the tool worse. If the code
cannot establish something from what it read, the honest answer is
`NOT-ASSESSED` and a sentence saying what it could not establish.

That shapes code review here more than style does. When you add a branch, ask
what evidence it stands on, and whether the failure direction is "I do not
know" rather than "this is fine".

## Getting set up

```bash
pip install -e ".[live,ai,dev]"
pytest
```

`lab/README.md` brings up a local Elasticsearch with real Sysmon telemetry, so
you can change the engine and see the numbers move without pointing anything at
a production cluster.

## Tests

A pull request that changes a verdict needs a test that would have failed
before it. The suite is small on purpose and most of it reads as a ledger of
wrong verdicts that actually shipped, each test named after the case it stops
coming back.

Two files carry more weight than the rest. `tests/test_no_inference.py` pins
the evidence rules: what the tool is allowed to claim about where a value went,
and what it must refuse to claim. `tests/test_no_ai.py` pins the separation
between measurement and the advisory layer. If a change to either of those
makes a test fail, the test is probably right.

The ingest tests parse the real Elastic pipeline in `lab/pipeline/`. Prefer
adding a case there over hand-building an `IngestFieldMap`, because a fixture
that agrees with the parser proves nothing about a pipeline somebody ships.

## Before you release a number

Any figure that goes in the README, in an issue or on a slide needs the SigmaHQ
commit and the sensor config commit next to it. `pinned-sources.json` records
the ones the published run used. SigmaHQ changes weekly, so a number without a
commit is not reproducible and should not be published.

## Reviewing

I read the rendered report three times before a release: once as a manager who
needs one sentence, once as the engineer who has to act on a finding tomorrow,
and once as someone trying to catch the report claiming more than it measured.
The third pass is the one that finds things.
