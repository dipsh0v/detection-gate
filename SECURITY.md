# Security

## Reporting

Open a draft security advisory on this repository, or write to the address on
my GitHub profile. I will acknowledge within five working days. If you have not
heard back in that time, assume the message went astray and open the advisory.

Please do not open a public issue for anything that would let someone read
another person's telemetry or credentials before there is a fix.

## What this tool touches

detection-gate reads. It issues one `field_caps` call and a small number of
`size: 0` aggregation requests against the index pattern you name, and it never
runs your detection searches. It writes nothing to your cluster.

The Elasticsearch API key is read from `$ELASTIC_API_KEY` and is not accepted
as a command-line flag, so it does not land in `ps`, `/proc`, shell history or
a CI log. A URL carrying a username or password is refused. TLS verification is
always on and there is no flag to turn it off.

## What leaves your network

Nothing, unless you pass `--model` to the `explain` command. That command asks
a third-party API to describe the telemetry behind a finding, and before the
first call it prints the endpoint, the number of calls and the exact list of
what each question carries, then waits for you to confirm. `--dry-run` lists
the questions and asks nothing. `--base-url` points the same code at a model on
your own network.

Each question carries resolved field names, a Sysmon event ID, a count of
affected rules and up to five rule titles. It carries no rule logic, no event
data, no query results and no credentials. Rule titles are third-party content,
so they are flattened, length-capped and passed inside a block the system
prompt declares untrusted.

## What the report contains

An HTML report names your index pattern, the window, every absent or silent
field, and the titles of every failing rule. That is a map of where your
telemetry is thin. Treat it as you would treat a coverage review, and set a
short retention on it if a CI job publishes it as an artifact.

## Known boundaries

The tool parses third-party content: Sigma rules, Sysmon configuration XML, and
an Elasticsearch ingest pipeline definition. XML is parsed with entity
expansion refused. Pattern matching against pipeline-authored regular
expressions is length-capped on both sides. A processor type the tool does not
model is reported as not assessed, never as evidence.
