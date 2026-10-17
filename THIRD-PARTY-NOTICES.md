# Third-party notices

detection-gate reads three bodies of work it did not write, and the honesty of
its output depends on them. None of them is vendored into this repository; the
commits the published numbers were measured against are in
`pinned-sources.json`.

## SigmaHQ/sigma

The detection rule corpus. Licensed under the Detection Rule License (DRL)
1.1, which is not an OSI licence and carries its own attribution and
redistribution terms. Read them before redistributing rules:
https://github.com/SigmaHQ/sigma/blob/master/LICENSE

Clone it yourself and pin the commit. The answer this tool gives is only
reproducible against a stated one.

## olafhartong/sysmon-modular

The modular Sysmon configuration used as the deployed sensor config in the
published run, and the source of the directory names this tool reads for event
IDs newer than the reference config documents. MIT licensed.
https://github.com/olafhartong/sysmon-modular

## SwiftOnSecurity/sysmon-config

The reference configuration this tool parses for the event ID to element
mapping and for the documented filtering semantics, including the line it
quotes about `include` with no rules. MIT licensed.
https://github.com/SwiftOnSecurity/sysmon-config

## elastic/integrations

`lab/pipeline/sysmon_operational.yml` is Elastic's own published ingest
pipeline for Windows Sysmon logs, used unmodified. It is in this repository
because the lab's whole argument rests on the ECS field names being Elastic's
work and not mine. Elastic's integrations are published under the Elastic
licence; see https://github.com/elastic/integrations for the terms that apply
to redistribution.

## OTRF/Security-Datasets

The four public Sysmon captures the lab downloads at load time. They are
fetched, not vendored. https://github.com/OTRF/Security-Datasets

## pySigma

Rule parsing and the Sysmon and Windows processing pipelines, by the SigmaHQ
project, LGPL-2.1. https://github.com/SigmaHQ/pySigma
