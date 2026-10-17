"""Run the same explanations through several models and put them side by side.

Choosing a model from a public leaderboard would be choosing on a proxy. The
work here is narrow and specific: describing Windows telemetry accurately, and
declining to answer when unsure. This measures exactly that, on exactly the
causes this corpus produces, and leaves the judgement to a person reading the
output.

Usage:
    export ANTHROPIC_API_KEY=...
    export OPENAI_API_KEY=...
    python compare_models.py --out ../model-comparison.md

One call per distinct cause, not per rule, so a whole corpus is tens of calls
rather than thousands.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detection_gate.explain import Cause, Explainer, collect_causes  # noqa: E402
from detection_gate.ingest import load_ingest_map  # noqa: E402
from detection_gate.rules import ROUTING_FIELDS, find_rule_files, load_corpus  # noqa: E402
from detection_gate.schema import SchemaSnapshot  # noqa: E402
from detection_gate.sysmon import (  # noqa: E402
    load_profile,
    merge_event_id_maps,
    parse_event_id_map,
    parse_event_id_map_from_dirs,
    parse_unfilterable_event_ids,
    sysmon_event_id_space,
)
from detection_gate.verdict import evaluate  # noqa: E402

# Model ids come from the account's own /v1/models listing rather than from
# memory. The three are picked to span the price range: if the cheap one answers
# as accurately as the expensive one on this narrow task, that is the finding.
CANDIDATES = [
    ("claude-opus-5-5", "anthropic"),
    ("claude-sonnet-5", "anthropic"),
    ("claude-haiku-4-5-20251001", "anthropic"),
]


def build_verdicts(args) -> list:
    rules = load_corpus(
        find_rule_files(Path(args.rules_dir), ["windows"]),
        _pipeline,
    )
    snap = SchemaSnapshot.load(Path(args.snapshot))
    ingest_map = load_ingest_map(Path(args.ingest_pipeline)) if args.ingest_pipeline else None

    id_map = merge_event_id_maps(
        parse_event_id_map(Path(args.reference_config)),
        parse_event_id_map_from_dirs(Path(args.modular_root)) if args.modular_root else {},
    )
    profile = load_profile(
        Path(args.config).stem,
        Path(args.config),
        id_map,
        unfilterable=parse_unfilterable_event_ids(Path(args.reference_config)),
    )
    return [
        evaluate(
            rule,
            profile=profile,
            schema_fields=snap.fields,
            populated_fields=snap.populated,
            sensor_scope_channels={"Microsoft-Windows-Sysmon/Operational"},
            sensor_event_id_space=sysmon_event_id_space(id_map),
            ingest_map=ingest_map,
            ignore_fields=set(ROUTING_FIELDS),
        )
        for rule in rules
    ]


def _pipeline():
    from sigma.pipelines.elasticsearch import ecs_windows
    from sigma.pipelines.sysmon import sysmon_pipeline

    return sysmon_pipeline() + ecs_windows()


def render(results: dict[Cause, dict[str, object]], models: list[str]) -> str:
    lines = [
        "# Model comparison for the explanation layer",
        "",
        f"Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}. "
        f"{len(results)} distinct causes, {len(models)} models.",
        "",
        "Read these for accuracy, not fluency. An empty section is a correct "
        "answer when the model does not know; an confident-sounding wrong "
        "sentence is the failure mode that matters.",
        "",
    ]

    for cause, by_model in results.items():
        lines.append(f"## `{cause.key}`")
        lines.append("")
        for model in models:
            explanation = by_model.get(model)
            lines.append(f"### {model}")
            if explanation is None:
                lines.append("_call failed_")
                lines.append("")
                continue
            if explanation.is_empty():
                lines.append("_truncated_" if explanation.truncated else "_declined to answer_")
                lines.append("")
                continue
            if explanation.truncated:
                lines.append("- _answer was cut off; treat as incomplete_")
            for label, value in (
                ("what", explanation.what),
                ("how to collect", explanation.how_to_collect),
                ("noise", explanation.noise),
                ("why absent", explanation.why_absent),
                ("frequency", explanation.frequency_note),
            ):
                if value:
                    lines.append(f"- **{label}**: {value}")
            lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-dir", default="sigma/rules")
    parser.add_argument("--snapshot", default="schema.json")
    parser.add_argument("--ingest-pipeline", default="lab/pipeline/sysmon_operational.yml")
    parser.add_argument("--config", default="configs/sysmonconfig-export.xml")
    parser.add_argument("--reference-config", default="configs/sysmonconfig-export.xml")
    parser.add_argument("--modular-root", default="configs/sysmon-modular")
    parser.add_argument("--out", default="model-comparison.md")
    parser.add_argument("--limit", type=int, default=0, help="only the first N causes, for a cheap trial")
    parser.add_argument("--models", nargs="*", help="override the candidate list, as model:provider")
    args = parser.parse_args()

    candidates = CANDIDATES
    if args.models:
        candidates = [tuple(entry.split(":", 1)) for entry in args.models]

    verdicts = build_verdicts(args)
    causes = collect_causes(verdicts)
    if args.limit:
        causes = dict(list(causes.items())[: args.limit])

    print(f"{len(causes)} distinct causes, {sum(len(v) for v in causes.values())} rule-and-reason pairs")
    print(f"{len(candidates)} models, so {len(causes) * len(candidates)} calls in total\n")

    results: dict[Cause, dict[str, object]] = {}
    for model, provider in candidates:
        explainer = Explainer(model, provider=provider)
        if not explainer.api_key:
            print(f"  {model}: no API key for {provider}, skipping")
            continue
        print(f"  {model} ({provider})")
        for index, (cause, rules) in enumerate(causes.items(), 1):
            try:
                explanation = explainer.explain(cause, rules)
            except Exception as error:
                print(f"    {cause.key}: failed, {type(error).__name__}: {error}")
                explanation = None
            results.setdefault(cause, {})[model] = explanation
            print(f"    [{index}/{len(causes)}] {cause.key}")

    output = Path(args.out)
    output.write_text(render(results, [m for m, _ in candidates]), encoding="utf-8")
    print(f"\nwrote {output}")


if __name__ == "__main__":
    main()
