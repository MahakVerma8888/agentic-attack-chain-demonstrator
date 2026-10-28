"""Render attack chains as Markdown and JSON reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .mitre import REMEDIATION
from .models import AttackChain

DISCLAIMER = (
    "> **Note:** chains are *hypothetical paths derived from scanner findings* and "
    "ATT&CK heuristics. They are triage aids for defenders, not proof of exploitability."
)


def to_markdown(chains: list[AttackChain], generated_at: datetime | None = None) -> str:
    stamp = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    out = ["# Attack Chain Report", "", f"_Generated {stamp}_", "", DISCLAIMER, ""]
    if not chains:
        out.append("No findings mapped to ATT&CK techniques.")
        return "\n".join(out) + "\n"

    out += ["## Summary", "", "| Host | Rating | Score | Tactics | Steps |", "|---|---|---|---|---|"]
    for c in chains:
        out.append(
            f"| {c.host} | {c.rating.upper()} | {c.score} | {' → '.join(c.tactics)} | {len(c.steps)} |"
        )

    for c in chains:
        out += ["", f"## Host {c.host} - {c.rating.upper()} (score {c.score})", "", c.narrative or "", ""]
        out += ["| # | Tactic | Technique | Evidence |", "|---|---|---|---|"]
        for i, s in enumerate(c.steps, 1):
            evidence = "<br>".join(sorted({f.title for f in s.findings}))
            out.append(
                f"| {i} | {s.technique.tactic} | [{s.technique.id}]({s.technique.url}) {s.technique.name} | {evidence} |"
            )
        fixes = [REMEDIATION[s.technique.id] for s in c.steps if s.technique.id in REMEDIATION]
        if fixes:
            out += ["", "**Recommended mitigations**", ""] + [f"- {fix}" for fix in dict.fromkeys(fixes)]
    return "\n".join(out) + "\n"


def to_json(chains: list[AttackChain]) -> str:
    payload = [
        {
            "host": c.host,
            "rating": c.rating,
            "score": c.score,
            "tactics": c.tactics,
            "narrative": c.narrative,
            "steps": [
                {
                    "technique": s.technique.id,
                    "name": s.technique.name,
                    "tactic": s.technique.tactic,
                    "findings": [f.title for f in s.findings],
                }
                for s in c.steps
            ],
        }
        for c in chains
    ]
    return json.dumps(payload, indent=2)
