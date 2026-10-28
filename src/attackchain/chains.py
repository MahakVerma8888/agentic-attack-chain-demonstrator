"""Correlate findings into per-host, tactic-ordered attack chains."""

from __future__ import annotations

from collections import defaultdict

from .mitre import TACTIC_ORDER, map_finding
from .models import AttackChain, ChainStep, Finding, Technique


def build_chains(findings: list[Finding]) -> list[AttackChain]:
    """Group findings by host and order the implied techniques by tactic.

    Each technique becomes one step, carrying every finding that supports it.
    Chains are returned highest-score first.
    """
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_host[finding.host].append(finding)

    chains: list[AttackChain] = []
    for host, host_findings in by_host.items():
        support: dict[str, tuple[Technique, list[Finding]]] = {}
        for finding in host_findings:
            for technique in map_finding(finding):
                entry = support.setdefault(technique.id, (technique, []))
                entry[1].append(finding)
        if not support:
            continue
        steps = [ChainStep(technique=t, findings=fs) for t, fs in support.values()]
        steps.sort(key=lambda s: (_tactic_rank(s.technique.tactic), s.technique.id))
        chains.append(AttackChain(host=host, steps=steps))

    chains.sort(key=lambda c: c.score, reverse=True)
    return chains


def _tactic_rank(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)
