"""Pluggable reasoning layer that turns a chain into an analyst-style narrative.

Two implementations are provided:

* ``RuleBasedReasoner`` - deterministic templates, no network, the default.
* ``LLMReasoner`` - wraps *any* ``complete(prompt) -> str`` callable you supply
  (a hosted API, a local Ollama model, ...). This repo ships no API keys
  and makes no network calls itself; if the callable raises, the reasoner falls
  back to the rule-based narrative so reports are always produced.
"""

from __future__ import annotations

from typing import Callable, Protocol

from .models import AttackChain


class Reasoner(Protocol):
    def explain(self, chain: AttackChain) -> str: ...


class RuleBasedReasoner:
    """Deterministic, explainable narrative generator."""

    def explain(self, chain: AttackChain) -> str:
        if not chain.steps:
            return "No actionable techniques were identified for this host."
        parts = []
        for i, step in enumerate(chain.steps, 1):
            evidence = ", ".join(sorted({f.title for f in step.findings}))
            parts.append(
                f"{i}. **{step.technique.tactic.replace('-', ' ').title()}** via "
                f"{step.technique.name} ({step.technique.id}), supported by: {evidence}."
            )
        if chain.is_multi_stage:
            head = (
                f"Host {chain.host} exposes weaknesses across {len(chain.tactics)} tactics, "
                "so an adversary could plausibly combine them as follows:"
            )
        else:
            head = f"Host {chain.host} shows an isolated weakness (single tactic):"
        return head + "\n\n" + "\n".join(parts)


class LLMReasoner:
    """Ask an LLM to write the narrative, grounded strictly in the findings."""

    def __init__(
        self,
        complete: Callable[[str], str],
        fallback: Reasoner | None = None,
    ) -> None:
        self._complete = complete
        self._fallback = fallback or RuleBasedReasoner()

    @staticmethod
    def build_prompt(chain: AttackChain) -> str:
        lines = [
            "You are a defensive security analyst. Using ONLY the evidence below,",
            "explain in 4-6 sentences how these weaknesses could be chained together",
            "and what to fix first. Do not invent findings, CVEs or exploits.",
            f"Host: {chain.host}",
        ]
        for step in chain.steps:
            titles = "; ".join(f.title for f in step.findings)
            lines.append(f"- {step.technique.id} {step.technique.name} [{step.technique.tactic}]: {titles}")
        return "\n".join(lines)

    def explain(self, chain: AttackChain) -> str:
        try:
            text = self._complete(self.build_prompt(chain)).strip()
            if text:
                return text
        except Exception:  # noqa: BLE001 - any provider failure falls back
            pass
        return self._fallback.explain(chain)
