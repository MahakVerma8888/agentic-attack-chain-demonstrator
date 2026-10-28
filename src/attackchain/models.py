"""Core data models shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique reference."""

    id: str
    name: str
    tactic: str  # ATT&CK tactic shortname, e.g. "initial-access"

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


@dataclass
class Finding:
    """A normalised finding from any scanner."""

    host: str
    source: str  # "nmap" | "nuclei"
    title: str
    severity: str = "info"
    port: int | None = None
    service: str | None = None
    tags: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    evidence: str = ""

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity.lower(), 0)


@dataclass
class ChainStep:
    """One step of a hypothetical attack path: a technique plus its evidence."""

    technique: Technique
    findings: list[Finding]

    @property
    def weight(self) -> int:
        return max((f.weight for f in self.findings), default=0)


@dataclass
class AttackChain:
    """Ordered technique steps derived from the findings on a single host."""

    host: str
    steps: list[ChainStep]
    narrative: str = ""

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for step in self.steps:
            if step.technique.tactic not in seen:
                seen.append(step.technique.tactic)
        return seen

    @property
    def is_multi_stage(self) -> bool:
        return len(self.tactics) >= 2

    @property
    def score(self) -> int:
        base = sum(step.weight for step in self.steps)
        # A path that spans several tactics is worse than isolated issues.
        return base + 2 * max(0, len(self.tactics) - 1)

    @property
    def rating(self) -> str:
        if self.score >= 20:
            return "critical"
        if self.score >= 12:
            return "high"
        if self.score >= 5:
            return "medium"
        return "low"
