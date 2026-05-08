"""Core data models for the CTF agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Observation:
    """A fact collected from the challenge workspace."""

    source: Path
    kind: str
    content: str
    confidence: float = 1.0


@dataclass
class Hypothesis:
    """A candidate attack path or flag location."""

    name: str
    rationale: str
    priority: float
    evidence: list[Observation] = field(default_factory=list)
    decoy_risk: float = 0.0

    @property
    def score(self) -> float:
        """Evidence-weighted score after penalizing likely decoys."""

        evidence_boost = sum(obs.confidence for obs in self.evidence) * 0.25
        return self.priority + evidence_boost - self.decoy_risk
