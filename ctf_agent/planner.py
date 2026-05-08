"""Adversarial-aware planning layer for a minimal CTF flag-finding agent.

The planner intentionally separates *what to try next* from the executor.  This
keeps the project focused on planning experiments: scoring hypotheses, avoiding
obvious bait, and choosing evidence-gathering actions before committing to an
attack path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Hypothesis, Observation


@dataclass(frozen=True)
class PlanStep:
    """An executable step chosen by the planning layer."""

    action: str
    target: Path
    reason: str
    expected_signal: str


class AdversarialPlanner:
    """Ranks CTF paths while penalizing adversarial distractions.

    The planner uses a deliberately simple scoring model that is easy to swap
    out later.  It prefers direct, high-signal evidence for flags, but reduces
    the rank of artifacts that look like planted distractions (for example
    filenames containing ``fake`` or text telling the solver to ignore other
    evidence).
    """

    FLAG_PATTERNS = ("flag{", "ctf{", "picoctf{", "htb{", "tryhackme{")
    DECOY_TERMS = (
        "fake",
        "decoy",
        "bait",
        "rabbit hole",
        "ignore all other",
        "not the flag",
        "definitely the flag",
    )
    HIGH_VALUE_SUFFIXES = (
        ".txt",
        ".md",
        ".log",
        ".json",
        ".yaml",
        ".yml",
        ".env",
        ".conf",
        ".ini",
        ".py",
        ".js",
        ".html",
    )

    def initial_plan(self, root: Path) -> list[PlanStep]:
        """Create the first breadth-first plan for a challenge directory."""

        return [
            PlanStep(
                action="enumerate",
                target=root,
                reason="Build a neutral inventory before following any clue.",
                expected_signal="File names, extensions, and obvious entrypoints.",
            )
        ]

    def build_hypotheses(self, observations: list[Observation]) -> list[Hypothesis]:
        """Turn observations into ranked candidate paths."""

        by_source: dict[Path, list[Observation]] = {}
        for obs in observations:
            by_source.setdefault(obs.source, []).append(obs)

        hypotheses: list[Hypothesis] = []
        for source, source_observations in by_source.items():
            text = "\n".join(obs.content for obs in source_observations).lower()
            priority = self._base_priority(source, text)
            risk = self._decoy_risk(source, text)
            rationale = self._rationale(source, text, risk)
            hypotheses.append(
                Hypothesis(
                    name=f"Inspect {source.name}",
                    rationale=rationale,
                    priority=priority,
                    evidence=source_observations,
                    decoy_risk=risk,
                )
            )

        return sorted(hypotheses, key=lambda item: item.score, reverse=True)

    def next_steps(self, hypotheses: list[Hypothesis], limit: int = 3) -> list[PlanStep]:
        """Choose the next verification-oriented actions."""

        steps: list[PlanStep] = []
        for hypothesis in hypotheses[:limit]:
            target = hypothesis.evidence[0].source
            steps.append(
                PlanStep(
                    action="inspect",
                    target=target,
                    reason=f"{hypothesis.rationale} score={hypothesis.score:.2f}",
                    expected_signal="A syntactically valid flag or evidence that downgrades this path.",
                )
            )
        return steps

    def _base_priority(self, source: Path, text: str) -> float:
        score = 0.25
        suffix = source.suffix.lower()
        name = source.name.lower()
        if suffix in self.HIGH_VALUE_SUFFIXES or suffix == "":
            score += 0.35
        if "flag" in name:
            score += 0.3
        if any(pattern in text for pattern in self.FLAG_PATTERNS):
            score += 1.0
        if "password" in text or "secret" in text or "key" in text:
            score += 0.25
        return score

    def _decoy_risk(self, source: Path, text: str) -> float:
        combined = f"{source.name.lower()}\n{self._strip_flag_values(text)}"
        return sum(0.3 for term in self.DECOY_TERMS if self._contains_decoy_term(combined, term))

    def _strip_flag_values(self, text: str) -> str:
        pattern = r"(?:flag|ctf|picoctf|htb|tryhackme)\{[^\s{}]{1,200}\}"
        return re.sub(pattern, "<flag>", text, flags=re.IGNORECASE)

    def _contains_decoy_term(self, text: str, term: str) -> bool:
        if " " in term:
            return term in text
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None

    def _rationale(self, source: Path, text: str, risk: float) -> str:
        reasons: list[str] = []
        if any(pattern in text for pattern in self.FLAG_PATTERNS):
            reasons.append("contains a known flag prefix")
        if "flag" in source.name.lower():
            reasons.append("filename references flag")
        if source.suffix.lower() in self.HIGH_VALUE_SUFFIXES:
            reasons.append("human-readable artifact")
        if risk:
            reasons.append(f"decoy indicators penalized by {risk:.2f}")
        return "; ".join(reasons) or "low-risk inventory candidate"
