"""Executable local CTF agent built around the planning layer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Observation
from .planner import AdversarialPlanner, PlanStep


FLAG_RE = re.compile(r"(?:flag|ctf|picoctf|htb|tryhackme)\{[^\s{}]{1,200}\}", re.IGNORECASE)


@dataclass(frozen=True)
class AgentResult:
    """Final result returned by a CTF run."""

    flag: str | None
    inspected: list[Path]
    plan_trace: list[PlanStep]


class CTFAgent:
    """A minimal local-filesystem CTF flag finder.

    This is intentionally constrained to local challenge directories.  It does
    not perform network exploitation; instead, it provides a small runnable
    harness for planning-layer experiments in adversarial CTF-style tasks.
    """

    def __init__(self, planner: AdversarialPlanner | None = None, max_bytes: int = 200_000):
        self.planner = planner or AdversarialPlanner()
        self.max_bytes = max_bytes

    def run(self, root: Path | str) -> AgentResult:
        """Run the observe-plan-inspect loop against a local challenge root."""

        root_path = Path(root).resolve()
        if not root_path.exists() or not root_path.is_dir():
            raise ValueError(f"Challenge root must be an existing directory: {root_path}")

        trace = self.planner.initial_plan(root_path)
        observations = self.observe(root_path)
        hypotheses = self.planner.build_hypotheses(observations)
        next_steps = self.planner.next_steps(hypotheses, limit=len(hypotheses))
        trace.extend(next_steps)

        inspected: list[Path] = []
        best_decoy_flag: str | None = None
        for step in next_steps:
            inspected.append(step.target)
            content = self._safe_read(step.target)
            flag = self._extract_flag(content)
            if not flag:
                continue
            if self._looks_decoy(step.target, content):
                best_decoy_flag = best_decoy_flag or flag
                continue
            return AgentResult(flag=flag, inspected=inspected, plan_trace=trace)

        return AgentResult(flag=best_decoy_flag, inspected=inspected, plan_trace=trace)

    def observe(self, root: Path) -> list[Observation]:
        """Collect lightweight observations from candidate files."""

        observations: list[Observation] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or self._is_hidden_metadata(path, root):
                continue
            content = self._safe_read(path)
            if content is None:
                observations.append(Observation(path, "binary", path.name, confidence=0.2))
                continue
            confidence = 1.0 if FLAG_RE.search(content) else 0.5
            observations.append(Observation(path, "text", content[:2_000], confidence=confidence))
        return observations

    def _safe_read(self, path: Path) -> str | None:
        try:
            data = path.read_bytes()[: self.max_bytes]
        except OSError:
            return None
        if b"\x00" in data:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="ignore")

    def _extract_flag(self, content: str | None) -> str | None:
        if not content:
            return None
        match = FLAG_RE.search(content)
        return match.group(0) if match else None

    def _looks_decoy(self, path: Path, content: str | None) -> bool:
        if content is None:
            return False
        combined = f"{path.name.lower()}\n{self.planner._strip_flag_values(content.lower())}"
        return any(self.planner._contains_decoy_term(combined, term) for term in self.planner.DECOY_TERMS)

    def _is_hidden_metadata(self, path: Path, root: Path) -> bool:
        relative_parts = path.relative_to(root).parts
        return any(part.startswith(".git") or part == "__pycache__" for part in relative_parts)
