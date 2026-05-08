from pathlib import Path

from ctf_agent.agent import CTFAgent
from ctf_agent.planner import AdversarialPlanner


def test_agent_prefers_non_decoy_flag(tmp_path: Path) -> None:
    (tmp_path / "fake_flag.txt").write_text("definitely the flag flag{wrong}", encoding="utf-8")
    (tmp_path / "app.log").write_text("real token ctf{right_path}", encoding="utf-8")

    result = CTFAgent().run(tmp_path)

    assert result.flag == "ctf{right_path}"
    assert result.inspected[0].name == "app.log"


def test_planner_penalizes_decoys(tmp_path: Path) -> None:
    decoy = tmp_path / "fake_flag.txt"
    real = tmp_path / "notes.txt"
    decoy.write_text("definitely the flag flag{wrong}", encoding="utf-8")
    real.write_text("audit trail flag{right}", encoding="utf-8")

    observations = CTFAgent().observe(tmp_path)
    hypotheses = AdversarialPlanner().build_hypotheses(observations)

    assert hypotheses[0].evidence[0].source == real
