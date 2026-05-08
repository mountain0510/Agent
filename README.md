# CTF Planner Agent

A minimal, runnable CTF flag-finding agent focused on the **planning layer**.
It is designed for local CTF challenge folders that may contain adversarial
bait such as fake flags, misleading notes, and rabbit holes.

## Goal

Most CTF tasks have one or a small number of valid paths to a flag.  If a task
also includes planted distractions, a naive agent can over-commit to the first
plausible clue.  This repository provides a small baseline agent whose planner:

1. inventories the challenge before following any single clue;
2. converts observations into scored hypotheses;
3. penalizes decoy indicators such as `fake`, `decoy`, `bait`, and
   "not the flag";
4. verifies high-scoring candidates first while keeping a trace of its plan.

## Install

```bash
python -m pip install -e .
```

## Run

```bash
ctf-agent examples/simple_ctf --trace
```

Expected output ends with:

```text
flag{planning_beats_bait}
```

## Architecture

- `ctf_agent.agent.CTFAgent`: observe-plan-inspect loop for local challenge
  directories.
- `ctf_agent.planner.AdversarialPlanner`: the planning layer you can improve
  without changing the executor.
- `ctf_agent.models`: small dataclasses for observations and hypotheses.

## Safety and scope

This baseline only reads local files.  It does not perform network scanning,
credential attacks, persistence, or exploitation against third-party systems.
That makes it useful for planning-layer experiments before adding richer CTF
observations or tools.
