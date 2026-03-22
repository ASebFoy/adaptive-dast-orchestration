# Adaptive DAST Orchestration: LLM-Driven Vulnerability Discovery

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

> **MSc Thesis Artifact** — NOVA Information Management School  
> Information Technology Management (Cybersecurity Specialisation)  
> Anton Sebastian Foy, 2026

---

## Overview

This repository contains the complete experimental artifact for a Design Science Research (DSR) thesis investigating whether an LLM-driven agent can improve injection vulnerability detection compared to traditional static scanning configurations.

The artefact is a **ReAct (Reasoning + Acting) agent** powered by GPT-4o that autonomously orchestrates OWASP ZAP scanning decisions. It is evaluated against a **static OWASP ZAP Automation Framework baseline**, both targeting OWASP Juice Shop v17.1.1 across **n=10 independent runs per condition** with full environment resets between runs.

### Research Questions

1. Can an LLM-driven orchestration agent achieve higher vulnerability recall than a fixed-configuration baseline?
2. Does adaptive orchestration maintain comparable precision?
3. How do resource consumption profiles differ between conditions?

### Hypotheses

| ID | Hypothesis | Result |
|----|-----------|--------|
| **H1** | Agent achieves higher recall than baseline | **Supported** (p < 0.001, Cliff's δ = 1.0) |
| **H2** | Agent maintains precision within 10pp of baseline | **Supported** (both 100%, δ = 0.0) |
| **H3a** | Agent produces different HTTP request volume | **Supported** (p < 0.001, δ = 1.0) |
| **H3b** | Agent improves detection efficiency by ≥25% | **Not supported** (−94.2%, baseline-favoured) |

### Key Findings

| Metric | Agent (n=10) | Baseline (n=10) |
|--------|:------------:|:----------------:|
| Recall | 42.86% | 28.57% |
| Precision | 100% | 100% |
| Cliff's δ (recall) | 1.0 (large) | — |
| Mean HTTP Requests | 39,412 | 1,504 |
| Mean Duration (min) | 59.4 | 60.1 |
| Mean Cost (USD) | $0.14 | — |

**Emergent Finding — Completion Declaration Pattern:** The agent accurately self-assessed task completion but continued executing post-declaration, consuming approximately 67.2% of total API expenditure with zero additional vulnerability detections. This pattern was observed in all 10 agent runs.

---

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────────┐
│   GPT-4o LLM    │────▶│  ReAct Agent │────▶│   OWASP ZAP API  │
│  (Reasoning)    │◀────│  (Orchestr.) │◀────│   (Scanning)     │
└─────────────────┘     └──────────────┘     └──────┬───────────┘
                                                     │
                                                     ▼
                                              ┌──────────────┐
                                              │  Juice Shop  │
                                              │  v17.1.1     │
                                              └──────────────┘
```

**Agent condition:** GPT-4o ReAct loop → tool selection → ZAP API calls → observation → reasoning → next action

**Baseline condition:** Fixed YAML configuration → ZAP Automation Framework → sequential scan execution

Both conditions ran with a 60-minute timeout per run.

---

## Repository Structure

```
├── README.md
├── LICENSE
├── .env.example                          # Environment variables template
├── .gitignore
├── docker-compose.yml                    # Juice Shop + ZAP containers
├── requirements.txt                      # Python dependencies (pinned)
├── requirements-dev.txt
│
├── src/                                  # Experiment code
│   ├── react_dast_agent.py               # ReAct agent (core artefact)
│   ├── tools.py                          # ZAP API tool abstraction layer
│   ├── baseline_runner.py                # ZAP Automation Framework runner
│   ├── experiment_runner.py              # Single-run orchestrator
│   ├── overnight_agent.py                # Batch runner — agent (n=10)
│   ├── overnight_baseline.py             # Batch runner — baseline (n=10)
│   ├── setup_user.py                     # Juice Shop user provisioning
│   └── reset_environment.py              # Environment reset between runs
│
├── analysis/                             # Post-experiment analysis
│   ├── evaluate.py                       # Ground truth matching & scoring
│   └── analyze_results.py                # Statistical tests (Mann-Whitney U, Cliff's δ)
│
├── config/                               # Configuration
│   ├── ground_truth_injection.json       # 8 injection vulnerability definitions
│   └── zap-injection-baseline.yaml       # ZAP Automation Framework config
│
├── data/                                 # Experimental results (n=10 per condition)
│   ├── agent_consolidated_summary.json   # All agent runs: alerts, transcripts, costs
│   ├── baseline_consolidated_summary.json
│   ├── agent_traces.json                 # Action sequences & phase analysis
│   ├── completion_declaration_analysis.json
│   ├── evaluation.json                   # Ground truth evaluation
│   └── analysis.json                     # Statistical analysis output
│
├── tables/                               # Thesis-ready CSV tables
│   ├── table_baseline_timing.csv
│   ├── table_agent_phase_timing.csv
│   ├── table_cost_breakdown.csv
│   └── table_agent_action_distribution.csv
│
└── scripts/                              # Utility scripts
    ├── quick_smoke_test.sh
    ├── start_agent.sh
    ├── reset.sh
    └── setup_verification.sh
```

---

## Prerequisites

- Docker and Docker Compose
- Python 3.10+
- OpenAI API key with GPT-4o access

## Setup

```bash
# Clone
git clone https://github.com/ASebFoy/adaptive-dast-orchestration.git
cd adaptive-dast-orchestration

# Environment
cp .env.example .env
# Edit .env → add your OpenAI API key

# Start containers
docker-compose up -d
# Wait ~30s for Juice Shop to initialise

# Python
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Provision test user
cd src && python setup_user.py
```

## Running Experiments

From the `src/` directory:

```bash
# Single agent run
python experiment_runner.py

# Full experiment — agent condition (n=10)
python overnight_agent.py --runs 10

# Full experiment — baseline condition (n=10)
python overnight_baseline.py --runs 10 \
  --config ../config/zap-injection-baseline.yaml
```

## Analysis

```bash
cd analysis

# Evaluate against ground truth
python evaluate.py \
  --results-dir ../results \
  --ground-truth ../config/ground_truth_injection.json

# Statistical analysis
python analyze_results.py \
  --evaluation ../results/evaluation.json
```

Pre-computed results from the thesis experiment are in `data/`.

---

## Ground Truth

Eight injection vulnerabilities in OWASP Juice Shop v17.1.1 (7 effective — 1 auth-gated entry excluded from recall denominator):

| ID | Type | Subtype | Endpoint | Auth |
|----|------|---------|----------|:----:|
| SQLI-LOGIN | SQL Injection | Authentication Bypass | `/rest/user/login` | No |
| SQLI-UNION-SCHEMA | SQL Injection | UNION-based Data Extraction | `/rest/products/search` | No |
| SQLI-BLIND-CHRISTMAS | SQL Injection | Blind SQL Injection | `/rest/products/search` | No |
| SQLI-EPHEMERAL | SQL Injection | Authentication Manipulation | `/rest/user/login` | No |
| SQLI-USER-CREDS | SQL Injection | Data Exfiltration | `/rest/products/search` | No |
| NOSQLI-DOS | NoSQL Injection | Denial of Service | `/rest/track-order` | No |
| NOSQLI-REVIEW | NoSQL Injection | Data Manipulation | `/rest/products/reviews` | **Yes** |
| NOSQLI-EXFIL | NoSQL Injection | Data Exfiltration | `/rest/track-order` | No |

See [`config/ground_truth_injection.json`](config/ground_truth_injection.json) for full definitions including payloads and CWE mappings.

---

## Technology Stack

| Component | Version | Role |
|-----------|---------|------|
| OWASP Juice Shop | v17.1.1 | Deliberately vulnerable target |
| OWASP ZAP | 2.15.0 | Security scanner |
| GPT-4o | 2024 | LLM reasoning engine |
| Python | 3.10+ | Orchestration & analysis |
| SciPy | 1.12.0 | Mann-Whitney U, Cliff's δ |

---

## Citation

```bibtex
@mastersthesis{foy2026adaptive,
  author  = {Foy, Anton Sebastian},
  title   = {Evaluating an {LLM}-Driven Vulnerability Discovery Agent Against 
             Traditional Web Application Scanners: A Design Science Approach},
  school  = {NOVA Information Management School},
  year    = {2026},
  type    = {{MSc} Thesis},
  address = {Lisbon, Portugal}
}
```

## License

MIT — see [LICENSE](LICENSE).

> **Note:** This artifact is for academic research. Always obtain proper authorisation before conducting security testing on any system.
