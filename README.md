# Adaptive DAST Orchestration: LLM-Driven Vulnerability Discovery

> **MSc Thesis Artifact** — Design Science Research  
> NOVA Information Management School — MSc in Information Technology Management (Cybersecurity)

## Overview

This repository contains the experimental artifact for an MSc thesis evaluating whether a GPT-4o-powered ReAct agent can improve injection vulnerability detection compared to a static OWASP ZAP Automation Framework baseline. The research follows a Design Science Research methodology, with OWASP Juice Shop as the target application.

The core artefact is a **ReAct (Reasoning + Acting) agent** that uses GPT-4o to autonomously drive OWASP ZAP scanning decisions, evaluated against a **fixed YAML-configured ZAP Automation Framework baseline** across n=10 independent runs per condition.

## Key Results

| Metric | Agent (n=10) | Baseline (n=10) |
|--------|:------------:|:----------------:|
| **Recall** | 42.9% | 28.6% |
| **Precision** | 100% | 100% |
| **Cliff's δ** | 1.0 (large) | — |
| **HTTP Requests** | ~26× more | — |

**Emergent Finding — Completion Declaration Pattern:** The agent accurately self-assessed task completion but continued executing post-declaration, consuming approximately 67.2% of total API expenditure with zero additional vulnerability detections.

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
                                              │  (Target)    │
                                              └──────────────┘
```

- **Agent condition:** GPT-4o ReAct loop → ZAP API tool calls → iterative, adaptive scanning
- **Baseline condition:** ZAP Automation Framework with fixed YAML configuration
- **Target:** OWASP Juice Shop v17.1.1 (7 ground-truth injection vulnerabilities)
- **Design:** n=10 independent runs per condition, full environment reset between runs

## Repository Structure

```
├── README.md
├── LICENSE
├── .env.example                 # Environment variables template
├── .gitignore
├── docker-compose.yml           # Juice Shop + ZAP containers
├── requirements.txt             # Python dependencies (pinned)
├── requirements-dev.txt         # Dev/test dependencies
│
├── src/                         # Core experiment code
│   ├── react_dast_agent.py      # ReAct agent implementation
│   ├── tools.py                 # ZAP API tool abstraction layer
│   ├── baseline_runner.py       # ZAP Automation Framework runner
│   ├── experiment_runner.py     # Single-run orchestrator (both conditions)
│   ├── overnight_agent.py       # Batch runner — agent condition (n=10)
│   ├── overnight_baseline.py    # Batch runner — baseline condition (n=10)
│   ├── setup_user.py            # Juice Shop test user provisioning
│   └── reset_environment.py     # Environment reset between runs
│
├── analysis/                    # Post-experiment analysis
│   ├── evaluate.py              # Ground truth matching & scoring
│   └── analyze_results.py       # Statistical tests (Mann-Whitney U, Cliff's δ)
│
├── config/                      # Configuration files
│   ├── ground_truth_injection.json   # 7 injection vulnerability definitions
│   └── zap-injection-baseline.yaml   # ZAP Automation Framework scan config
│
├── data/                        # Experimental results
│   ├── agent_consolidated_summary.json   # All 10 agent runs (alerts, transcripts, costs)
│   ├── baseline_consolidated_summary.json # All 10 baseline runs
│   ├── agent_traces.json                  # Agent action sequences & phase analysis
│   ├── completion_declaration_analysis.json # Completion Declaration Pattern data
│   ├── evaluation.json                    # Ground truth evaluation results
│   └── analysis.json                      # Statistical analysis output
│
└── tables/                      # Processed CSV tables (thesis-ready)
    ├── table_baseline_timing.csv
    ├── table_agent_phase_timing.csv
    ├── table_cost_breakdown.csv
    └── table_agent_action_distribution.csv
```

## Prerequisites

- **Docker** and **Docker Compose**
- **Python 3.10+**
- **OpenAI API key** with GPT-4o access

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/ASebFoy/adaptive-dast-orchestration.git
cd adaptive-dast-orchestration

# 2. Configure environment
cp .env.example .env
# Edit .env and add your OpenAI API key

# 3. Start Docker services
docker-compose up -d
# Wait ~30s for Juice Shop to initialise

# 4. Install Python dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 5. Provision test user in Juice Shop
cd src && python setup_user.py
```

## Running Experiments

All commands assume you are in the `src/` directory with the virtual environment activated.

```bash
# Single agent run
python experiment_runner.py

# Batch: agent condition (n=10)
python overnight_agent.py --runs 10

# Batch: baseline condition (n=10)
python overnight_baseline.py --runs 10 \
  --config ../config/zap-injection-baseline.yaml
```

## Analysis

```bash
# Evaluate raw results against ground truth
cd analysis
python evaluate.py \
  --results-dir ../results \
  --ground-truth ../config/ground_truth_injection.json

# Statistical analysis
python analyze_results.py \
  --evaluation ../results/evaluation.json
```

Pre-computed results from the thesis experiment are available in `data/`.

## Ground Truth

Seven injection vulnerabilities in OWASP Juice Shop v17.1.1, defined in [`config/ground_truth_injection.json`](config/ground_truth_injection.json):

| ID | Type | Endpoint | Auth Required |
|----|------|----------|:-------------:|
| SQLI-LOGIN | SQL Injection | `/rest/user/login` | No |
| SQLI-SEARCH | SQL Injection | `/rest/products/search` | No |
| SQLI-USER-LOGIN-IP | SQL Injection | `/rest/user/login` (union) | No |
| NOSQLI-REVIEWS | NoSQL Injection | `/rest/products/reviews` | Yes |
| NOSQLI-SLEEP | NoSQL Injection | `/rest/products/reviews` | Yes |
| SSJI-PRODUCT-REVIEWS | Server-Side JS Injection | `/rest/products/reviews` | Yes |
| SQLI-ORDER-BY | SQL Injection | `/rest/products/search` | No |

## Technology Stack

| Component | Version |
|-----------|---------|
| OWASP Juice Shop | v17.1.1 |
| OWASP ZAP | 2.15.0 |
| GPT-4o | 2024 release |
| Python | 3.10+ |
| SciPy | 1.12.0 |

## Citation

```bibtex
@mastersthesis{foy2026adaptive,
  author  = {Foy, Anton Sebastian},
  title   = {Evaluating an {LLM}-Driven Vulnerability Discovery Agent Against 
             Traditional Web Application Scanners: A Design Science Approach},
  school  = {NOVA Information Management School},
  year    = {2026},
  type    = {MSc Thesis},
  address = {Lisbon, Portugal}
}
```

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

**Note:** This artifact is provided for academic research purposes. Always obtain proper authorisation before conducting security testing on any system.
