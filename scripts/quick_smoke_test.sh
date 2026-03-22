#!/bin/bash

echo "=== QUICK SMOKE TEST (5 min each) ==="
echo "Results will be saved to: results/debug/"

# Setup
set -a
source .env
set +a
source venv/bin/activate

mkdir -p results/debug/baseline
mkdir -p results/debug/agent

# Test 1: Baseline (5 min timeout)
echo ""
echo "=== Running Baseline Smoke Test (5 min max) ==="
./reset.sh

timeout 300 python3 baseline_runner.py \
  --output-dir results/debug/baseline \
  --run-id smoke_baseline_$(date +%Y%m%d_%H%M%S) || echo "Baseline: 5 min timeout reached"

# Test 2: Agent (5 min timeout)
echo ""
echo "=== Running Agent Smoke Test (5 min max) ==="
./reset.sh

timeout 300 python3 -c "
import os
from react_dast_agent import ReActDastAgent
from datetime import datetime
import json

config = {
    'zap_api_key': os.environ['ZAP_API_KEY'],
    'zap_url': os.environ.get('ZAP_URL', 'http://localhost:8080'),
    'openai_api_key': os.environ['OPENAI_API_KEY'],
    'target_url': os.environ.get('TARGET_URL', 'http://juice-shop:3000'),
    'max_iterations': 10,
    'max_tokens': 50000,
    'cost_limit_usd': 2.00,
    'time_limit_minutes': 5,
    'temperature': 0
}

agent = ReActDastAgent(config)
agent.setup_file_logging('results/debug/agent')
results = agent.run()

output_file = f'results/debug/agent/agent_smoke_{datetime.now().strftime(\"%Y%m%d_%H%M%S\")}.json'
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

agent.cleanup_file_logging()
print(f'Results: {output_file}')
" || echo "Agent: 5 min timeout reached"

# Show results
echo ""
echo "=== SMOKE TEST COMPLETE ==="
echo ""
echo "Baseline results:"
ls -lh results/debug/baseline/ 2>/dev/null | tail -1

echo ""
echo "Agent results:"
ls -lh results/debug/agent/ 2>/dev/null | tail -1

echo ""
echo "=== Quick Summary ==="

# Baseline summary
python3 -c "
import json, glob, os
files = glob.glob('results/debug/baseline/*.json')
if files:
    with open(files[-1]) as f:
        data = json.load(f)
    print('BASELINE:')
    print(f'  Alerts: {len(data.get(\"alerts\", []))}')
    print(f'  HTTP Requests: {data.get(\"http_requests\", 0)}')
    print(f'  Duration: {data.get(\"duration_minutes\", 0):.2f} min')
" 2>/dev/null

echo ""

# Agent summary
python3 -c "
import json, glob, os
files = glob.glob('results/debug/agent/*.json')
if files:
    with open(files[-1]) as f:
        data = json.load(f)
    print('AGENT:')
    print(f'  Alerts: {len(data.get(\"alerts\", []))}')
    print(f'  HTTP Requests: {data.get(\"http_requests\", 0)}')
    print(f'  Duration: {data.get(\"duration_minutes\", 0):.2f} min')
    print(f'  Iterations: {data.get(\"iterations\", 0)}')
    print(f'  Cost: \${data.get(\"cost_usd\", 0):.4f}')
    print(f'  Termination: {data.get(\"termination_reason\", \"unknown\")}')
" 2>/dev/null

echo ""
echo "Full results in: results/debug/"