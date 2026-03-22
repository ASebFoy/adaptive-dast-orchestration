#!/usr/bin/env python3
"""
Overnight Agent Runner

Executes multiple ReAct DAST agent runs sequentially with automated reset between runs.
Designed for unattended overnight execution to collect all agent data needed
for the thesis experiment.

Features:
    - Runs 8 agent scans sequentially
    - Automated reset between runs using reset_environment.py
    - Comprehensive logging to file and console
    - Cost tracking and token usage monitoring
    - Error recovery with detailed diagnostics
    - Final summary with aggregated statistics

Usage:
    python3 overnight_agent.py [--runs 8] [--output-dir ./results/agent]
    
The script will:
    1. Validate environment
    2. For each run (1-8):
        a. Reset environment (Juice Shop + ZAP)
        b. Run agent scan
        c. Log results
        d. Save individual run output
    3. Generate consolidated summary report
    
Recommended: Run inside tmux/screen for resilience against SSH disconnection:
    tmux new -s agent
    python3 overnight_agent.py
    # Detach: Ctrl+b, d
    # Reattach: tmux attach -t agent
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_NUM_RUNS = 8
DEFAULT_OUTPUT_DIR = "./results/agent"
DEFAULT_TIMEOUT_MINUTES = 60
DEFAULT_MAX_ITERATIONS = 50
DEFAULT_MAX_TOKENS = 100000
DEFAULT_COST_LIMIT = 5.00
RESET_SCRIPT = "reset_environment.py"


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(output_dir: str):
    """Configure logging to both file and console."""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(output_dir, f"overnight_agent_{timestamp}.log")
    
    # File handler (detailed)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # Console handler (summary)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - [OVERNIGHT] - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    
    # Root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger, log_file


# =============================================================================
# Helper Functions
# =============================================================================

def log_section(logger, title: str):
    """Log a section header."""
    logger.info("")
    logger.info("=" * 80)
    logger.info(title)
    logger.info("=" * 80)


def run_reset(logger) -> bool:
    """Execute reset_environment.py to clean state."""
    logger.info("Executing environment reset...")
    
    if not os.path.exists(RESET_SCRIPT):
        logger.error(f"Reset script not found: {RESET_SCRIPT}")
        return False
    
    try:
        proc = subprocess.run(
            [sys.executable, RESET_SCRIPT],
            capture_output=True,
            text=True,
            timeout=300  # 5 min timeout for reset
        )
        
        if proc.returncode == 0:
            logger.info("âœ“ Environment reset successful")
            logger.debug(f"Reset output:\n{proc.stdout}")
            return True
        else:
            logger.error(f"âœ— Environment reset failed (exit code {proc.returncode})")
            logger.error(f"STDOUT:\n{proc.stdout}")
            logger.error(f"STDERR:\n{proc.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("âœ— Environment reset timed out after 5 minutes")
        return False
    except Exception as e:
        logger.error(f"âœ— Environment reset error: {e}")
        return False


def run_agent(
    logger,
    run_id: int,
    output_dir: str,
    timeout_minutes: int,
    max_iterations: int,
    max_tokens: int,
    cost_limit: float
) -> Optional[dict]:
    """Execute a single agent run."""
    logger.info(f"Starting agent run {run_id}/{DEFAULT_NUM_RUNS}")
    
    # Create inline Python script for agent execution
    agent_code = f"""
import os
import sys
from react_dast_agent import ReActDastAgent
from datetime import datetime
import json

config = {{
    'zap_api_key': os.environ['ZAP_API_KEY'],
    'zap_url': os.environ.get('ZAP_URL', 'http://localhost:8080'),
    'openai_api_key': os.environ['OPENAI_API_KEY'],
    'target_url': os.environ.get('TARGET_URL', 'http://juice-shop:3000'),
    'max_iterations': {max_iterations},
    'max_tokens': {max_tokens},
    'cost_limit_usd': {cost_limit},
    'time_limit_minutes': {timeout_minutes},
    'temperature': 0
}}

try:
    agent = ReActDastAgent(config)
    agent.setup_file_logging('{output_dir}')
    results = agent.run()
    
    # Add run_id to results
    results['run_id'] = {run_id}
    results['condition'] = 'agent'
    
    output_file = os.path.join(
        '{output_dir}',
        f'agent_run_{run_id}_{{datetime.now().strftime("%Y%m%d_%H%M%S")}}.json'
    )
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    agent.cleanup_file_logging()
    print(f'AGENT_OUTPUT_FILE:{{output_file}}')
    sys.exit(0)
    
except Exception as e:
    print(f'AGENT_ERROR:{{e}}', file=sys.stderr)
    sys.exit(1)
"""
    
    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", agent_code],
            capture_output=True,
            text=True,
            timeout=(timeout_minutes + 5) * 60  # Add 5 min buffer
        )
        
        duration = time.time() - start
        
        if proc.returncode == 0:
            logger.info(f"âœ“ Agent run {run_id} completed in {duration/60:.1f} minutes")
            
            # Extract output file from stdout
            output_file = None
            for line in proc.stdout.split('\n'):
                if line.startswith('AGENT_OUTPUT_FILE:'):
                    output_file = line.split(':', 1)[1]
                    break
            
            if output_file and os.path.exists(output_file):
                with open(output_file) as f:
                    result = json.load(f)
                    
                logger.info(f"  Results:")
                logger.info(f"    Injection alerts: {len(result.get('alerts', []))}")
                logger.info(f"    HTTP requests: {result.get('http_requests', 0)}")
                logger.info(f"    Duration: {result.get('duration_minutes', 0):.1f} min")
                logger.info(f"    Iterations: {result.get('iterations', 0)}")
                logger.info(f"    Cost: ${result.get('cost_usd', 0):.4f}")
                logger.info(f"    Termination: {result.get('termination_reason', 'unknown')}")
                logger.info(f"    Output: {output_file}")
                
                return result
            else:
                # Fallback: try to find most recent file
                output_files = sorted(
                    Path(output_dir).glob(f"agent_run_{run_id}_*.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                )
                
                if output_files:
                    with open(output_files[0]) as f:
                        result = json.load(f)
                    logger.info(f"  Found output: {output_files[0]}")
                    return result
                else:
                    logger.warning("âœ— Output file not found, but run succeeded")
                    return None
        else:
            logger.error(f"âœ— Agent run {run_id} failed (exit code {proc.returncode})")
            logger.error(f"Duration: {duration/60:.1f} minutes")
            logger.debug(f"STDOUT:\n{proc.stdout}")
            logger.debug(f"STDERR:\n{proc.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"âœ— Agent run {run_id} timed out")
        return None
    except Exception as e:
        logger.error(f"âœ— Agent run {run_id} error: {e}")
        return None


def generate_summary(logger, results: list, output_dir: str, start_time: float):
    """Generate and save final summary report."""
    log_section(logger, "OVERNIGHT AGENT SUMMARY")
    
    total_duration = time.time() - start_time
    successful_runs = [r for r in results if r is not None]
    
    logger.info(f"Total runs attempted: {len(results)}")
    logger.info(f"Successful runs: {len(successful_runs)}")
    logger.info(f"Failed runs: {len(results) - len(successful_runs)}")
    logger.info(f"Total duration: {total_duration/3600:.2f} hours")
    
    if successful_runs:
        logger.info("")
        logger.info("Individual Run Results:")
        logger.info("-" * 80)
        
        for result in successful_runs:
            run_id = result.get('run_id', '?')
            alerts = len(result.get('alerts', []))
            requests = result.get('http_requests', 0)
            duration = result.get('duration_minutes', 0)
            cost = result.get('cost_usd', 0)
            iterations = result.get('iterations', 0)
            termination = result.get('termination_reason', 'unknown')
            
            logger.info(f"  Run {run_id}: {alerts} alerts, {requests} requests, "
                       f"{duration:.1f} min, ${cost:.2f}, {iterations} iter, {termination}")
        
        # Aggregate statistics
        logger.info("")
        logger.info("Aggregate Statistics:")
        logger.info("-" * 80)
        
        all_alerts = [len(r.get('alerts', [])) for r in successful_runs]
        all_requests = [r.get('http_requests', 0) for r in successful_runs]
        all_durations = [r.get('duration_minutes', 0) for r in successful_runs]
        all_costs = [r.get('cost_usd', 0) for r in successful_runs]
        all_iterations = [r.get('iterations', 0) for r in successful_runs]
        
        logger.info(f"  Injection Alerts: min={min(all_alerts)}, max={max(all_alerts)}, "
                   f"mean={sum(all_alerts)/len(all_alerts):.1f}")
        logger.info(f"  HTTP Requests: min={min(all_requests)}, max={max(all_requests)}, "
                   f"mean={sum(all_requests)/len(all_requests):.1f}")
        logger.info(f"  Duration (min): min={min(all_durations):.1f}, max={max(all_durations):.1f}, "
                   f"mean={sum(all_durations)/len(all_durations):.1f}")
        logger.info(f"  Cost (USD): min=${min(all_costs):.2f}, max=${max(all_costs):.2f}, "
                   f"mean=${sum(all_costs)/len(all_costs):.2f}, total=${sum(all_costs):.2f}")
        logger.info(f"  Iterations: min={min(all_iterations)}, max={max(all_iterations)}, "
                   f"mean={sum(all_iterations)/len(all_iterations):.1f}")
    
    # Save summary to JSON
    summary = {
        "experiment": "agent",
        "timestamp": datetime.now().isoformat(),
        "total_duration_hours": round(total_duration / 3600, 2),
        "runs_attempted": len(results),
        "runs_successful": len(successful_runs),
        "runs_failed": len(results) - len(successful_runs),
        "results": successful_runs,
        "statistics": {
            "alerts": {
                "values": all_alerts,
                "min": min(all_alerts) if all_alerts else 0,
                "max": max(all_alerts) if all_alerts else 0,
                "mean": sum(all_alerts) / len(all_alerts) if all_alerts else 0
            },
            "http_requests": {
                "values": all_requests,
                "min": min(all_requests) if all_requests else 0,
                "max": max(all_requests) if all_requests else 0,
                "mean": sum(all_requests) / len(all_requests) if all_requests else 0
            },
            "duration_minutes": {
                "values": all_durations,
                "min": min(all_durations) if all_durations else 0,
                "max": max(all_durations) if all_durations else 0,
                "mean": sum(all_durations) / len(all_durations) if all_durations else 0
            },
            "cost_usd": {
                "values": all_costs,
                "min": min(all_costs) if all_costs else 0,
                "max": max(all_costs) if all_costs else 0,
                "mean": sum(all_costs) / len(all_costs) if all_costs else 0,
                "total": sum(all_costs) if all_costs else 0
            },
            "iterations": {
                "values": all_iterations,
                "min": min(all_iterations) if all_iterations else 0,
                "max": max(all_iterations) if all_iterations else 0,
                "mean": sum(all_iterations) / len(all_iterations) if all_iterations else 0
            }
        } if successful_runs else {}
    }
    
    summary_file = os.path.join(
        output_dir,
        f"agent_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("")
    logger.info(f"Summary saved to: {summary_file}")
    logger.info("=" * 80)


# =============================================================================
# Main Execution
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run overnight agent experiments with automated reset"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_NUM_RUNS,
        help=f"Number of agent runs (default: {DEFAULT_NUM_RUNS})"
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_MINUTES,
        help=f"Timeout per run in minutes (default: {DEFAULT_TIMEOUT_MINUTES})"
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_MAX_ITERATIONS,
        help=f"Max iterations per run (default: {DEFAULT_MAX_ITERATIONS})"
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Max tokens per run (default: {DEFAULT_MAX_TOKENS})"
    )
    parser.add_argument(
        "--cost-limit",
        type=float,
        default=DEFAULT_COST_LIMIT,
        help=f"Cost limit per run in USD (default: {DEFAULT_COST_LIMIT})"
    )
    parser.add_argument(
        "--skip-reset",
        action="store_true",
        help="Skip environment reset between runs (for debugging only)"
    )
    parser.add_argument(
        "--start-from",
        type=int,
        default=1,
        help="Start from run N (for recovery after failure)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger, log_file = setup_logging(args.output_dir)
    
    log_section(logger, "OVERNIGHT AGENT EXPERIMENT STARTING")
    
    logger.info(f"Configuration:")
    logger.info(f"  Number of runs: {args.runs}")
    logger.info(f"  Output directory: {args.output_dir}")
    logger.info(f"  Timeout per run: {args.timeout} minutes")
    logger.info(f"  Max iterations: {args.max_iterations}")
    logger.info(f"  Max tokens: {args.max_tokens}")
    logger.info(f"  Cost limit: ${args.cost_limit}")
    logger.info(f"  Log file: {log_file}")
    logger.info(f"  Starting from run: {args.start_from}")
    
    # Verify prerequisites
    if not os.path.exists("react_dast_agent.py"):
        logger.error("react_dast_agent.py not found in current directory")
        return 1
    
    if not args.skip_reset and not os.path.exists(RESET_SCRIPT):
        logger.error(f"Reset script not found: {RESET_SCRIPT}")
        logger.error("Use --skip-reset to proceed without reset (not recommended)")
        return 1
    
    # Check environment variables
    required_env = ["ZAP_URL", "ZAP_API_KEY", "TARGET_URL", "OPENAI_API_KEY"]
    missing_env = [var for var in required_env if not os.getenv(var)]
    
    if missing_env:
        logger.error(f"Missing environment variables: {', '.join(missing_env)}")
        logger.error("Load .env file: set -a; source .env; set +a")
        return 1
    
    logger.info("âœ“ Prerequisites verified")
    
    # Execute runs
    start_time = time.time()
    results = []
    
    for run_id in range(args.start_from, args.runs + 1):
        log_section(logger, f"AGENT RUN {run_id}/{args.runs}")
        
        # Reset environment (unless skipped)
        if not args.skip_reset:
            if not run_reset(logger):
                logger.error(f"Aborting run {run_id} due to reset failure")
                results.append(None)
                continue
            
            # Brief pause after reset
            logger.info("Waiting 10s for services to stabilize...")
            time.sleep(10)
        
        # Run agent
        result = run_agent(
            logger,
            run_id=run_id,
            output_dir=args.output_dir,
            timeout_minutes=args.timeout,
            max_iterations=args.max_iterations,
            max_tokens=args.max_tokens,
            cost_limit=args.cost_limit
        )
        
        results.append(result)
        
        # Brief pause between runs
        if run_id < args.runs:
            logger.info("Waiting 30s before next run...")
            time.sleep(30)
    
    # Generate summary
    generate_summary(logger, results, args.output_dir, start_time)
    
    # Exit code
    successful = sum(1 for r in results if r is not None)
    if successful == args.runs:
        logger.info("âœ“ ALL RUNS COMPLETED SUCCESSFULLY")
        return 0
    elif successful > 0:
        logger.warning(f"âš  PARTIAL SUCCESS: {successful}/{args.runs} runs completed")
        return 0  # Still success if we got some data
    else:
        logger.error("âœ— ALL RUNS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())