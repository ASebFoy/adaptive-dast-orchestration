#!/usr/bin/env python3
"""
Experiment Runner: Orchestrates Complete Thesis Experiment

This script manages the full experimental protocol:
    - 5 baseline runs (ZAP Automation Framework)
    - 5 agent runs (LLM-driven ReAct orchestration)

Each run includes:
    - Clean state reset (ZAP session, Juice Shop state)
    - Test user setup
    - Execution with timeout and resource limits
    - Result collection and storage

Usage:
    python experiment_runner.py --runs 5 --output-dir ./results
    
    # Run only baseline
    python experiment_runner.py --condition baseline --runs 5
    
    # Run only agent
    python experiment_runner.py --condition agent --runs 5

Author: Thesis Experiment Infrastructure
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

import requests
from zapv2 import ZAPv2

# Import local modules
from setup_user import setup_test_user
from baseline_runner import run_baseline

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_ZAP_URL = "http://localhost:8080"
DEFAULT_TARGET_URL = "http://localhost:3000"
DEFAULT_ZAP_API_KEY = "thesis-zap-api-key"
DEFAULT_OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DEFAULT_OUTPUT_DIR = "./results"
DEFAULT_RUNS_PER_CONDITION = 5
DEFAULT_BASELINE_TIMEOUT = 60  # minutes
DEFAULT_AGENT_BUFFER = 15  # minutes added to average baseline duration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# State Management
# =============================================================================

def reset_juice_shop(target_url: str) -> bool:
    """
    Reset Juice Shop to clean state by restarting the Docker container.
    
    Juice Shop accumulates solved challenges, orders, and user data across
    requests. Restarting the container ensures each experimental run starts
    from an identical application state, preventing prior runs from
    influencing spider discovery or endpoint behavior.
    
    Args:
        target_url: Juice Shop URL
        
    Returns:
        True if reset successful
    """
    logger.info("Resetting Juice Shop state via container restart...")
    
    try:
        # Restart only the Juice Shop container (preserves ZAP state,
        # which is reset separately via reset_zap_session)
        result = subprocess.run(
            ["docker-compose", "restart", "juice-shop"],
            capture_output=True,
            timeout=90
        )
        
        if result.returncode != 0:
            logger.warning(
                f"Docker restart command returned {result.returncode}: "
                f"{result.stderr.decode()[:200]}. Falling back to connectivity check."
            )
        
        # Wait for Juice Shop to become healthy again
        logger.info("Waiting for Juice Shop to become healthy...")
        max_retries = 30
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    f"{target_url}/rest/admin/application-version",
                    timeout=5
                )
                if response.status_code == 200:
                    version = response.json().get("version", "unknown")
                    logger.info(f"Juice Shop v{version} is ready after restart")
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(2)
        
        logger.error(f"Juice Shop not available after {max_retries} retries")
        return False
        
    except subprocess.TimeoutExpired:
        logger.error("Docker restart timed out")
        return False
    except FileNotFoundError:
        # docker-compose not available â€” fall back to connectivity check
        logger.warning(
            "docker-compose not found; skipping container restart. "
            "Falling back to connectivity check only."
        )
        try:
            response = requests.get(
                f"{target_url}/rest/admin/application-version",
                timeout=10
            )
            if response.status_code == 200:
                logger.info("Juice Shop is accessible (no restart performed)")
                return True
            return False
        except Exception as e:
            logger.error(f"Juice Shop connectivity check failed: {e}")
            return False


def reset_zap_session(zap: ZAPv2) -> bool:
    """
    Clear ZAP session completely.
    
    Args:
        zap: ZAPv2 client
        
    Returns:
        True if reset successful
    """
    logger.info("Resetting ZAP session...")
    
    try:
        # Create new session
        zap.core.new_session(overwrite=True)
        
        # Verify clean state
        alerts = zap.core.number_of_alerts()
        messages = zap.core.number_of_messages()
        
        logger.info(f"ZAP session reset: {alerts} alerts, {messages} messages")
        return True
        
    except Exception as e:
        logger.error(f"ZAP session reset failed: {e}")
        return False


def restart_docker_services() -> bool:
    """
    Restart Docker services for complete clean state.
    
    Returns:
        True if restart successful
    """
    logger.info("Restarting Docker services...")
    
    try:
        # Stop services
        subprocess.run(
            ["docker-compose", "down", "-v"],
            capture_output=True,
            timeout=60
        )
        
        # Wait a moment
        time.sleep(5)
        
        # Start services
        result = subprocess.run(
            ["docker-compose", "up", "-d"],
            capture_output=True,
            timeout=120
        )
        
        if result.returncode != 0:
            logger.error(f"Docker restart failed: {result.stderr.decode()}")
            return False
        
        # Wait for services to be healthy
        logger.info("Waiting for services to be healthy...")
        time.sleep(30)
        
        return True
        
    except Exception as e:
        logger.error(f"Docker restart failed: {e}")
        return False


# =============================================================================
# Experiment Execution
# =============================================================================

def run_agent_experiment(
    zap_url: str,
    zap_api_key: str,
    target_url: str,
    openai_api_key: str,
    output_dir: str,
    run_id: int,
    timeout_minutes: int
) -> dict:
    """
    Execute a single agent run.
    
    Args:
        zap_url: ZAP API URL
        zap_api_key: ZAP API key
        target_url: Target application URL
        openai_api_key: OpenAI API key
        output_dir: Output directory
        run_id: Run identifier
        timeout_minutes: Maximum execution time
        
    Returns:
        Dictionary with run results
    """
    logger.info("=" * 60)
    logger.info(f"AGENT RUN {run_id}")
    logger.info("=" * 60)
    
    start_time = time.time()
    timestamp = datetime.now().isoformat()
    
    try:
        # Import agent module
        from react_dast_agent import ReActDastAgent
        
        # Configure agent
        config = {
            "zap_api_key": zap_api_key,
            "zap_url": zap_url,
            "openai_api_key": openai_api_key,
            "target_url": target_url,
            "max_iterations": 50,
            "max_tokens": 100000,
            "time_limit_minutes": timeout_minutes,
            "temperature": 0
        }
        
        # Run agent
        agent = ReActDastAgent(config)
        agent.setup_file_logging(output_dir)
        results = agent.run()
        agent.cleanup_file_logging()
        
        duration = time.time() - start_time
        
        # Compile output
        output = {
            "run_id": run_id,
            "condition": "agent",
            "timestamp": timestamp,
            "duration_minutes": round(duration / 60, 2),
            "duration_seconds": round(duration, 2),
            "target_url": target_url,
            "results": {
                "alerts": results.get("alerts", []),
                "injection_alerts": len(results.get("alerts", [])),
                "http_requests": results.get("http_requests", 0),
                "iterations": results.get("iterations", 0),
                "tokens_used": results.get("tokens_used", 0),
                "termination_reason": results.get("termination_reason", "unknown")
            },
            "transcript": results.get("transcript", []),
            "summary": results.get("summary", {})
        }
        
        # Save output
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(
            output_dir,
            f"agent_run_{run_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        logger.info("=" * 60)
        logger.info(f"AGENT RUN {run_id} COMPLETE")
        logger.info(f"Duration: {output['duration_minutes']} minutes")
        logger.info(f"Injection alerts: {output['results']['injection_alerts']}")
        logger.info(f"HTTP requests: {output['results']['http_requests']}")
        logger.info(f"Iterations: {output['results']['iterations']}")
        logger.info(f"Tokens used: {output['results']['tokens_used']}")
        logger.info(f"Results saved to: {output_file}")
        logger.info("=" * 60)
        
        output["success"] = True
        output["output_file"] = output_file
        
        return output
        
    except Exception as e:
        logger.error(f"Agent run failed: {e}")
        return {
            "success": False,
            "run_id": run_id,
            "condition": "agent",
            "error": str(e)
        }


def calculate_agent_timeout(baseline_results: list) -> int:
    """
    Calculate agent timeout based on baseline results.
    
    Formula: Maximum baseline duration + 15 minutes buffer
    Per Decision Document Â§4.2: "Time cap: Baseline maximum duration + 15 minutes"
    
    Args:
        baseline_results: List of baseline run results
        
    Returns:
        Timeout in minutes
    """
    if not baseline_results:
        return DEFAULT_BASELINE_TIMEOUT + DEFAULT_AGENT_BUFFER
    
    durations = [r.get("duration_minutes", DEFAULT_BASELINE_TIMEOUT) 
                 for r in baseline_results if r.get("success")]
    
    if not durations:
        return DEFAULT_BASELINE_TIMEOUT + DEFAULT_AGENT_BUFFER
    
    max_duration = max(durations)
    timeout = int(max_duration + 0.999) + DEFAULT_AGENT_BUFFER  # round up, not truncate
    
    logger.info(f"Calculated agent timeout: {timeout} minutes (max baseline: {max_duration:.1f} + {DEFAULT_AGENT_BUFFER} buffer)")
    
    return timeout


def run_experiment(
    zap_url: str,
    zap_api_key: str,
    target_url: str,
    openai_api_key: str,
    baseline_config: str,
    output_dir: str,
    num_runs: int,
    condition: Optional[str] = None,
    skip_docker_restart: bool = False
) -> dict:
    """
    Run the complete experiment.
    
    Args:
        zap_url: ZAP API URL
        zap_api_key: ZAP API key
        target_url: Target application URL
        openai_api_key: OpenAI API key
        baseline_config: Path to baseline YAML config
        output_dir: Output directory
        num_runs: Number of runs per condition
        condition: Run only specific condition ('baseline' or 'agent')
        skip_docker_restart: Skip Docker restart between runs
        
    Returns:
        Dictionary with experiment results
    """
    logger.info("=" * 70)
    logger.info("THESIS EXPERIMENT: Adaptive DAST Orchestration")
    logger.info("=" * 70)
    logger.info(f"Conditions: {'baseline only' if condition == 'baseline' else 'agent only' if condition == 'agent' else 'both (baseline + agent)'}")
    logger.info(f"Runs per condition: {num_runs}")
    logger.info(f"Output directory: {output_dir}")
    logger.info("=" * 70)
    
    experiment_start = time.time()
    timestamp = datetime.now().isoformat()
    
    # Initialize ZAP client
    zap = ZAPv2(
        apikey=zap_api_key,
        proxies={"http": zap_url, "https": zap_url}
    )
    
    baseline_results = []
    agent_results = []
    
    # ==========================================================================
    # Phase 1: Baseline Runs
    # ==========================================================================
    
    if condition in [None, "baseline"]:
        logger.info("\n" + "=" * 70)
        logger.info("PHASE 1: BASELINE RUNS")
        logger.info("=" * 70)
        
        baseline_output_dir = os.path.join(output_dir, "baseline")
        
        for run_id in range(1, num_runs + 1):
            logger.info(f"\n--- Preparing baseline run {run_id}/{num_runs} ---")
            
            # Reset state
            if not skip_docker_restart and run_id > 1:
                # For subsequent runs, do a full reset
                reset_zap_session(zap)
            else:
                reset_zap_session(zap)
            
            # Reset Juice Shop and setup user
            reset_juice_shop(target_url)
            setup_result = setup_test_user(target_url)
            
            if not setup_result.get("success"):
                logger.error(f"Failed to setup test user for run {run_id}")
                baseline_results.append({
                    "success": False,
                    "run_id": run_id,
                    "error": "Test user setup failed"
                })
                continue
            
            # Run baseline
            result = run_baseline(
                zap_url=zap_url,
                zap_api_key=zap_api_key,
                target_url=target_url,
                config_file=baseline_config,
                output_dir=baseline_output_dir,
                run_id=run_id,
                timeout_minutes=DEFAULT_BASELINE_TIMEOUT
            )
            
            baseline_results.append(result)
            
            # Brief pause between runs
            if run_id < num_runs:
                logger.info("Pausing before next run...")
                time.sleep(10)
    
    # ==========================================================================
    # Phase 2: Agent Runs
    # ==========================================================================
    
    if condition in [None, "agent"]:
        logger.info("\n" + "=" * 70)
        logger.info("PHASE 2: AGENT RUNS")
        logger.info("=" * 70)
        
        # Calculate timeout from baseline results
        agent_timeout = calculate_agent_timeout(baseline_results)
        
        agent_output_dir = os.path.join(output_dir, "agent")
        
        for run_id in range(1, num_runs + 1):
            logger.info(f"\n--- Preparing agent run {run_id}/{num_runs} ---")
            
            # Reset state
            reset_zap_session(zap)
            reset_juice_shop(target_url)
            
            # Setup user
            setup_result = setup_test_user(target_url)
            
            if not setup_result.get("success"):
                logger.error(f"Failed to setup test user for run {run_id}")
                agent_results.append({
                    "success": False,
                    "run_id": run_id,
                    "error": "Test user setup failed"
                })
                continue
            
            # Run agent
            result = run_agent_experiment(
                zap_url=zap_url,
                zap_api_key=zap_api_key,
                target_url=target_url,
                openai_api_key=openai_api_key,
                output_dir=agent_output_dir,
                run_id=run_id,
                timeout_minutes=agent_timeout
            )
            
            agent_results.append(result)
            
            # Brief pause between runs
            if run_id < num_runs:
                logger.info("Pausing before next run...")
                time.sleep(10)
    
    # ==========================================================================
    # Compile Experiment Summary
    # ==========================================================================
    
    experiment_duration = time.time() - experiment_start
    
    summary = {
        "experiment_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "timestamp": timestamp,
        "duration_minutes": round(experiment_duration / 60, 2),
        "configuration": {
            "target_url": target_url,
            "zap_url": zap_url,
            "runs_per_condition": num_runs,
            "baseline_timeout_minutes": DEFAULT_BASELINE_TIMEOUT,
            "agent_timeout_minutes": calculate_agent_timeout(baseline_results)
        },
        "baseline": {
            "total_runs": len(baseline_results),
            "successful_runs": sum(1 for r in baseline_results if r.get("success")),
            "results": baseline_results
        },
        "agent": {
            "total_runs": len(agent_results),
            "successful_runs": sum(1 for r in agent_results if r.get("success")),
            "results": agent_results
        }
    }
    
    # Save summary
    os.makedirs(output_dir, exist_ok=True)
    summary_file = os.path.join(output_dir, f"experiment_summary_{summary['experiment_id']}.json")
    
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("\n" + "=" * 70)
    logger.info("EXPERIMENT COMPLETE")
    logger.info("=" * 70)
    logger.info(f"Total duration: {summary['duration_minutes']} minutes")
    logger.info(f"Baseline: {summary['baseline']['successful_runs']}/{summary['baseline']['total_runs']} successful")
    logger.info(f"Agent: {summary['agent']['successful_runs']}/{summary['agent']['total_runs']} successful")
    logger.info(f"Summary saved to: {summary_file}")
    logger.info("=" * 70)
    
    return summary


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run thesis experiment: Adaptive DAST Orchestration"
    )
    parser.add_argument(
        "--zap-url",
        default=os.environ.get("ZAP_URL", DEFAULT_ZAP_URL),
        help=f"ZAP API URL (default: {DEFAULT_ZAP_URL})"
    )
    parser.add_argument(
        "--zap-api-key",
        default=os.environ.get("ZAP_API_KEY", DEFAULT_ZAP_API_KEY),
        help="ZAP API key"
    )
    parser.add_argument(
        "--target-url",
        default=os.environ.get("TARGET_URL", DEFAULT_TARGET_URL),
        help=f"Target application URL (default: {DEFAULT_TARGET_URL})"
    )
    parser.add_argument(
        "--openai-api-key",
        default=os.environ.get("OPENAI_API_KEY", ""),
        help="OpenAI API key (required for agent runs)"
    )
    parser.add_argument(
        "--baseline-config",
        default="zap-injection-baseline.yaml",
        help="Baseline automation framework config"
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS_PER_CONDITION,
        help=f"Runs per condition (default: {DEFAULT_RUNS_PER_CONDITION})"
    )
    parser.add_argument(
        "--condition",
        choices=["baseline", "agent"],
        help="Run only specific condition"
    )
    parser.add_argument(
        "--skip-docker-restart",
        action="store_true",
        help="Skip Docker restart between runs"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate OpenAI key for agent runs
    if args.condition in [None, "agent"] and not args.openai_api_key:
        print("ERROR: OPENAI_API_KEY is required for agent runs")
        print("Set via --openai-api-key or OPENAI_API_KEY environment variable")
        sys.exit(1)
    
    result = run_experiment(
        zap_url=args.zap_url,
        zap_api_key=args.zap_api_key,
        target_url=args.target_url,
        openai_api_key=args.openai_api_key,
        baseline_config=args.baseline_config,
        output_dir=args.output_dir,
        num_runs=args.runs,
        condition=args.condition,
        skip_docker_restart=args.skip_docker_restart
    )
    
    # Exit based on success
    baseline_success = result["baseline"]["successful_runs"] == result["baseline"]["total_runs"]
    agent_success = result["agent"]["successful_runs"] == result["agent"]["total_runs"]
    
    if baseline_success and agent_success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()