#!/usr/bin/env python3
"""
Overnight Baseline Runner

Executes multiple baseline runs sequentially with automated reset between runs.
Designed for unattended overnight execution to collect all baseline data needed
for the thesis experiment.

Features:
    - Runs 5 baseline scans sequentially
    - Automated reset between runs using reset_environment.py
    - Comprehensive logging to file and console
    - Cost tracking (N/A for baseline but kept for consistency)
    - Error recovery with detailed diagnostics
    - Final summary with aggregated statistics

Usage:
    python overnight_baseline.py [--runs 5] [--output-dir ./results/baseline]
    
The script will:
    1. Validate environment
    2. For each run (1-5):
        a. Reset environment (Juice Shop + ZAP)
        b. Run baseline scan
        c. Log results
        d. Save individual run output
    3. Generate consolidated summary report
    
Recommended: Run inside tmux/screen for resilience against SSH disconnection:
    tmux new -s baseline
    python overnight_baseline.py
    # Detach: Ctrl+b, d
    # Reattach: tmux attach -t baseline
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
DEFAULT_OUTPUT_DIR = "./results/baseline"
DEFAULT_CONFIG = "configs/zap-injection-baseline.yaml"
DEFAULT_TIMEOUT_MINUTES = 60
RESET_SCRIPT = "reset_environment.py"


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(output_dir: str):
    """Configure logging to both file and console."""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(output_dir, f"overnight_baseline_{timestamp}.log")
    
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


def run_baseline(
    logger,
    run_id: int,
    config: str,
    output_dir: str,
    timeout_minutes: int
) -> Optional[dict]:
    """Execute a single baseline run."""
    logger.info(f"Starting baseline run {run_id}/{DEFAULT_NUM_RUNS}")
    
    cmd = [
        sys.executable,
        "baseline_runner.py",
        "--config", config,
        "--output-dir", output_dir,
        "--run-id", str(run_id),
        "--timeout", str(timeout_minutes),
        "--verbose"
    ]
    
    logger.info(f"Command: {' '.join(cmd)}")
    
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=(timeout_minutes + 5) * 60  # Add 5 min buffer
        )
        
        duration = time.time() - start
        
        if proc.returncode == 0:
            logger.info(f"âœ“ Baseline run {run_id} completed in {duration/60:.1f} minutes")
            
            # Find and load the output file
            output_files = sorted(
                Path(output_dir).glob(f"baseline_run_{run_id}_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            
            if output_files:
                with open(output_files[0]) as f:
                    result = json.load(f)
                    
                logger.info(f"  Results:")
                logger.info(f"    Injection alerts: {result['results']['injection_alerts']}")
                logger.info(f"    HTTP requests: {result['results']['http_requests']}")
                logger.info(f"    Duration: {result['duration_minutes']} min")
                logger.info(f"    Output: {output_files[0]}")
                
                return result
            else:
                logger.warning("âœ— Output file not found, but run succeeded")
                return None
        else:
            logger.error(f"âœ— Baseline run {run_id} failed (exit code {proc.returncode})")
            logger.error(f"Duration: {duration/60:.1f} minutes")
            logger.debug(f"STDOUT:\n{proc.stdout}")
            logger.debug(f"STDERR:\n{proc.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"âœ— Baseline run {run_id} timed out")
        return None
    except Exception as e:
        logger.error(f"âœ— Baseline run {run_id} error: {e}")
        return None


def generate_summary(logger, results: list, output_dir: str, start_time: float):
    """Generate and save final summary report."""
    log_section(logger, "OVERNIGHT BASELINE SUMMARY")
    
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
            run_id = result['run_id']
            alerts = result['results']['injection_alerts']
            requests = result['results']['http_requests']
            duration = result['duration_minutes']
            
            logger.info(f"  Run {run_id}: {alerts} alerts, {requests} requests, {duration:.1f} min")
        
        # Aggregate statistics
        logger.info("")
        logger.info("Aggregate Statistics:")
        logger.info("-" * 80)
        
        all_alerts = [r['results']['injection_alerts'] for r in successful_runs]
        all_requests = [r['results']['http_requests'] for r in successful_runs]
        all_durations = [r['duration_minutes'] for r in successful_runs]
        
        logger.info(f"  Injection Alerts: min={min(all_alerts)}, max={max(all_alerts)}, "
                   f"mean={sum(all_alerts)/len(all_alerts):.1f}")
        logger.info(f"  HTTP Requests: min={min(all_requests)}, max={max(all_requests)}, "
                   f"mean={sum(all_requests)/len(all_requests):.1f}")
        logger.info(f"  Duration (min): min={min(all_durations):.1f}, max={max(all_durations):.1f}, "
                   f"mean={sum(all_durations)/len(all_durations):.1f}")
    
    # Save summary to JSON
    summary = {
        "experiment": "baseline",
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
            }
        } if successful_runs else {}
    }
    
    summary_file = os.path.join(
        output_dir,
        f"baseline_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
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
        description="Run overnight baseline experiments with automated reset"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_NUM_RUNS,
        help=f"Number of baseline runs (default: {DEFAULT_NUM_RUNS})"
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help=f"ZAP config file (default: {DEFAULT_CONFIG})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_MINUTES,
        help=f"Timeout per run in minutes (default: {DEFAULT_TIMEOUT_MINUTES})"
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
    
    log_section(logger, "OVERNIGHT BASELINE EXPERIMENT STARTING")
    
    logger.info(f"Configuration:")
    logger.info(f"  Number of runs: {args.runs}")
    logger.info(f"  Output directory: {args.output_dir}")
    logger.info(f"  Config file: {args.config}")
    logger.info(f"  Timeout per run: {args.timeout} minutes")
    logger.info(f"  Log file: {log_file}")
    logger.info(f"  Starting from run: {args.start_from}")
    
    # Verify prerequisites
    if not os.path.exists(args.config):
        logger.error(f"Config file not found: {args.config}")
        return 1
    
    if not os.path.exists("baseline_runner.py"):
        logger.error("baseline_runner.py not found in current directory")
        return 1
    
    if not args.skip_reset and not os.path.exists(RESET_SCRIPT):
        logger.error(f"Reset script not found: {RESET_SCRIPT}")
        logger.error("Use --skip-reset to proceed without reset (not recommended)")
        return 1
    
    # Check environment variables
    required_env = ["ZAP_URL", "ZAP_API_KEY", "TARGET_URL"]
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
        log_section(logger, f"BASELINE RUN {run_id}/{args.runs}")
        
        # Reset environment (unless skipped or first run)
        if not args.skip_reset:
            if not run_reset(logger):
                logger.error(f"Aborting run {run_id} due to reset failure")
                results.append(None)
                continue
            
            # Brief pause after reset
            logger.info("Waiting 10s for services to stabilize...")
            time.sleep(10)
        
        # Run baseline
        result = run_baseline(
            logger,
            run_id=run_id,
            config=args.config,
            output_dir=args.output_dir,
            timeout_minutes=args.timeout
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