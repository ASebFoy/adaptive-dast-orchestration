#!/usr/bin/env python3
"""
Baseline Runner for ZAP Automation Framework

Executes the baseline condition using ZAP's built-in automation framework
with a predetermined YAML configuration. This represents the fixed-workflow
automation approach against which the LLM-agent orchestration is compared.

Usage:
    python baseline_runner.py --config zap-injection-baseline.yaml --output-dir ./results
    
The runner will:
    1. Verify ZAP and Juice Shop connectivity
    2. Clear ZAP session for clean state
    3. Set up test user authentication
    4. Execute the automation framework plan
    5. Collect results (alerts, timing, HTTP requests)
    6. Save structured output for analysis

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

import requests
from zapv2 import ZAPv2

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_ZAP_URL = "http://localhost:8080"
DEFAULT_TARGET_URL = "http://localhost:3000"
DEFAULT_ZAP_API_KEY = "thesis-zap-api-key"
DEFAULT_CONFIG_FILE = "configs/zap-injection-baseline.yaml"
DEFAULT_OUTPUT_DIR = "./results/baseline"
DEFAULT_TIMEOUT_MINUTES = 60

# Injection CWE IDs for alert filtering
INJECTION_CWE_IDS = {77, 78, 89, 90, 91, 94, 95, 96, 97, 98, 99, 113, 134, 564, 611, 643, 917, 943, 1236}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_file_logging(output_dir: str, run_id: int) -> logging.FileHandler:
    """
    Add a file handler so all log output is persisted alongside results.

    Args:
        output_dir: Directory where results are saved
        run_id: Current run identifier

    Returns:
        The FileHandler (caller can remove it after the run)
    """
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(
        output_dir,
        f"baseline_run_{run_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    logging.getLogger().addHandler(fh)
    logger.info(f"Log file: {log_file}")
    return fh


# =============================================================================
# Helper Functions
# =============================================================================

def verify_zap_connection(zap: ZAPv2) -> bool:
    """Verify ZAP is accessible."""
    try:
        version = zap.core.version
        logger.info(f"Connected to ZAP version: {version}")
        return True
    except Exception as e:
        logger.error(f"Failed to connect to ZAP: {e}")
        return False


def verify_target_connection(target_url: str) -> bool:
    """Verify target application is accessible."""
    try:
        response = requests.get(f"{target_url}/rest/admin/application-version", timeout=10)
        if response.status_code == 200:
            version = response.json().get("version", "unknown")
            logger.info(f"Connected to Juice Shop v{version}")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to connect to target: {e}")
        return False


def clear_zap_session(zap: ZAPv2) -> bool:
    """Clear ZAP session for clean state."""
    try:
        zap.core.new_session(overwrite=True)
        logger.info("ZAP session cleared")
        return True
    except Exception as e:
        logger.error(f"Failed to clear ZAP session: {e}")
        return False


def filter_injection_alerts(alerts: list) -> list:
    """Filter alerts to only injection-related vulnerabilities."""
    injection_keywords = [
        "sql injection", "nosql injection", "mongodb injection",
        "command injection", "os command", "template injection",
        "ssti", "ldap injection", "xpath injection", "xxe",
        "xml external entity", "code injection"
    ]
    
    filtered = []
    for alert in alerts:
        # Check CWE ID
        cwe_id = alert.get("cweid")
        if cwe_id and int(cwe_id) in INJECTION_CWE_IDS:
            filtered.append(alert)
            continue
        
        # Check alert name
        name = alert.get("name", "").lower()
        if any(kw in name for kw in injection_keywords):
            filtered.append(alert)
            continue
    
    return filtered


def run_automation_framework(
    zap_url: str,
    api_key: str,
    config_file: str,
    timeout_minutes: int
) -> dict:
    """
    Run ZAP automation framework with the specified configuration.

    Uses ZAP's automation framework via the API.

    Returns:
        {
          "success": bool,
          "duration_seconds": float,
          "plan_id": str,
          "error": str (if any)
        }
    """
    logger.info(f"Loading automation framework config: {config_file}")

    if not os.path.exists(config_file):
        return {"success": False, "error": f"Config file not found: {config_file}"}

    # NOTE: ZAP automation 'runPlan' expects a file path inside the ZAP container,
    # not YAML text. Your docker-compose mounts ./configs -> /zap/configs.
    container_plan_path = f"/zap/configs/{os.path.basename(config_file)}"

    # Create ZAP client
    zap = ZAPv2(apikey=api_key, proxies={"http": zap_url, "https": zap_url})

    logger.info(f"Starting automation framework execution (plan: {container_plan_path})...")
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60

    try:
        # Start plan
        result = zap.automation.run_plan(container_plan_path)

        # Extract planId
        plan_id = result.get("planId") if isinstance(result, dict) else result
        if not plan_id:
            raise RuntimeError(f"No planId returned from runPlan: {result}")

        logger.info(f"Automation plan started. planId={plan_id}")

        # Poll progress until completion or timeout
        while True:
            elapsed = time.time() - start_time
            if elapsed >= timeout_seconds:
                logger.warning(f"Timeout reached after {timeout_minutes} minutes (planId={plan_id})")
                break

            try:
                # IMPORTANT: this wrapper method expects plan_id, not the dict result
                progress = zap.automation.plan_progress(plan_id)
            except Exception as e:
                # If wrapper is flaky, surface debug info and keep polling
                logger.debug(f"Error calling plan_progress(planId={plan_id}): {e}")
                time.sleep(3)
                continue

            jobs = progress.get("jobs", []) if isinstance(progress, dict) else []

            # Log lightweight status every poll
            if jobs:
                # show each job name/status if present
                status_line = ", ".join(
                    f"{j.get('name','job')}={j.get('status','?')}" for j in jobs
                )
                logger.info(f"Automation running... ({int(elapsed)}s) [{status_line}]")
            else:
                logger.info(f"Automation running... ({int(elapsed)}s) [no jobs reported yet]")

            # Only treat as complete if jobs exist AND all are terminal
            if jobs and all(j.get("status") in ("COMPLETED", "FAILED", "SKIPPED") for j in jobs):
                logger.info(f"Automation framework completed (planId={plan_id})")
                break

            time.sleep(5)

        duration = time.time() - start_time
        return {
            "success": True,
            "duration_seconds": duration,
            "plan_id": str(plan_id),
        }

    except Exception as e:
        logger.error(f"Automation framework error: {e}")
        return {"success": False, "error": str(e)}



def collect_results(zap: ZAPv2) -> dict:
    """
    Collect scan results from ZAP.
    
    Args:
        zap: ZAPv2 client instance
        
    Returns:
        Dictionary with collected results
    """
    logger.info("Collecting scan results...")
    
    try:
        # Get all alerts
        all_alerts = zap.core.alerts()
        injection_alerts = filter_injection_alerts(all_alerts)
        
        logger.info(f"Total ZAP alerts: {len(all_alerts)}, injection-related: {len(injection_alerts)}")
        
        # Log each injection alert found
        for i, alert in enumerate(injection_alerts, 1):
            logger.info(
                f"  Alert {i}: {alert.get('name')} | "
                f"Risk={alert.get('risk')} | "
                f"URL={alert.get('url', 'N/A')} | "
                f"Param={alert.get('param', 'N/A')} | "
                f"CWE={alert.get('cweid', 'N/A')} | "
                f"PluginId={alert.get('pluginId', 'N/A')}"
            )
        
        # Format alerts
        formatted_alerts = []
        for alert in injection_alerts:
            formatted_alerts.append({
                "id": alert.get("id"),
                "pluginId": alert.get("pluginId"),
                "name": alert.get("name"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "method": alert.get("method"),
                "param": alert.get("param"),
                "attack": alert.get("attack", "")[:500],
                "evidence": alert.get("evidence", "")[:500],
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
                "description": alert.get("description", "")[:1000]
            })
        
        # Get counts
        http_requests = int(zap.core.number_of_messages())

        urls_resp = zap.core.urls()
        if isinstance(urls_resp, dict) and "urls" in urls_resp:
            urls_found = len(urls_resp["urls"])
        elif isinstance(urls_resp, list):
            urls_found = len(urls_resp)
        else:
            urls_found = 0
        
        logger.info(f"HTTP requests sent: {http_requests}")
        logger.info(f"URLs in site tree:  {urls_found}")
                
        # Summarize by risk
        by_risk = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for alert in injection_alerts:
            risk = alert.get("risk", "Informational")
            if risk in by_risk:
                by_risk[risk] += 1
        
        # Summarize by type
        by_type = {}
        for alert in injection_alerts:
            name = alert.get("name", "Unknown")
            by_type[name] = by_type.get(name, 0) + 1
        
        return {
            "alerts": formatted_alerts,
            "total_alerts": len(all_alerts),
            "injection_alerts": len(formatted_alerts),
            "http_requests": http_requests,
            "urls_found": urls_found,
            "by_risk": by_risk,
            "by_type": by_type
        }
        
    except Exception as e:
        logger.error(f"Error collecting results: {e}")
        return {
            "alerts": [],
            "total_alerts": 0,
            "injection_alerts": 0,
            "http_requests": 0,
            "urls_found": 0,
            "by_risk": {},
            "by_type": {},
            "error": str(e)
        }


def run_baseline(
    zap_url: str,
    zap_api_key: str,
    target_url: str,
    config_file: str,
    output_dir: str,
    run_id: int,
    timeout_minutes: int
) -> dict:
    """
    Execute a single baseline run.
    
    Args:
        zap_url: ZAP API URL
        zap_api_key: ZAP API key
        target_url: Target application URL
        config_file: Path to automation framework config
        output_dir: Directory for output files
        run_id: Run identifier (1-5)
        timeout_minutes: Maximum execution time
        
    Returns:
        Dictionary with run results
    """
    logger.info("=" * 60)
    logger.info(f"BASELINE RUN {run_id}")
    logger.info("=" * 60)
    
    # Set up file logging so everything is persisted
    file_handler = setup_file_logging(output_dir, run_id)
    
    logger.info(f"Configuration:")
    logger.info(f"  ZAP URL:      {zap_url}")
    logger.info(f"  Target URL:   {target_url}")
    logger.info(f"  Config file:  {config_file}")
    logger.info(f"  Timeout:      {timeout_minutes} minutes")
    logger.info(f"  Output dir:   {output_dir}")
    
    start_time = time.time()
    timestamp = datetime.now().isoformat()
    
    # Initialize ZAP client
    zap = ZAPv2(
        apikey=zap_api_key,
        proxies={"http": zap_url, "https": zap_url}
    )
    
    # Step 1: Verify connections
    logger.info("-" * 40)
    logger.info("STEP 1/6: Verifying connections")
    logger.info("-" * 40)
    if not verify_zap_connection(zap):
        logging.getLogger().removeHandler(file_handler)
        return {"success": False, "error": "ZAP not accessible"}
    
    if not verify_target_connection(target_url):
        logging.getLogger().removeHandler(file_handler)
        return {"success": False, "error": "Target not accessible"}
    
    # Step 2: Clear session
    logger.info("-" * 40)
    logger.info("STEP 2/6: Clearing ZAP session for clean state")
    logger.info("-" * 40)
    if not clear_zap_session(zap):
        logging.getLogger().removeHandler(file_handler)
        return {"success": False, "error": "Failed to clear ZAP session"}
    
    # Step 3: Run automation framework
    logger.info("-" * 40)
    logger.info("STEP 3/6: Running ZAP automation framework")
    logger.info("-" * 40)
    logger.info("Pipeline: passiveScan-config â†’ spider â†’ spiderAjax â†’ passiveScan-wait â†’ activeScan-config â†’ activeScan â†’ report")
    exec_result = run_automation_framework(
        zap_url, zap_api_key, config_file, timeout_minutes
    )
    
    if not exec_result.get("success"):
        logger.error(f"Automation framework failed: {exec_result.get('error')}")
        logging.getLogger().removeHandler(file_handler)
        return {
            "success": False,
            "error": exec_result.get("error", "Automation framework failed")
        }
    
    logger.info(f"Automation framework finished in {exec_result.get('duration_seconds', 0):.1f}s")
    
    # Step 4: Collect results
    logger.info("-" * 40)
    logger.info("STEP 4/6: Collecting scan results from ZAP")
    logger.info("-" * 40)
    results = collect_results(zap)
    
    # Step 5: Compile final output
    logger.info("-" * 40)
    logger.info("STEP 5/6: Compiling output")
    logger.info("-" * 40)
    duration = time.time() - start_time
    
    output = {
        "run_id": run_id,
        "condition": "baseline",
        "timestamp": timestamp,
        "duration_minutes": round(duration / 60, 2),
        "duration_seconds": round(duration, 2),
        "config_file": config_file,
        "target_url": target_url,
        "results": results,
        "summary": {
            "injection_alerts": results["injection_alerts"],
            "http_requests": results["http_requests"],
            "urls_found": results["urls_found"],
            "alerts_by_risk": results["by_risk"],
            "alerts_by_type": results["by_type"]
        }
    }
    
    # Step 6: Save output
    logger.info("-" * 40)
    logger.info("STEP 6/6: Saving results")
    logger.info("-" * 40)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"baseline_run_{run_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    # Final summary
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"BASELINE RUN {run_id} â€” FINAL SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Duration:          {output['duration_minutes']} minutes ({output['duration_seconds']}s)")
    logger.info(f"  HTTP requests:     {results['http_requests']}")
    logger.info(f"  URLs discovered:   {results['urls_found']}")
    logger.info(f"  Total ZAP alerts:  {results['total_alerts']}")
    logger.info(f"  Injection alerts:  {results['injection_alerts']}")
    if results['by_risk']:
        logger.info(f"  By risk:           High={results['by_risk'].get('High', 0)}, Medium={results['by_risk'].get('Medium', 0)}, Low={results['by_risk'].get('Low', 0)}")
    if results['by_type']:
        logger.info(f"  By type:")
        for vuln_type, count in results['by_type'].items():
            logger.info(f"    - {vuln_type}: {count}")
    logger.info(f"  Results JSON:      {output_file}")
    logger.info("=" * 60)
    
    # Clean up file handler
    logging.getLogger().removeHandler(file_handler)
    file_handler.close()
    
    output["success"] = True
    output["output_file"] = output_file
    
    return output


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run baseline ZAP automation framework scan"
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
        default=os.environ.get("HOST_TARGET_URL", DEFAULT_TARGET_URL),
        help=f"Target application URL (default: {DEFAULT_TARGET_URL})"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Automation framework config file (default: {DEFAULT_CONFIG_FILE})"
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default="1",
        help="Run identifier (default: 1)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_MINUTES,
        help=f"Timeout in minutes (default: {DEFAULT_TIMEOUT_MINUTES})"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    result = run_baseline(
        zap_url=args.zap_url,
        zap_api_key=args.zap_api_key,
        target_url=args.target_url,
        config_file=args.config,
        output_dir=args.output_dir,
        run_id=args.run_id,
        timeout_minutes=args.timeout
    )
    
    if result.get("success"):
        print(f"\nâœ“ Baseline run {args.run_id} completed successfully")
        sys.exit(0)
    else:
        print(f"\nâœ— Baseline run failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()