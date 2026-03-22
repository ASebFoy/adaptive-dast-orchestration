#!/usr/bin/env python3
"""
Evaluation Module: Ground Truth Comparison and Metric Calculation

Compares experimental results against the documented ground truth
vulnerabilities and calculates performance metrics:
    - Recall: TP / (TP + FN) - proportion of ground truth detected
    - Precision: TP / (TP + FP) - proportion of genuine alerts
    - Detection Efficiency: (TP / HTTP Requests) Ã— 1000

Ground Truth Matching Criteria (per Decision Document Â§3.1):
    1. Alert pluginId is in evaluation set (40018-40024 for SQL, 40033 for NoSQL)
    2. Alert URL path contains the ground truth endpoint path
    3. Alert parameter matches the ground truth parameter
    4. Alert injection type matches (SQL vs NoSQL, determined by CWE)
    5. Each GT entry matched at most once; each alert matched at most once
    6. Auth-gated GT entries excluded from recall denominator

Usage:
    python evaluate.py --results-dir ./results --ground-truth ground_truth_injection.json
    
    # Evaluate single run
    python evaluate.py --result-file ./results/baseline/baseline_run_1.json

Author: Thesis Experiment Infrastructure
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# =============================================================================
# Configuration
# =============================================================================

# Ground truth file
DEFAULT_GROUND_TRUTH = "ground_truth_injection.json"

# ---------------------------------------------------------------------------
# Evaluation-relevant ZAP rule IDs (Decision Document Â§2.1, Â§3.1)
# Only alerts from these rules participate in TP/FP/FN calculation.
# Alerts from other rules (90020, 90035, 40015, 90021, 90023) are EXCLUDED
# entirely â€” they are neither TP nor FP.
# ---------------------------------------------------------------------------
SQL_INJECTION_RULE_IDS = {40018, 40019, 40020, 40021, 40022, 40023, 40024}
NOSQL_INJECTION_RULE_IDS = {40033}
EVALUATION_RULE_IDS = SQL_INJECTION_RULE_IDS | NOSQL_INJECTION_RULE_IDS

# CWE-to-type mapping for ground truth entries
SQL_CWE = "CWE-89"
NOSQL_CWE = "CWE-943"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Ground Truth Loading
# =============================================================================

def load_ground_truth(filepath: str) -> dict:
    """
    Load ground truth vulnerabilities from JSON file.
    
    Args:
        filepath: Path to ground truth JSON file
        
    Returns:
        Dictionary with ground truth data
    """
    logger.info(f"Loading ground truth from: {filepath}")
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    vulnerabilities = data.get("vulnerabilities", [])
    logger.info(f"Loaded {len(vulnerabilities)} ground truth vulnerabilities")
    
    return data


def get_effective_ground_truth(ground_truth: dict) -> list:
    """
    Return only unauthenticated ground truth entries for evaluation.
    
    Per Decision Document Â§3.1: Auth-gated entries (NOSQLI-REVIEW) are
    excluded from the recall denominator.
    
    Args:
        ground_truth: Full ground truth dictionary
        
    Returns:
        List of vulnerability dicts where auth_required is False
    """
    all_vulns = ground_truth.get("vulnerabilities", [])
    effective = [v for v in all_vulns if not v.get("auth_required", False)]
    
    excluded = [v["id"] for v in all_vulns if v.get("auth_required", False)]
    if excluded:
        logger.info(
            f"Excluded {len(excluded)} auth-gated GT entries from evaluation: "
            f"{', '.join(excluded)}"
        )
    logger.info(f"Effective ground truth: {len(effective)} entries")
    
    return effective


def load_result_file(filepath: str) -> dict:
    """
    Load a single result file.
    
    Args:
        filepath: Path to result JSON file
        
    Returns:
        Dictionary with result data
    """
    with open(filepath, 'r') as f:
        return json.load(f)


def load_all_results(results_dir: str) -> dict:
    """
    Load all result files from a directory.
    
    Args:
        results_dir: Path to results directory
        
    Returns:
        Dictionary with baseline and agent results
    """
    results = {
        "baseline": [],
        "agent": []
    }
    
    # Load baseline results
    baseline_dir = os.path.join(results_dir, "baseline")
    if os.path.exists(baseline_dir):
        for filename in sorted(os.listdir(baseline_dir)):
            if filename.endswith('.json') and filename.startswith('baseline_run'):
                filepath = os.path.join(baseline_dir, filename)
                results["baseline"].append(load_result_file(filepath))
    
    # Load agent results
    agent_dir = os.path.join(results_dir, "agent")
    if os.path.exists(agent_dir):
        for filename in sorted(os.listdir(agent_dir)):
            if filename.endswith('.json') and filename.startswith('agent_run'):
                filepath = os.path.join(agent_dir, filename)
                results["agent"].append(load_result_file(filepath))
    
    logger.info(
        f"Loaded {len(results['baseline'])} baseline runs, "
        f"{len(results['agent'])} agent runs"
    )
    
    return results


# =============================================================================
# Alert Filtering
# =============================================================================

def filter_evaluation_alerts(alerts: list) -> list:
    """
    Filter alerts to only those from evaluation-relevant ZAP rules.
    
    Per Decision Document Â§2.3 and Â§3.1:
    Only alerts from SQL injection rules (40018-40024) and NoSQL injection
    rule (40033) are evaluated. Alerts from rules 90020, 90035, 40015,
    90021, 90023 are excluded entirely â€” they are neither TP nor FP.
    
    Args:
        alerts: List of alert dictionaries from ZAP
        
    Returns:
        List of alerts from evaluation-relevant rules only
    """
    filtered = []
    excluded_count = 0
    
    for alert in alerts:
        # Get plugin ID (ZAP uses "pluginId" in API, some formats use "plugin_id")
        plugin_id = alert.get("pluginId") or alert.get("plugin_id")
        
        if plugin_id is not None:
            try:
                if int(plugin_id) in EVALUATION_RULE_IDS:
                    filtered.append(alert)
                else:
                    excluded_count += 1
            except (ValueError, TypeError):
                excluded_count += 1
        else:
            # If no plugin ID available, fall back to CWE-based filtering
            # This handles edge cases where alert format differs
            cwe_id = alert.get("cweid")
            if cwe_id:
                try:
                    cwe_int = int(cwe_id)
                    if cwe_int in (89, 564):
                        logger.warning(
                            f"Alert missing pluginId, using CWE fallback: "
                            f"CWE-{cwe_int}, name={alert.get('name', 'unknown')}, "
                            f"url={alert.get('url', 'unknown')}"
                        )
                        filtered.append(alert)
                    elif cwe_int == 943:
                        logger.warning(
                            f"Alert missing pluginId, using CWE fallback: "
                            f"CWE-{cwe_int}, name={alert.get('name', 'unknown')}, "
                            f"url={alert.get('url', 'unknown')}"
                        )
                        filtered.append(alert)
                    else:
                        excluded_count += 1
                except (ValueError, TypeError):
                    excluded_count += 1
            else:
                excluded_count += 1
    
    if excluded_count > 0:
        logger.info(
            f"Alert filtering: kept {len(filtered)} evaluation-relevant alerts, "
            f"excluded {excluded_count} non-evaluation alerts"
        )
    
    return filtered


# =============================================================================
# Alert Matching
# =============================================================================

def normalize_endpoint(url: str) -> str:
    """
    Extract and normalize endpoint path from URL.
    
    Args:
        url: Full URL string
        
    Returns:
        Normalized endpoint path
    """
    try:
        parsed = urlparse(url)
        path = parsed.path
        # Remove trailing slashes and normalize
        return path.rstrip('/')
    except Exception:
        return url


def get_alert_injection_type(alert: dict) -> str:
    """
    Determine injection type from alert using plugin ID or CWE.
    
    Per Decision Document Â§3.1 step 2:
        Rule IDs 40018-40024 OR CWE-89 â†’ "sql"
        Rule ID 40033 OR CWE-943 â†’ "nosql"
    
    Args:
        alert: Alert dictionary
        
    Returns:
        "sql", "nosql", or "unknown"
    """
    # Primary: check plugin ID
    plugin_id = alert.get("pluginId") or alert.get("plugin_id")
    if plugin_id is not None:
        try:
            pid = int(plugin_id)
            if pid in SQL_INJECTION_RULE_IDS:
                return "sql"
            if pid in NOSQL_INJECTION_RULE_IDS:
                return "nosql"
        except (ValueError, TypeError):
            pass
    
    # Fallback: check CWE
    cwe_id = alert.get("cweid")
    if cwe_id is not None:
        try:
            cwe_int = int(cwe_id)
            if cwe_int in (89, 564):
                return "sql"
            if cwe_int == 943:
                return "nosql"
        except (ValueError, TypeError):
            pass
    
    return "unknown"


def get_gt_injection_type(gt_vuln: dict) -> str:
    """
    Determine injection type from ground truth entry using CWE.
    
    Args:
        gt_vuln: Ground truth vulnerability dictionary
        
    Returns:
        "sql", "nosql", or "unknown"
    """
    cwe = gt_vuln.get("cwe", "")
    if cwe == SQL_CWE:
        return "sql"
    elif cwe == NOSQL_CWE:
        return "nosql"
    return "unknown"


def match_alert_to_ground_truth(alert: dict, gt_vuln: dict) -> bool:
    """
    Check if an alert matches a ground truth vulnerability.
    
    Per Decision Document Â§3.1, matching requires ALL of:
        1. Alert URL path contains the ground truth endpoint path
        2. Alert parameter matches the ground truth parameter
        3. Alert injection type matches GT injection type (SQL vs NoSQL)
    
    Args:
        alert: Alert dictionary
        gt_vuln: Ground truth vulnerability dictionary
        
    Returns:
        True if alert matches the ground truth vulnerability
    """
    # Get ground truth fields
    gt_endpoint = gt_vuln.get("location", "")
    gt_param = gt_vuln.get("parameter", "")
    gt_type = get_gt_injection_type(gt_vuln)
    
    # Get alert fields
    alert_url = alert.get("url", "")
    alert_endpoint = normalize_endpoint(alert_url)
    alert_param = alert.get("param", "")
    alert_type = get_alert_injection_type(alert)
    
    # Check 1: Endpoint path containment
    if gt_endpoint not in alert_endpoint:
        return False
    
    # Check 2: Parameter match
    if alert_param != gt_param:
        return False
    
    # Check 3: Injection type match
    if gt_type == "unknown" or alert_type == "unknown":
        return False
    if gt_type != alert_type:
        return False
    
    return True


# =============================================================================
# Evaluation Functions
# =============================================================================

def evaluate_run(run_result: dict, ground_truth: dict) -> dict:
    """
    Evaluate a single experimental run against ground truth.
    
    Implements the matching procedure from Decision Document Â§3.1 and Â§10:
    1. Load effective GT entries (auth_required == false) â†’ 7 entries
    2. Filter alerts to evaluation-relevant rules only
    3. For each alert, match to first unmatched GT entry in document order
    4. Calculate recall, precision, efficiency
    
    Args:
        run_result: Result dictionary from a run
        ground_truth: Ground truth dictionary
        
    Returns:
        Evaluation metrics dictionary
    """
    # Step 1: Get effective ground truth (exclude auth-gated)
    gt_vulnerabilities = get_effective_ground_truth(ground_truth)
    effective_gt_count = len(gt_vulnerabilities)
    
    # Step 2: Get alerts from result
    if "results" in run_result:
        raw_alerts = run_result["results"].get("alerts", [])
    else:
        raw_alerts = run_result.get("alerts", [])
    
    # Step 3: Filter to evaluation-relevant alerts only (SQL/NoSQL injection rules)
    alerts = filter_evaluation_alerts(raw_alerts)
    
    logger.debug(
        f"Raw alerts: {len(raw_alerts)}, "
        f"Evaluation-relevant alerts: {len(alerts)}"
    )
    
    # Step 4: Match alerts to ground truth entries
    # Per Decision Document Â§3.1: each GT entry matched at most once,
    # each alert maps to at most one GT entry, assign to first unmatched
    # entry in document order.
    matched_gt_ids = set()
    matched_alerts = []
    unmatched_alerts = []
    
    for alert in alerts:
        matched = False
        for gt_vuln in gt_vulnerabilities:  # document order
            gt_id = gt_vuln.get("id")
            
            # Skip already-matched GT entries
            if gt_id in matched_gt_ids:
                continue
            
            if match_alert_to_ground_truth(alert, gt_vuln):
                matched_gt_ids.add(gt_id)
                matched_alerts.append({
                    "alert_name": alert.get("name", ""),
                    "alert_url": alert.get("url", ""),
                    "alert_param": alert.get("param", ""),
                    "alert_plugin_id": alert.get("pluginId") or alert.get("plugin_id"),
                    "ground_truth_id": gt_id
                })
                matched = True
                break
        
        if not matched:
            unmatched_alerts.append({
                "alert_name": alert.get("name", ""),
                "alert_url": alert.get("url", ""),
                "alert_param": alert.get("param", ""),
                "alert_plugin_id": alert.get("pluginId") or alert.get("plugin_id"),
                "alert_cweid": alert.get("cweid", "")
            })
    
    # Step 5: Calculate metrics
    true_positives = len(matched_gt_ids)
    false_positives = len(unmatched_alerts)
    false_negatives = effective_gt_count - true_positives
    
    # Get HTTP requests
    if "results" in run_result:
        http_requests = run_result["results"].get("http_requests", 0)
    else:
        http_requests = run_result.get("http_requests", 0)
    
    # Recall = TP / effective_gt_count (7, not 8)
    recall = true_positives / effective_gt_count if effective_gt_count > 0 else 0
    # Precision = TP / (TP + FP)
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0 else 0
    )
    # Detection Efficiency = TP per 1,000 HTTP requests
    efficiency = (true_positives / http_requests) * 1000 if http_requests > 0 else 0
    
    # List detected and missed vulnerabilities
    detected_list = [gt["id"] for gt in gt_vulnerabilities if gt["id"] in matched_gt_ids]
    missed_list = [gt["id"] for gt in gt_vulnerabilities if gt["id"] not in matched_gt_ids]
    
    return {
        "run_id": run_result.get("run_id"),
        "condition": run_result.get("condition"),
        "metrics": {
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "detection_efficiency": round(efficiency, 4),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "effective_ground_truth": effective_gt_count,
            "total_evaluation_alerts": len(alerts),
            "total_raw_alerts": len(raw_alerts),
            "http_requests": http_requests
        },
        "matched_alerts": matched_alerts,
        "unmatched_alerts": unmatched_alerts,
        "detected_vulnerabilities": detected_list,
        "missed_vulnerabilities": missed_list,
        "duration_minutes": run_result.get("duration_minutes", 0)
    }


def evaluate_condition(results: list, ground_truth: dict, condition_name: str) -> dict:
    """
    Evaluate all runs for a condition.
    
    Args:
        results: List of run result dictionaries
        ground_truth: Ground truth dictionary
        condition_name: Name of condition ('baseline' or 'agent')
        
    Returns:
        Aggregated evaluation for the condition
    """
    logger.info(f"Evaluating {condition_name} condition ({len(results)} runs)...")
    
    run_evaluations = []
    
    for run_result in results:
        eval_result = evaluate_run(run_result, ground_truth)
        run_evaluations.append(eval_result)
    
    # Aggregate metrics
    if run_evaluations:
        recalls = [r["metrics"]["recall"] for r in run_evaluations]
        precisions = [r["metrics"]["precision"] for r in run_evaluations]
        efficiencies = [r["metrics"]["detection_efficiency"] for r in run_evaluations]
        http_requests = [r["metrics"]["http_requests"] for r in run_evaluations]
        durations = [r["duration_minutes"] for r in run_evaluations]
        true_positives = [r["metrics"]["true_positives"] for r in run_evaluations]
        
        aggregate = {
            "recall": {
                "mean": round(sum(recalls) / len(recalls), 4),
                "min": round(min(recalls), 4),
                "max": round(max(recalls), 4),
                "values": recalls
            },
            "precision": {
                "mean": round(sum(precisions) / len(precisions), 4),
                "min": round(min(precisions), 4),
                "max": round(max(precisions), 4),
                "values": precisions
            },
            "detection_efficiency": {
                "mean": round(sum(efficiencies) / len(efficiencies), 4),
                "min": round(min(efficiencies), 4),
                "max": round(max(efficiencies), 4),
                "values": efficiencies
            },
            "http_requests": {
                "mean": round(sum(http_requests) / len(http_requests), 2),
                "min": min(http_requests),
                "max": max(http_requests),
                "values": http_requests
            },
            "duration_minutes": {
                "mean": round(sum(durations) / len(durations), 2),
                "min": round(min(durations), 2),
                "max": round(max(durations), 2),
                "values": durations
            },
            "true_positives": {
                "mean": round(sum(true_positives) / len(true_positives), 2),
                "min": min(true_positives),
                "max": max(true_positives),
                "values": true_positives
            }
        }
    else:
        aggregate = {}
    
    return {
        "condition": condition_name,
        "num_runs": len(results),
        "aggregate": aggregate,
        "runs": run_evaluations
    }


def evaluate_experiment(
    results_dir: str,
    ground_truth_file: str,
    output_file: Optional[str] = None
) -> dict:
    """
    Evaluate complete experiment.
    
    Args:
        results_dir: Directory containing results
        ground_truth_file: Path to ground truth JSON
        output_file: Optional output file path
        
    Returns:
        Complete evaluation dictionary
    """
    logger.info("=" * 60)
    logger.info("EXPERIMENT EVALUATION")
    logger.info("=" * 60)
    
    # Load data
    ground_truth = load_ground_truth(ground_truth_file)
    results = load_all_results(results_dir)
    
    # Report effective GT
    effective_gt = get_effective_ground_truth(ground_truth)
    
    # Evaluate each condition
    baseline_eval = evaluate_condition(results["baseline"], ground_truth, "baseline")
    agent_eval = evaluate_condition(results["agent"], ground_truth, "agent")
    
    # Compile evaluation
    evaluation = {
        "ground_truth": {
            "total_vulnerabilities": len(ground_truth.get("vulnerabilities", [])),
            "effective_vulnerabilities": len(effective_gt),
            "auth_gated_excluded": len(ground_truth.get("vulnerabilities", [])) - len(effective_gt),
            "by_type": ground_truth.get("metadata", {}).get("by_type", {}),
            "endpoints": ground_truth.get("metadata", {}).get("endpoints_affected", [])
        },
        "evaluation_rules": {
            "sql_injection_rules": sorted(SQL_INJECTION_RULE_IDS),
            "nosql_injection_rules": sorted(NOSQL_INJECTION_RULE_IDS),
            "note": "Only alerts from these rules are evaluated. All other rules excluded."
        },
        "baseline": baseline_eval,
        "agent": agent_eval,
        "comparison": {}
    }
    
    # Add comparison if both conditions have data
    if baseline_eval.get("aggregate") and agent_eval.get("aggregate"):
        baseline_agg = baseline_eval["aggregate"]
        agent_agg = agent_eval["aggregate"]
        
        baseline_eff_mean = baseline_agg["detection_efficiency"]["mean"]
        agent_eff_mean = agent_agg["detection_efficiency"]["mean"]
        
        evaluation["comparison"] = {
            "recall_difference": round(
                agent_agg["recall"]["mean"] - baseline_agg["recall"]["mean"], 4
            ),
            "precision_difference": round(
                agent_agg["precision"]["mean"] - baseline_agg["precision"]["mean"], 4
            ),
            "efficiency_difference": round(
                agent_eff_mean - baseline_eff_mean, 4
            ),
            "efficiency_improvement_pct": round(
                ((agent_eff_mean - baseline_eff_mean) / baseline_eff_mean * 100)
                if baseline_eff_mean > 0 else 0, 2
            ),
            "request_difference": round(
                agent_agg["http_requests"]["mean"] - baseline_agg["http_requests"]["mean"], 2
            )
        }
    
    # Save evaluation
    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(evaluation, f, indent=2)
        logger.info(f"Evaluation saved to: {output_file}")
    
    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("EVALUATION SUMMARY")
    logger.info("=" * 60)
    logger.info(
        f"Ground truth: {evaluation['ground_truth']['total_vulnerabilities']} total, "
        f"{evaluation['ground_truth']['effective_vulnerabilities']} effective "
        f"({evaluation['ground_truth']['auth_gated_excluded']} auth-gated excluded)"
    )
    
    if baseline_eval.get("aggregate"):
        ba = baseline_eval["aggregate"]
        logger.info(f"\nBASELINE ({baseline_eval['num_runs']} runs):")
        logger.info(f"  Recall: {ba['recall']['mean']:.2%} (range: {ba['recall']['min']:.2%} - {ba['recall']['max']:.2%})")
        logger.info(f"  Precision: {ba['precision']['mean']:.2%}")
        logger.info(f"  Efficiency: {ba['detection_efficiency']['mean']:.4f} TP/1000 requests")
        logger.info(f"  HTTP Requests: {ba['http_requests']['mean']:.0f} (avg)")
    
    if agent_eval.get("aggregate"):
        aa = agent_eval["aggregate"]
        logger.info(f"\nAGENT ({agent_eval['num_runs']} runs):")
        logger.info(f"  Recall: {aa['recall']['mean']:.2%} (range: {aa['recall']['min']:.2%} - {aa['recall']['max']:.2%})")
        logger.info(f"  Precision: {aa['precision']['mean']:.2%}")
        logger.info(f"  Efficiency: {aa['detection_efficiency']['mean']:.4f} TP/1000 requests")
        logger.info(f"  HTTP Requests: {aa['http_requests']['mean']:.0f} (avg)")
    
    if evaluation.get("comparison"):
        comp = evaluation["comparison"]
        logger.info(f"\nCOMPARISON (Agent - Baseline):")
        logger.info(f"  Recall difference: {comp['recall_difference']:+.2%}")
        logger.info(f"  Precision difference: {comp['precision_difference']:+.2%}")
        logger.info(f"  Efficiency improvement: {comp['efficiency_improvement_pct']:+.1f}%")
    
    logger.info("=" * 60)
    
    return evaluation


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate experiment results against ground truth"
    )
    parser.add_argument(
        "--results-dir",
        default="./results",
        help="Directory containing results"
    )
    parser.add_argument(
        "--ground-truth",
        default=DEFAULT_GROUND_TRUTH,
        help=f"Ground truth JSON file (default: {DEFAULT_GROUND_TRUTH})"
    )
    parser.add_argument(
        "--output",
        default="./results/evaluation.json",
        help="Output file for evaluation results"
    )
    parser.add_argument(
        "--result-file",
        help="Evaluate single result file instead of directory"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.result_file:
        # Evaluate single file
        ground_truth = load_ground_truth(args.ground_truth)
        result = load_result_file(args.result_file)
        evaluation = evaluate_run(result, ground_truth)
        
        print(json.dumps(evaluation, indent=2))
    else:
        # Evaluate full experiment
        evaluate_experiment(
            results_dir=args.results_dir,
            ground_truth_file=args.ground_truth,
            output_file=args.output
        )


if __name__ == "__main__":
    main()
