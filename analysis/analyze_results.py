#!/usr/bin/env python3
"""
Statistical Analysis Module: Hypothesis Testing and Effect Sizes

Performs statistical analysis on experimental results:
    - Mann-Whitney U test (non-parametric, appropriate for n=5)
    - Cliff's Delta effect size
    - Coefficient of Variation (CV) for between-run variability
    - Hypothesis verdict determination with sensitivity analysis

Hypotheses (from thesis):
    H1: Agent achieves higher recall than baseline
    H2: Agent maintains precision within 10pp of baseline
    H3a: Agent produces different HTTP request volume
    H3b: Agent improves detection efficiency by â‰¥25%

Usage:
    python analyze_results.py --evaluation ./results/evaluation.json
    
    # Generate publication-ready tables
    python analyze_results.py --evaluation ./results/evaluation.json --format latex

Author: Thesis Experiment Infrastructure
"""

import argparse
import json
import logging
import os
import sys
from typing import Optional

import numpy as np
from scipy import stats

# =============================================================================
# Configuration
# =============================================================================

ALPHA = 0.05
PRECISION_THRESHOLD_PP = 10
EFFICIENCY_THRESHOLD_PCT = 25

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Statistical Functions
# =============================================================================

def coefficient_of_variation(values: list) -> float:
    """
    Calculate coefficient of variation (CV) as a percentage.
    
    CV = (standard deviation / mean) Ã— 100
    Uses sample standard deviation (ddof=1).
    
    Args:
        values: List of numeric values
        
    Returns:
        CV as a percentage, or 0 if mean is 0
    """
    if not values or len(values) < 2:
        return 0.0
    mean = np.mean(values)
    if mean == 0:
        return 0.0
    std = np.std(values, ddof=1)
    return round((std / abs(mean)) * 100, 2)


def mann_whitney_u(group1: list, group2: list) -> dict:
    """
    Perform two-sided Mann-Whitney U test with exact p-values.
    
    Uses method='exact' per Decision Document Â§5.4 given n=5.
    """
    if len(group1) < 2 or len(group2) < 2:
        return {
            "statistic": None, "p_value": None,
            "significant": None, "error": "Insufficient samples"
        }
    
    try:
        statistic, p_value = stats.mannwhitneyu(
            group1, group2, alternative='two-sided', method='exact'
        )
        return {
            "statistic": float(statistic),
            "p_value": float(p_value),
            "significant": p_value < ALPHA,
            "alpha": ALPHA,
            "method": "exact"
        }
    except Exception as e:
        return {
            "statistic": None, "p_value": None,
            "significant": None, "error": str(e)
        }


def mann_whitney_u_one_sided(
    group1: list, group2: list, alternative: str = 'greater'
) -> dict:
    """
    Perform one-sided Mann-Whitney U test with exact p-values.
    
    Uses method='exact' per Decision Document Â§5.4 given n=5.
    """
    if len(group1) < 2 or len(group2) < 2:
        return {
            "statistic": None, "p_value": None,
            "significant": None, "error": "Insufficient samples"
        }
    
    try:
        statistic, p_value = stats.mannwhitneyu(
            group1, group2, alternative=alternative, method='exact'
        )
        return {
            "statistic": float(statistic),
            "p_value": float(p_value),
            "significant": p_value < ALPHA,
            "alternative": alternative,
            "alpha": ALPHA,
            "method": "exact"
        }
    except Exception as e:
        return {
            "statistic": None, "p_value": None,
            "significant": None, "error": str(e)
        }


def cliffs_delta(group1: list, group2: list) -> dict:
    """
    Calculate Cliff's Delta effect size.
    
    Convention: Î´ = P(group2 > group1) - P(group2 < group1)
    Positive Î´ means group2 (agent) tends to have higher values.
    
    This convention aligns with all hypothesis tests where group1=baseline
    and group2=agent: positive delta = agent is higher.
    
    Interpretation (Romano et al., 2006):
        |Î´| < 0.147: negligible
        0.147 â‰¤ |Î´| < 0.33: small
        0.33 â‰¤ |Î´| < 0.474: medium
        |Î´| â‰¥ 0.474: large
    
    Args:
        group1: Baseline values
        group2: Agent values
        
    Returns:
        Dictionary with delta, magnitude, and interpretation
    """
    if not group1 or not group2:
        return {"delta": None, "magnitude": None, "error": "Empty groups"}
    
    n1, n2 = len(group1), len(group2)
    
    # Count how often agent > baseline and agent < baseline
    agent_greater = 0
    agent_less = 0
    
    for x in group1:      # baseline values
        for y in group2:   # agent values
            if y > x:
                agent_greater += 1
            elif y < x:
                agent_less += 1
    
    # Î´ = P(agent > baseline) - P(agent < baseline)
    delta = (agent_greater - agent_less) / (n1 * n2)
    abs_delta = abs(delta)
    
    if abs_delta < 0.147:
        magnitude = "negligible"
    elif abs_delta < 0.33:
        magnitude = "small"
    elif abs_delta < 0.474:
        magnitude = "medium"
    else:
        magnitude = "large"
    
    if abs_delta >= 0.147:
        direction = "Agent" if delta > 0 else "Baseline"
        interpretation = f"{direction} tends to have higher values"
    else:
        interpretation = "No meaningful difference"
    
    return {
        "delta": round(delta, 4),
        "magnitude": magnitude,
        "interpretation": interpretation
    }


# =============================================================================
# Hypothesis Testing
# =============================================================================

def test_h1_recall(baseline_recalls: list, agent_recalls: list) -> dict:
    """
    Test H1: Agent achieves higher recall than baseline.
    
    Uses one-sided test: alternative='less' tests if baseline < agent.
    """
    logger.info("Testing H1: Agent recall > Baseline recall")
    
    mw_result = mann_whitney_u_one_sided(baseline_recalls, agent_recalls, 'less')
    cd_result = cliffs_delta(baseline_recalls, agent_recalls)
    
    baseline_mean = np.mean(baseline_recalls) if baseline_recalls else 0
    agent_mean = np.mean(agent_recalls) if agent_recalls else 0
    baseline_cv = coefficient_of_variation(baseline_recalls)
    agent_cv = coefficient_of_variation(agent_recalls)
    
    if mw_result.get("significant") and cd_result.get("delta", 0) > 0:
        verdict = "SUPPORTED"
        explanation = (
            f"Agent recall ({agent_mean:.2%}) significantly higher than "
            f"baseline ({baseline_mean:.2%})"
        )
    elif agent_mean > baseline_mean:
        verdict = "PARTIALLY_SUPPORTED"
        explanation = (
            f"Agent recall higher ({agent_mean:.2%} vs {baseline_mean:.2%}) "
            f"but not statistically significant"
        )
    else:
        verdict = "NOT_SUPPORTED"
        explanation = (
            f"Agent recall ({agent_mean:.2%}) not higher than "
            f"baseline ({baseline_mean:.2%})"
        )
    
    return {
        "hypothesis": "H1",
        "description": "Agent achieves higher recall than baseline",
        "baseline_values": baseline_recalls,
        "agent_values": agent_recalls,
        "baseline_mean": round(float(baseline_mean), 4),
        "agent_mean": round(float(agent_mean), 4),
        "difference": round(float(agent_mean - baseline_mean), 4),
        "baseline_cv": baseline_cv,
        "agent_cv": agent_cv,
        "mann_whitney_u": mw_result,
        "cliffs_delta": cd_result,
        "verdict": verdict,
        "explanation": explanation
    }


def test_h2_precision(baseline_precisions: list, agent_precisions: list) -> dict:
    """
    Test H2: Agent maintains precision within 10pp of baseline.
    
    Includes sensitivity analysis at 5pp and 15pp thresholds
    per Decision Document Â§5.2.
    """
    logger.info("Testing H2: Agent precision within 10pp of baseline")
    
    baseline_mean = np.mean(baseline_precisions) if baseline_precisions else 0
    agent_mean = np.mean(agent_precisions) if agent_precisions else 0
    difference_pp = (agent_mean - baseline_mean) * 100
    baseline_cv = coefficient_of_variation(baseline_precisions)
    agent_cv = coefficient_of_variation(agent_precisions)
    
    mw_result = mann_whitney_u(baseline_precisions, agent_precisions)
    cd_result = cliffs_delta(baseline_precisions, agent_precisions)
    
    within_threshold = difference_pp >= -PRECISION_THRESHOLD_PP
    
    # Sensitivity analysis at 5pp and 15pp
    sensitivity = {
        "within_5pp": difference_pp >= -5,
        "within_10pp": difference_pp >= -10,
        "within_15pp": difference_pp >= -15,
    }
    
    if within_threshold:
        verdict = "SUPPORTED"
        explanation = (
            f"Agent precision ({agent_mean:.2%}) within "
            f"{PRECISION_THRESHOLD_PP}pp of baseline ({baseline_mean:.2%})"
        )
    else:
        verdict = "NOT_SUPPORTED"
        explanation = (
            f"Agent precision ({agent_mean:.2%}) more than "
            f"{PRECISION_THRESHOLD_PP}pp below baseline ({baseline_mean:.2%})"
        )
    
    return {
        "hypothesis": "H2",
        "description": f"Agent maintains precision within {PRECISION_THRESHOLD_PP}pp of baseline",
        "baseline_values": baseline_precisions,
        "agent_values": agent_precisions,
        "baseline_mean": round(float(baseline_mean), 4),
        "agent_mean": round(float(agent_mean), 4),
        "difference_pp": round(float(difference_pp), 2),
        "threshold_pp": PRECISION_THRESHOLD_PP,
        "within_threshold": within_threshold,
        "sensitivity": sensitivity,
        "baseline_cv": baseline_cv,
        "agent_cv": agent_cv,
        "mann_whitney_u": mw_result,
        "cliffs_delta": cd_result,
        "verdict": verdict,
        "explanation": explanation
    }


def test_h3a_requests(baseline_requests: list, agent_requests: list) -> dict:
    """Test H3a: Agent produces different HTTP request volume."""
    logger.info("Testing H3a: Significant difference in HTTP requests")
    
    mw_result = mann_whitney_u(baseline_requests, agent_requests)
    cd_result = cliffs_delta(baseline_requests, agent_requests)
    
    baseline_mean = np.mean(baseline_requests) if baseline_requests else 0
    agent_mean = np.mean(agent_requests) if agent_requests else 0
    baseline_cv = coefficient_of_variation(baseline_requests)
    agent_cv = coefficient_of_variation(agent_requests)
    
    if mw_result.get("significant"):
        direction = "more" if agent_mean > baseline_mean else "fewer"
        verdict = "SUPPORTED"
        explanation = (
            f"Significant difference: agent sends {direction} requests "
            f"({agent_mean:.0f} vs {baseline_mean:.0f})"
        )
    else:
        verdict = "NOT_SUPPORTED"
        explanation = (
            f"No significant difference in request volume "
            f"({agent_mean:.0f} vs {baseline_mean:.0f})"
        )
    
    return {
        "hypothesis": "H3a",
        "description": "Significant difference in HTTP request volume",
        "baseline_values": baseline_requests,
        "agent_values": agent_requests,
        "baseline_mean": round(float(baseline_mean), 2),
        "agent_mean": round(float(agent_mean), 2),
        "difference": round(float(agent_mean - baseline_mean), 2),
        "difference_pct": round(
            float((agent_mean - baseline_mean) / baseline_mean * 100), 2
        ) if baseline_mean > 0 else 0,
        "baseline_cv": baseline_cv,
        "agent_cv": agent_cv,
        "mann_whitney_u": mw_result,
        "cliffs_delta": cd_result,
        "verdict": verdict,
        "explanation": explanation
    }


def test_h3b_efficiency(
    baseline_efficiencies: list, agent_efficiencies: list
) -> dict:
    """
    Test H3b: Agent improves detection efficiency by â‰¥25%.
    
    Includes sensitivity analysis at 15% and 50% thresholds
    per Decision Document Â§5.2.
    """
    logger.info(f"Testing H3b: Agent efficiency â‰¥{EFFICIENCY_THRESHOLD_PCT}% better")
    
    mw_result = mann_whitney_u_one_sided(
        baseline_efficiencies, agent_efficiencies, 'less'
    )
    cd_result = cliffs_delta(baseline_efficiencies, agent_efficiencies)
    
    baseline_mean = np.mean(baseline_efficiencies) if baseline_efficiencies else 0
    agent_mean = np.mean(agent_efficiencies) if agent_efficiencies else 0
    baseline_cv = coefficient_of_variation(baseline_efficiencies)
    agent_cv = coefficient_of_variation(agent_efficiencies)
    
    improvement_pct = (
        ((agent_mean - baseline_mean) / baseline_mean * 100)
        if baseline_mean > 0 else 0
    )
    meets_threshold = improvement_pct >= EFFICIENCY_THRESHOLD_PCT
    
    # Sensitivity analysis at 15% and 50%
    sensitivity = {
        "meets_15pct": improvement_pct >= 15,
        "meets_25pct": improvement_pct >= 25,
        "meets_50pct": improvement_pct >= 50,
    }
    
    if meets_threshold and mw_result.get("significant"):
        verdict = "SUPPORTED"
        explanation = (
            f"Agent efficiency {improvement_pct:.1f}% better "
            f"(â‰¥{EFFICIENCY_THRESHOLD_PCT}% threshold), statistically significant"
        )
    elif meets_threshold:
        verdict = "PARTIALLY_SUPPORTED"
        explanation = (
            f"Agent efficiency {improvement_pct:.1f}% better "
            f"(meets threshold) but not statistically significant"
        )
    elif improvement_pct > 0:
        verdict = "PARTIALLY_SUPPORTED"
        explanation = (
            f"Agent efficiency improved ({improvement_pct:.1f}%) "
            f"but below {EFFICIENCY_THRESHOLD_PCT}% threshold"
        )
    else:
        verdict = "NOT_SUPPORTED"
        explanation = f"Agent efficiency not improved ({improvement_pct:.1f}%)"
    
    return {
        "hypothesis": "H3b",
        "description": f"Agent improves detection efficiency by â‰¥{EFFICIENCY_THRESHOLD_PCT}%",
        "baseline_values": baseline_efficiencies,
        "agent_values": agent_efficiencies,
        "baseline_mean": round(float(baseline_mean), 4),
        "agent_mean": round(float(agent_mean), 4),
        "improvement_pct": round(float(improvement_pct), 2),
        "threshold_pct": EFFICIENCY_THRESHOLD_PCT,
        "meets_threshold": meets_threshold,
        "sensitivity": sensitivity,
        "baseline_cv": baseline_cv,
        "agent_cv": agent_cv,
        "mann_whitney_u": mw_result,
        "cliffs_delta": cd_result,
        "verdict": verdict,
        "explanation": explanation
    }


# =============================================================================
# Analysis Pipeline
# =============================================================================

def analyze_experiment(evaluation: dict) -> dict:
    """Perform complete statistical analysis on experiment evaluation."""
    logger.info("=" * 60)
    logger.info("STATISTICAL ANALYSIS")
    logger.info("=" * 60)
    
    baseline_agg = evaluation.get("baseline", {}).get("aggregate", {})
    agent_agg = evaluation.get("agent", {}).get("aggregate", {})
    
    if not baseline_agg or not agent_agg:
        return {
            "error": "Missing baseline or agent aggregate data",
            "evaluation": evaluation
        }
    
    # Extract value arrays
    baseline_recalls = baseline_agg.get("recall", {}).get("values", [])
    agent_recalls = agent_agg.get("recall", {}).get("values", [])
    baseline_precisions = baseline_agg.get("precision", {}).get("values", [])
    agent_precisions = agent_agg.get("precision", {}).get("values", [])
    baseline_requests = baseline_agg.get("http_requests", {}).get("values", [])
    agent_requests = agent_agg.get("http_requests", {}).get("values", [])
    baseline_efficiencies = baseline_agg.get("detection_efficiency", {}).get("values", [])
    agent_efficiencies = agent_agg.get("detection_efficiency", {}).get("values", [])
    
    # Run hypothesis tests
    h1_result = test_h1_recall(baseline_recalls, agent_recalls)
    h2_result = test_h2_precision(baseline_precisions, agent_precisions)
    h3a_result = test_h3a_requests(baseline_requests, agent_requests)
    h3b_result = test_h3b_efficiency(baseline_efficiencies, agent_efficiencies)
    
    # Compute variability summary (CV for all metrics)
    variability = {
        "baseline": {
            "recall_cv": coefficient_of_variation(baseline_recalls),
            "precision_cv": coefficient_of_variation(baseline_precisions),
            "http_requests_cv": coefficient_of_variation(baseline_requests),
            "efficiency_cv": coefficient_of_variation(baseline_efficiencies),
        },
        "agent": {
            "recall_cv": coefficient_of_variation(agent_recalls),
            "precision_cv": coefficient_of_variation(agent_precisions),
            "http_requests_cv": coefficient_of_variation(agent_requests),
            "efficiency_cv": coefficient_of_variation(agent_efficiencies),
        }
    }
    
    analysis = {
        "sample_sizes": {
            "baseline": len(baseline_recalls),
            "agent": len(agent_recalls)
        },
        "alpha": ALPHA,
        "hypotheses": {
            "H1": h1_result,
            "H2": h2_result,
            "H3a": h3a_result,
            "H3b": h3b_result
        },
        "variability": variability,
        "summary": {
            "H1_verdict": h1_result["verdict"],
            "H2_verdict": h2_result["verdict"],
            "H3a_verdict": h3a_result["verdict"],
            "H3b_verdict": h3b_result["verdict"]
        }
    }
    
    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("HYPOTHESIS VERDICTS")
    logger.info("=" * 60)
    
    for h_id, h_result in analysis["hypotheses"].items():
        logger.info(f"\n{h_id}: {h_result['description']}")
        logger.info(f"  Verdict: {h_result['verdict']}")
        logger.info(f"  {h_result['explanation']}")
        if h_result.get("cliffs_delta", {}).get("delta") is not None:
            cd = h_result["cliffs_delta"]
            logger.info(f"  Effect size: Cliff's Delta = {cd['delta']:.3f} ({cd['magnitude']})")
        logger.info(f"  CV: baseline={h_result.get('baseline_cv', 'N/A')}%, agent={h_result.get('agent_cv', 'N/A')}%")
        if "sensitivity" in h_result:
            logger.info(f"  Sensitivity: {h_result['sensitivity']}")
    
    logger.info("\n" + "=" * 60)
    
    return analysis


def format_results_table(analysis: dict, format_type: str = "text") -> str:
    """Format analysis results as a table."""
    hypotheses = analysis.get("hypotheses", {})
    
    rows = []
    for h_id in ["H1", "H2", "H3a", "H3b"]:
        h = hypotheses.get(h_id, {})
        p_val = h.get('mann_whitney_u', {}).get('p_value')
        delta = h.get('cliffs_delta', {}).get('delta')
        rows.append({
            "Hypothesis": h_id,
            "Description": h.get("description", ""),
            "Baseline": f"{h.get('baseline_mean', 0):.3f}",
            "Agent": f"{h.get('agent_mean', 0):.3f}",
            "p-value": f"{p_val:.4f}" if p_val is not None else "N/A",
            "Cliff's Î´": f"{delta:.3f}" if delta is not None else "N/A",
            "Verdict": h.get("verdict", "")
        })
    
    cliff_key = "Cliff's Î´"
    
    if format_type == "markdown":
        lines = [
            "| Hypothesis | Baseline | Agent | p-value | Cliff's Î´ | Verdict |",
            "|------------|----------|-------|---------|-----------|---------|"
        ]
        for row in rows:
            cliff_val = row[cliff_key]
            lines.append(
                f"| {row['Hypothesis']} | {row['Baseline']} | {row['Agent']} "
                f"| {row['p-value']} | {cliff_val} | {row['Verdict']} |"
            )
        return "\n".join(lines)
    
    elif format_type == "latex":
        lines = [
            "\\begin{table}[h]",
            "\\centering",
            "\\caption{Hypothesis Test Results}",
            "\\begin{tabular}{lccccc}",
            "\\hline",
            "Hypothesis & Baseline & Agent & p-value & Cliff's $\\delta$ & Verdict \\\\",
            "\\hline"
        ]
        for row in rows:
            cliff_val = row[cliff_key]
            lines.append(
                f"{row['Hypothesis']} & {row['Baseline']} & {row['Agent']} "
                f"& {row['p-value']} & {cliff_val} & {row['Verdict']} \\\\"
            )
        lines.extend(["\\hline", "\\end{tabular}", "\\end{table}"])
        return "\n".join(lines)
    
    else:
        header = (
            f"{'Hypothesis':<12} {'Baseline':>10} {'Agent':>10} "
            f"{'p-value':>10} {'Cliff Î´':>10} {'Verdict':<20}"
        )
        separator = "-" * len(header)
        lines = [separator, header, separator]
        for row in rows:
            cliff_val = row[cliff_key]
            lines.append(
                f"{row['Hypothesis']:<12} {row['Baseline']:>10} {row['Agent']:>10} "
                f"{row['p-value']:>10} {cliff_val:>10} {row['Verdict']:<20}"
            )
        lines.append(separator)
        return "\n".join(lines)


def format_variability_table(analysis: dict) -> str:
    """Format CV variability summary as a text table."""
    variability = analysis.get("variability", {})
    if not variability:
        return "No variability data available."
    
    header = f"{'Metric':<25} {'Baseline CV%':>15} {'Agent CV%':>15}"
    separator = "-" * len(header)
    lines = [separator, header, separator]
    
    metrics = ["recall", "precision", "http_requests", "efficiency"]
    labels = ["Recall", "Precision", "HTTP Requests", "Detection Efficiency"]
    
    for metric, label in zip(metrics, labels):
        b_cv = variability.get("baseline", {}).get(f"{metric}_cv", "N/A")
        a_cv = variability.get("agent", {}).get(f"{metric}_cv", "N/A")
        lines.append(f"{label:<25} {b_cv:>15} {a_cv:>15}")
    
    lines.append(separator)
    return "\n".join(lines)


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Perform statistical analysis on experiment results"
    )
    parser.add_argument(
        "--evaluation",
        default="./results/evaluation.json",
        help="Evaluation JSON file"
    )
    parser.add_argument(
        "--output",
        default="./results/analysis.json",
        help="Output file"
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown", "latex"],
        default="text",
        help="Table format"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"Loading evaluation from: {args.evaluation}")
    with open(args.evaluation, 'r') as f:
        evaluation = json.load(f)
    
    analysis = analyze_experiment(evaluation)
    
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(analysis, f, indent=2)
    logger.info(f"Analysis saved to: {args.output}")
    
    print("\nHypothesis Test Results:")
    print(format_results_table(analysis, args.format))
    print("\nVariability (Coefficient of Variation):")
    print(format_variability_table(analysis))


if __name__ == "__main__":
    main()
