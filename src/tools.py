"""
ZAP Tool Wrappers for ReAct DAST Agent

This module provides tool abstractions for OWASP ZAP operations, specifically
configured for injection vulnerability detection. All active scanning is
restricted to injection-related vulnerability classes only.

Injection Vulnerability Scope:
    - SQL Injection (all database variants)
    - NoSQL Injection (MongoDB)
    - OS Command Injection
    - Server-Side Template Injection (SSTI)
    - LDAP Injection
    - XPath Injection
    - XML External Entity (XXE)

Explicitly Excluded:
    - Cross-Site Scripting (XSS)
    - Cross-Site Request Forgery (CSRF)
    - Authentication/Session vulnerabilities
    - Broken Access Control
    - Security Misconfiguration
    - All other OWASP Top 10 categories

Design Rationale:
    This focused scope ensures fair comparison between baseline static DAST
    execution and LLM-driven agentic orchestration by evaluating both
    conditions against the same ground truth vulnerability set.

Author: [Thesis Author]
Date: 2025
"""

import logging
import time
from typing import Any, Optional

import requests
from zapv2 import ZAPv2


# =============================================================================
# Module Configuration
# =============================================================================

# Configure module logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(handler)


# =============================================================================
# Injection Scanner Rule IDs
# =============================================================================
# These are the ONLY active scanner rules enabled during active scanning.
# All other rules are explicitly disabled to ensure injection-only detection.

INJECTION_SCANNER_RULES = {
    # SQL Injection Family
    40018: "SQL Injection",
    40019: "SQL Injection - SQLite",
    40020: "SQL Injection - Hypersonic SQL",
    40021: "SQL Injection - Oracle",
    40022: "SQL Injection - PostgreSQL",
    40023: "SQL Injection - MySQL",
    40024: "SQL Injection - Microsoft SQL Server",
    
    # NoSQL Injection
    40033: "NoSQL Injection - MongoDB",
    
    # Command Injection
    90020: "Remote OS Command Injection",
    
    # Template Injection
    90035: "Server Side Template Injection",
    
    # Directory/Protocol Injection
    40015: "LDAP Injection",
    90021: "XPath Injection",
    
    # XML Attacks
    90023: "XML External Entity Attack",
}

# CWE IDs associated with injection vulnerabilities for alert filtering
INJECTION_CWE_IDS = {
    77,    # Command Injection
    78,    # OS Command Injection
    89,    # SQL Injection
    90,    # LDAP Injection
    91,    # XML Injection
    94,    # Code Injection
    95,    # Eval Injection
    96,    # Static Code Injection
    97,    # Server-Side Includes Injection
    98,    # PHP File Inclusion
    99,    # Resource Injection
    113,   # HTTP Response Splitting
    134,   # Uncontrolled Format String
    564,   # SQL Injection: Hibernate
    611,   # XXE
    643,   # XPath Injection
    917,   # Expression Language Injection
    943,   # Improper Neutralization in Data Query Logic
    1236,  # CSV Injection
}

# Keywords for secondary alert filtering (case-insensitive matching)
INJECTION_ALERT_KEYWORDS = [
    "sql injection",
    "nosql injection",
    "mongodb injection",
    "command injection",
    "os command",
    "remote code execution",
    "rce",
    "template injection",
    "ssti",
    "server-side template",
    "ldap injection",
    "xpath injection",
    "xml external entity",
    "xxe",
    "xml injection",
    "code injection",
    "expression language injection",
    "el injection",
    "ognl injection",
    "hibernate injection",
    "hql injection",
]


# =============================================================================
# Tool 1: Authentication
# =============================================================================

def authenticate(
    zap: ZAPv2,
    target_url: str,
    username: str = "test@juice-sh.op",
    password: str = "test123",
    zap_proxy_url: str = "http://localhost:8080"
) -> dict:
    """
    Authenticate to the target application via JSON POST.
    
    Configures authentication for OWASP Juice Shop by sending credentials
    to the REST login endpoint and configuring ZAP to use the resulting
    JWT token for subsequent requests.
    
    Args:
        zap: ZAPv2 client instance
        target_url: Base URL of target application (e.g., http://localhost:3000)
        username: Email/username for authentication
        password: Password for authentication
        zap_proxy_url: ZAP proxy URL for routing requests
        
    Returns:
        dict: {
            "success": bool - Whether authentication succeeded
            "message": str - Status message or error description
            "token_configured": bool - Whether ZAP was configured with token
            "duration_seconds": float - Time taken for authentication
        }
        
    Example:
        >>> result = authenticate(zap, "http://localhost:3000")
        >>> if result["success"]:
        ...     print("Authenticated successfully")
    """
    start_time = time.time()
    logger.info(f"Authenticating to {target_url} as {username}...")
    
    try:
        # Construct login endpoint URL
        login_url = f"{target_url.rstrip('/')}/rest/user/login"
        
        # Configure proxy for request routing through ZAP
        proxies = {
            "http": zap_proxy_url,
            "https": zap_proxy_url
        }
        
        # Prepare authentication payload
        auth_payload = {
            "email": username,
            "password": password
        }
        
        # Send authentication request through ZAP proxy
        logger.debug(f"Sending POST to {login_url}")
        response = requests.post(
            login_url,
            json=auth_payload,
            proxies=proxies,
            timeout=30,
            verify=False  # Juice Shop typically uses self-signed certs
        )
        
        duration = time.time() - start_time
        
        # Check response status
        if response.status_code != 200:
            logger.warning(f"Authentication failed with status {response.status_code}")
            return {
                "success": False,
                "message": f"HTTP {response.status_code}: {response.text[:200]}",
                "token_configured": False,
                "duration_seconds": round(duration, 2)
            }
        
        # Parse response for token
        try:
            data = response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            return {
                "success": False,
                "message": f"Invalid JSON response: {e}",
                "token_configured": False,
                "duration_seconds": round(duration, 2)
            }
        
        # Extract JWT token from Juice Shop response structure
        token = None
        if "authentication" in data and "token" in data["authentication"]:
            token = data["authentication"]["token"]
        elif "token" in data:
            token = data["token"]
        
        if not token:
            logger.warning("No token found in authentication response")
            return {
                "success": False,
                "message": "Authentication response did not contain token",
                "token_configured": False,
                "duration_seconds": round(duration, 2)
            }
        
        # Configure ZAP to include Authorization header in all requests
        # Using ZAP's replacer to add Bearer token to request headers
        try:
            # Remove any existing auth rules first
            existing_rules = zap.replacer.rules
            for rule in existing_rules:
                if "Auth" in rule.get("description", ""):
                    zap.replacer.remove_rule(rule["description"])
            
            # Add new authorization header rule
            zap.replacer.add_rule(
                description="JWT Auth Token",
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                matchstring="Authorization",
                replacement=f"Bearer {token}",
                initiators=""
            )
            
            logger.info("JWT token configured in ZAP replacer")
            
        except Exception as e:
            logger.warning(f"Failed to configure ZAP replacer: {e}")
            # Authentication succeeded even if ZAP config failed
            return {
                "success": True,
                "message": f"Authenticated but ZAP config failed: {e}",
                "token_configured": False,
                "duration_seconds": round(duration, 2)
            }
        
        logger.info(f"Authentication successful in {duration:.2f}s")
        
        return {
            "success": True,
            "message": "Authentication successful, JWT token configured",
            "token_configured": True,
            "duration_seconds": round(duration, 2)
        }
        
    except requests.exceptions.Timeout:
        duration = time.time() - start_time
        logger.error("Authentication request timed out")
        return {
            "success": False,
            "message": "Request timed out after 30 seconds",
            "token_configured": False,
            "duration_seconds": round(duration, 2)
        }
        
    except requests.exceptions.ConnectionError as e:
        duration = time.time() - start_time
        logger.error(f"Connection error during authentication: {e}")
        return {
            "success": False,
            "message": f"Connection error: {e}",
            "token_configured": False,
            "duration_seconds": round(duration, 2)
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Unexpected error during authentication: {e}")
        return {
            "success": False,
            "message": f"Unexpected error: {e}",
            "token_configured": False,
            "duration_seconds": round(duration, 2)
        }


# =============================================================================
# Tool 2: Traditional Spider
# =============================================================================

def run_spider(
    zap: ZAPv2,
    target_url: str,
    max_depth: int = 10,
    max_children: int = 0,
    poll_interval: float = 2.0,
    timeout_minutes: float = 30.0
) -> dict:
    """
    Run ZAP traditional spider for URL discovery.
    
    The spider crawls the target application to discover URLs and endpoints
    that may contain injection points. This is a prerequisite for effective
    active scanning as it populates ZAP's site tree.
    
    Args:
        zap: ZAPv2 client instance
        target_url: Starting URL for spider crawl
        max_depth: Maximum crawl depth (default: 10)
        max_children: Maximum children per node, 0 for unlimited (default: 0)
        poll_interval: Seconds between progress polls (default: 2.0)
        timeout_minutes: Maximum spider duration in minutes (default: 30.0)
        
    Returns:
        dict: {
            "success": bool - Whether spider completed successfully
            "urls_found": int - Number of URLs discovered
            "duration_seconds": float - Time taken for spider crawl
            "scan_id": str - ZAP scan ID for reference
            "message": str - Status message
        }
        
    Example:
        >>> result = run_spider(zap, "http://localhost:3000", max_depth=5)
        >>> print(f"Discovered {result['urls_found']} URLs")
    """
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    
    logger.info(f"Starting spider on {target_url} (max_depth={max_depth})...")
    
    try:
        # Configure spider max depth before starting
        zap.spider.set_option_max_depth(max_depth)
        
        # Start the spider scan
        scan_id = zap.spider.scan(
            url=target_url,
            maxchildren=max_children,
            recurse=True,
            contextname=None,
            subtreeonly=False
        )
        
        logger.info(f"Spider started with scan ID: {scan_id}")
        
        # Poll for completion
        while True:
            elapsed = time.time() - start_time
            
            # Check timeout
            if elapsed >= timeout_seconds:
                logger.warning(f"Spider timeout after {timeout_minutes} minutes")
                try:
                    zap.spider.stop(scan_id)
                except Exception:
                    pass
                break
            
            # Check progress
            try:
                progress = int(zap.spider.status(scan_id))
            except (ValueError, TypeError):
                progress = 0
            
            logger.debug(f"Spider progress: {progress}% (elapsed: {elapsed:.1f}s)")
            
            if progress >= 100:
                logger.info("Spider completed successfully")
                break
            
            time.sleep(poll_interval)
        
        # Get results
        duration = time.time() - start_time
        
        try:
            spider_results = zap.spider.results(scan_id)
            urls_found = len(spider_results) if spider_results else 0
        except Exception as e:
            logger.warning(f"Failed to get spider results: {e}")
            urls_found = len(zap.core.urls())
        
        logger.info(f"Spider completed in {duration:.2f}s, found {urls_found} URLs")
        
        return {
            "success": True,
            "urls_found": urls_found,
            "duration_seconds": round(duration, 2),
            "scan_id": scan_id,
            "message": f"Spider completed, discovered {urls_found} URLs"
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Spider error: {e}")
        return {
            "success": False,
            "urls_found": 0,
            "duration_seconds": round(duration, 2),
            "scan_id": None,
            "message": f"Spider failed: {e}"
        }


# =============================================================================
# Tool 3: AJAX Spider
# =============================================================================

def run_ajax_spider(
    zap: ZAPv2,
    target_url: str,
    max_duration: int = 10,
    browser_id: str = "firefox-headless",
    poll_interval: float = 5.0
) -> dict:
    """
    Run ZAP AJAX spider for JavaScript-rendered content discovery.
    
    The AJAX spider uses a real browser to execute JavaScript and discover
    dynamically-generated content that the traditional spider cannot find.
    This is essential for modern SPAs like OWASP Juice Shop which heavily
    rely on client-side rendering.
    
    Args:
        zap: ZAPv2 client instance
        target_url: Starting URL for AJAX spider
        max_duration: Maximum crawl duration in minutes (default: 10)
        browser_id: Browser to use (default: firefox-headless)
            Options: firefox-headless, firefox, chrome-headless, chrome
        poll_interval: Seconds between status polls (default: 5.0)
        
    Returns:
        dict: {
            "success": bool - Whether AJAX spider completed
            "urls_found": int - Number of URLs discovered
            "duration_seconds": float - Time taken for crawl
            "final_status": str - Final spider status
            "message": str - Status message
        }
        
    Example:
        >>> result = run_ajax_spider(zap, "http://localhost:3000", max_duration=5)
        >>> print(f"AJAX spider found {result['urls_found']} URLs")
    """
    start_time = time.time()
    timeout_seconds = (max_duration + 2) * 60  # Add buffer for shutdown
    
    logger.info(
        f"Starting AJAX spider on {target_url} "
        f"(max_duration={max_duration}min, browser={browser_id})..."
    )
    
    try:
        # Configure AJAX spider options
        zap.ajaxSpider.set_option_max_duration(str(max_duration))
        zap.ajaxSpider.set_option_browser_id(browser_id)
        
        # Start AJAX spider
        zap.ajaxSpider.scan(url=target_url, inscope=True)
        
        logger.info("AJAX spider started")
        
        # Poll for completion
        while True:
            elapsed = time.time() - start_time
            
            # Check timeout
            if elapsed >= timeout_seconds:
                logger.warning("AJAX spider timeout, stopping...")
                try:
                    zap.ajaxSpider.stop()
                except Exception:
                    pass
                break
            
            # Check status
            status = zap.ajaxSpider.status
            logger.debug(f"AJAX spider status: {status} (elapsed: {elapsed:.1f}s)")
            
            if status != "running":
                logger.info(f"AJAX spider finished with status: {status}")
                break
            
            time.sleep(poll_interval)
        
        # Get results
        duration = time.time() - start_time
        
        try:
            results = zap.ajaxSpider.results()
            urls_found = len(results) if results else 0
        except Exception as e:
            logger.warning(f"Failed to get AJAX spider results: {e}")
            urls_found = 0
        
        final_status = zap.ajaxSpider.status
        
        logger.info(f"AJAX spider completed in {duration:.2f}s, found {urls_found} URLs")
        
        return {
            "success": True,
            "urls_found": urls_found,
            "duration_seconds": round(duration, 2),
            "final_status": final_status,
            "message": f"AJAX spider completed, discovered {urls_found} URLs"
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"AJAX spider error: {e}")
        return {
            "success": False,
            "urls_found": 0,
            "duration_seconds": round(duration, 2),
            "final_status": "error",
            "message": f"AJAX spider failed: {e}"
        }


# =============================================================================
# Tool 4: Active Scan (Injection-Only)
# =============================================================================

def run_active_scan(
    zap: ZAPv2,
    target_url: str,
    policy: str = "injection-only",
    poll_interval: float = 5.0,
    timeout_minutes: float = 60.0
) -> dict:
    """
    Run active scan configured for INJECTION vulnerabilities ONLY.
    
    CRITICAL: This function configures ZAP to scan ONLY for injection-related
    vulnerabilities. All other scanner rules are explicitly disabled to ensure
    the scan results align with the thesis scope and ground truth.
    
    Enabled Scanner Rules:
        - 40018: SQL Injection (Generic)
        - 40019: SQL Injection - SQLite
        - 40020: SQL Injection - Hypersonic SQL
        - 40021: SQL Injection - Oracle
        - 40022: SQL Injection - PostgreSQL
        - 40023: SQL Injection - MySQL
        - 40024: SQL Injection - Microsoft SQL Server
        - 40033: NoSQL Injection - MongoDB
        - 90020: Remote OS Command Injection
        - 90035: Server Side Template Injection
        - 40015: LDAP Injection
        - 90021: XPath Injection
        - 90023: XML External Entity Attack
    
    All other rules (XSS, CSRF, authentication, etc.) are DISABLED.
    
    Args:
        zap: ZAPv2 client instance
        target_url: URL to scan
        policy: Scan policy name (default: injection-only, created if not exists)
        poll_interval: Seconds between progress polls (default: 5.0)
        timeout_minutes: Maximum scan duration in minutes (default: 60.0)
        
    Returns:
        dict: {
            "success": bool - Whether scan completed
            "alerts_found": int - Number of injection alerts found
            "duration_seconds": float - Time taken for scan
            "requests_sent": int - Number of HTTP requests sent
            "scan_id": str - ZAP scan ID
            "progress": int - Final progress percentage
            "message": str - Status message
        }
        
    Example:
        >>> result = run_active_scan(zap, "http://localhost:3000")
        >>> print(f"Found {result['alerts_found']} injection vulnerabilities")
    """
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    
    logger.info(f"Starting INJECTION-ONLY active scan on {target_url}...")
    logger.info(f"Enabled rules: {list(INJECTION_SCANNER_RULES.keys())}")
    
    try:
        # Step 1: Configure injection-only scan policy
        _configure_injection_only_policy(zap, policy)
        
        # Get initial message count for requests calculation
        try:
            initial_messages = int(zap.core.number_of_messages())
        except (ValueError, TypeError):
            initial_messages = 0
        
        # Step 2: Start active scan with injection-only policy
        scan_id = zap.ascan.scan(
            url=target_url,
            recurse=True,
            inscopeonly=False,
            scanpolicyname=policy,
            method=None,
            postdata=None
        )
        
        logger.info(f"Active scan started with scan ID: {scan_id}")
        
        # Step 3: Poll for completion
        final_progress = 0
        while True:
            elapsed = time.time() - start_time
            
            # Check timeout
            if elapsed >= timeout_seconds:
                logger.warning(f"Active scan timeout after {timeout_minutes} minutes")
                try:
                    zap.ascan.stop(scan_id)
                except Exception:
                    pass
                break
            
            # Check progress
            try:
                progress = int(zap.ascan.status(scan_id))
                final_progress = progress
            except (ValueError, TypeError):
                progress = 0
            
            # Log progress periodically
            if int(elapsed) % 30 == 0:  # Log every 30 seconds
                logger.info(f"Active scan progress: {progress}% (elapsed: {elapsed:.1f}s)")
            else:
                logger.debug(f"Active scan progress: {progress}%")
            
            if progress >= 100:
                logger.info("Active scan completed successfully")
                break
            
            time.sleep(poll_interval)
        
        # Step 4: Collect results
        duration = time.time() - start_time
        
        # Get injection alerts only
        injection_alerts = _filter_injection_alerts(zap.core.alerts())
        alerts_found = len(injection_alerts)
        
        # Calculate requests sent
        try:
            final_messages = int(zap.core.number_of_messages())
            requests_sent = final_messages - initial_messages
        except (ValueError, TypeError):
            requests_sent = 0
        
        logger.info(
            f"Active scan completed in {duration:.2f}s: "
            f"{alerts_found} injection alerts, {requests_sent} requests"
        )
        
        return {
            "success": True,
            "alerts_found": alerts_found,
            "duration_seconds": round(duration, 2),
            "requests_sent": requests_sent,
            "scan_id": scan_id,
            "progress": final_progress,
            "message": f"Scan completed: {alerts_found} injection vulnerabilities found"
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Active scan error: {e}")
        return {
            "success": False,
            "alerts_found": 0,
            "duration_seconds": round(duration, 2),
            "requests_sent": 0,
            "scan_id": None,
            "progress": 0,
            "message": f"Active scan failed: {e}"
        }


def _configure_injection_only_policy(zap: ZAPv2, policy_name: str) -> None:
    """
    Configure ZAP scan policy to enable ONLY injection-related scanners.
    
    This is the critical function that ensures scan scope alignment with
    the thesis research focus. All non-injection scanners are disabled.
    
    Args:
        zap: ZAPv2 client instance
        policy_name: Name for the scan policy
    """
    logger.info(f"Configuring injection-only scan policy: {policy_name}")
    
    # Try to create new policy (may fail if exists, which is fine)
    try:
        zap.ascan.add_scan_policy(
            scanpolicyname=policy_name,
            alertthreshold="MEDIUM",
            attackstrength="MEDIUM"
        )
        logger.debug(f"Created new scan policy: {policy_name}")
    except Exception as e:
        logger.debug(f"Policy may already exist: {e}")
    
    # Get all available scanners
    try:
        all_scanners = zap.ascan.scanners(policy_name)
    except Exception:
        all_scanners = zap.ascan.scanners()
    
    # Step 1: DISABLE ALL scanners first
    logger.debug("Disabling all scanners...")
    disabled_count = 0
    for scanner in all_scanners:
        scanner_id = scanner.get("id")
        if scanner_id:
            try:
                # Set threshold to OFF to disable the scanner
                zap.ascan.set_scanner_alert_threshold(
                    id=scanner_id,
                    alertthreshold="OFF",
                    scanpolicyname=policy_name
                )
                disabled_count += 1
            except Exception as e:
                logger.debug(f"Could not disable scanner {scanner_id}: {e}")
    
    logger.info(f"Disabled {disabled_count} scanners")
    
    # Step 2: ENABLE ONLY injection scanners
    logger.debug("Enabling injection scanners only...")
    enabled_count = 0
    for rule_id, rule_name in INJECTION_SCANNER_RULES.items():
        try:
            # Enable the scanner with MEDIUM threshold
            zap.ascan.set_scanner_alert_threshold(
                id=rule_id,
                alertthreshold="MEDIUM",
                scanpolicyname=policy_name
            )
            # Set attack strength to MEDIUM
            zap.ascan.set_scanner_attack_strength(
                id=rule_id,
                attackstrength="MEDIUM",
                scanpolicyname=policy_name
            )
            enabled_count += 1
            logger.debug(f"Enabled scanner {rule_id}: {rule_name}")
        except Exception as e:
            logger.warning(f"Failed to enable scanner {rule_id} ({rule_name}): {e}")
    
    logger.info(
        f"Injection-only policy configured: "
        f"{enabled_count}/{len(INJECTION_SCANNER_RULES)} injection scanners enabled"
    )


# =============================================================================
# Tool 5: Get Alerts (Injection-Only)
# =============================================================================

def get_alerts(zap: ZAPv2, include_all: bool = False) -> dict:
    """
    Get current alerts, filtered to INJECTION vulnerabilities only.
    
    By default, this function filters out all non-injection alerts to ensure
    the results align with the thesis scope. Set include_all=True to get
    unfiltered alerts (useful for debugging).
    
    Filtering Logic:
        1. Check CWE ID against known injection CWEs
        2. Check alert name for injection-related keywords
        3. Alerts matching either criterion are included
    
    Args:
        zap: ZAPv2 client instance
        include_all: If True, return all alerts without filtering (default: False)
        
    Returns:
        dict: {
            "success": bool - Whether retrieval succeeded
            "count": int - Number of (filtered) alerts
            "alerts": list[dict] - List of alert details
            "by_risk": dict - Count by risk level
            "by_type": dict - Count by vulnerability type
            "message": str - Status message
        }
        
    Example:
        >>> result = get_alerts(zap)
        >>> for alert in result["alerts"]:
        ...     print(f"{alert['risk']}: {alert['name']} at {alert['url']}")
    """
    logger.info("Retrieving alerts...")
    
    try:
        # Get all alerts from ZAP
        all_alerts = zap.core.alerts()
        
        # Filter to injection alerts only (unless include_all is True)
        if include_all:
            filtered_alerts = all_alerts
            logger.debug(f"Returning all {len(all_alerts)} alerts (unfiltered)")
        else:
            filtered_alerts = _filter_injection_alerts(all_alerts)
            logger.debug(
                f"Filtered {len(all_alerts)} total alerts to "
                f"{len(filtered_alerts)} injection alerts"
            )
        
        # Format alerts for return
        formatted_alerts = []
        for alert in filtered_alerts:
            formatted_alerts.append({
                "id": alert.get("id"),
                "plugin_id": alert.get("pluginId"),
                "name": alert.get("name"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "method": alert.get("method"),
                "param": alert.get("param"),
                "attack": alert.get("attack", "")[:500],  # Truncate long attacks
                "evidence": alert.get("evidence", "")[:500],
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
                "description": alert.get("description", "")[:1000],
                "solution": alert.get("solution", "")[:500],
                "reference": alert.get("reference", "")[:500],
            })
        
        # Compute summaries
        by_risk = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        by_type = {}
        
        for alert in filtered_alerts:
            # Count by risk
            risk = alert.get("risk", "Informational")
            if risk in by_risk:
                by_risk[risk] += 1
            
            # Count by type
            name = alert.get("name", "Unknown")
            by_type[name] = by_type.get(name, 0) + 1
        
        logger.info(f"Retrieved {len(formatted_alerts)} injection alerts")
        
        return {
            "success": True,
            "count": len(formatted_alerts),
            "alerts": formatted_alerts,
            "by_risk": by_risk,
            "by_type": by_type,
            "message": f"Retrieved {len(formatted_alerts)} injection alerts"
        }
        
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        return {
            "success": False,
            "count": 0,
            "alerts": [],
            "by_risk": {},
            "by_type": {},
            "message": f"Failed to retrieve alerts: {e}"
        }


def _filter_injection_alerts(alerts: list[dict]) -> list[dict]:
    """
    Filter alerts to include only injection-related vulnerabilities.
    
    Uses dual filtering strategy:
        1. CWE ID matching against known injection CWEs
        2. Keyword matching in alert name
    
    Args:
        alerts: List of raw alert dictionaries from ZAP
        
    Returns:
        list[dict]: Filtered list containing only injection alerts
    """
    injection_alerts = []
    
    for alert in alerts:
        is_injection = False
        
        # Check 1: CWE ID matching
        try:
            cwe_id = int(alert.get("cweid", 0))
            if cwe_id in INJECTION_CWE_IDS:
                is_injection = True
        except (ValueError, TypeError):
            pass
        
        # Check 2: Keyword matching in alert name
        if not is_injection:
            name = alert.get("name", "").lower()
            for keyword in INJECTION_ALERT_KEYWORDS:
                if keyword in name:
                    is_injection = True
                    break
        
        # Check 3: Plugin ID matching (scanner rule IDs)
        if not is_injection:
            try:
                plugin_id = int(alert.get("pluginId", 0))
                if plugin_id in INJECTION_SCANNER_RULES:
                    is_injection = True
            except (ValueError, TypeError):
                pass
        
        if is_injection:
            injection_alerts.append(alert)
    
    return injection_alerts


# =============================================================================
# Tool 6: Get Status
# =============================================================================

def get_status(zap: ZAPv2) -> dict:
    """
    Get current ZAP state and scan status.
    
    Provides a comprehensive snapshot of ZAP's current state including
    discovered URLs, alerts, active scans, and HTTP message counts.
    
    Args:
        zap: ZAPv2 client instance
        
    Returns:
        dict: {
            "success": bool - Whether status retrieval succeeded
            "urls_found": int - Number of URLs in site tree
            "alerts": int - Total number of alerts
            "injection_alerts": int - Number of injection-related alerts
            "active_scans": int - Number of active scans running
            "messages": int - Total HTTP messages recorded
            "hosts": list[str] - List of discovered hosts
            "spider_status": str - Current spider status
            "ajax_spider_status": str - Current AJAX spider status
            "active_scan_status": str - Current active scan status
            "zap_version": str - ZAP version string
            "message": str - Status summary
        }
        
    Example:
        >>> status = get_status(zap)
        >>> print(f"URLs: {status['urls_found']}, Alerts: {status['injection_alerts']}")
    """
    logger.info("Getting ZAP status...")
    
    try:
        # Core statistics
        try:
            urls_resp = zap.core.urls()
            if isinstance(urls_resp, dict) and "urls" in urls_resp:
                urls_found = len(urls_resp["urls"])
            elif isinstance(urls_resp, list):
                urls_found = len(urls_resp)
            else:
                urls_found = 0
        except Exception:
            urls_found = 0
        
        try:
            total_alerts = int(zap.core.number_of_alerts())
        except (ValueError, TypeError):
            total_alerts = 0
        
        try:
            messages = int(zap.core.number_of_messages())
        except (ValueError, TypeError):
            messages = 0
        
        try:
            hosts = zap.core.hosts
        except Exception:
            hosts = []
        
        # Get injection-only alert count
        try:
            all_alerts = zap.core.alerts()
            injection_alerts = len(_filter_injection_alerts(all_alerts))
        except Exception:
            injection_alerts = 0
        
        # Spider status
        try:
            spider_scans = zap.spider.scans
            if spider_scans:
                latest_spider = spider_scans[-1]
                spider_status = f"{latest_spider.get('state', 'unknown')} ({latest_spider.get('progress', 0)}%)"
            else:
                spider_status = "not_started"
        except Exception:
            spider_status = "unknown"
        
        # AJAX spider status
        try:
            ajax_status = zap.ajaxSpider.status
        except Exception:
            ajax_status = "unknown"
        
        # Active scan status
        try:
            active_scans = zap.ascan.scans
            if active_scans:
                latest_scan = active_scans[-1]
                ascan_status = f"{latest_scan.get('state', 'unknown')} ({latest_scan.get('progress', 0)}%)"
                active_scan_count = sum(1 for s in active_scans if s.get("state") == "RUNNING")
            else:
                ascan_status = "not_started"
                active_scan_count = 0
        except Exception:
            ascan_status = "unknown"
            active_scan_count = 0
        
        # ZAP version
        try:
            zap_version = zap.core.version
        except Exception:
            zap_version = "unknown"
        
        status = {
            "success": True,
            "urls_found": urls_found,
            "alerts": total_alerts,
            "injection_alerts": injection_alerts,
            "active_scans": active_scan_count,
            "messages": messages,
            "hosts": hosts,
            "spider_status": spider_status,
            "ajax_spider_status": ajax_status,
            "active_scan_status": ascan_status,
            "zap_version": zap_version,
            "message": (
                f"URLs: {urls_found}, Total Alerts: {total_alerts}, "
                f"Injection Alerts: {injection_alerts}, Messages: {messages}"
            )
        }
        
        logger.info(status["message"])
        
        return status
        
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return {
            "success": False,
            "urls_found": 0,
            "alerts": 0,
            "injection_alerts": 0,
            "active_scans": 0,
            "messages": 0,
            "hosts": [],
            "spider_status": "error",
            "ajax_spider_status": "error",
            "active_scan_status": "error",
            "zap_version": "unknown",
            "message": f"Failed to get status: {e}"
        }


# =============================================================================
# Utility Functions
# =============================================================================

def verify_zap_connection(zap: ZAPv2) -> dict:
    """
    Verify that ZAP is accessible and responding.
    
    Args:
        zap: ZAPv2 client instance
        
    Returns:
        dict: {
            "success": bool - Whether ZAP is accessible
            "version": str - ZAP version if accessible
            "message": str - Status message
        }
    """
    try:
        version = zap.core.version
        return {
            "success": True,
            "version": version,
            "message": f"Connected to ZAP version {version}"
        }
    except Exception as e:
        return {
            "success": False,
            "version": None,
            "message": f"Failed to connect to ZAP: {e}"
        }


def clear_session(zap: ZAPv2) -> dict:
    """
    Clear the current ZAP session (alerts, URLs, etc.).
    
    Useful for resetting state between scan runs.
    
    Args:
        zap: ZAPv2 client instance
        
    Returns:
        dict: {
            "success": bool - Whether session was cleared
            "message": str - Status message
        }
    """
    try:
        zap.core.new_session(overwrite=True)
        return {
            "success": True,
            "message": "ZAP session cleared"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to clear session: {e}"
        }


def get_injection_rule_info() -> dict:
    """
    Get information about enabled injection scanner rules.
    
    Returns:
        dict: {
            "rules": dict - Mapping of rule IDs to names
            "cwes": set - Set of injection-related CWE IDs
            "keywords": list - Keywords used for alert filtering
        }
    """
    return {
        "rules": INJECTION_SCANNER_RULES.copy(),
        "cwes": INJECTION_CWE_IDS.copy(),
        "keywords": INJECTION_ALERT_KEYWORDS.copy()
    }


# =============================================================================
# Module Self-Test
# =============================================================================

if __name__ == "__main__":
    """
    Quick self-test to verify module structure.
    Does not require ZAP to be running.
    """
    print("ZAP Tools Module - Injection-Only Configuration")
    print("=" * 60)
    print("\nEnabled Injection Scanner Rules:")
    for rule_id, rule_name in INJECTION_SCANNER_RULES.items():
        print(f"  {rule_id}: {rule_name}")
    
    print(f"\nTotal injection rules: {len(INJECTION_SCANNER_RULES)}")
    print(f"Injection CWE IDs tracked: {len(INJECTION_CWE_IDS)}")
    print(f"Alert filter keywords: {len(INJECTION_ALERT_KEYWORDS)}")
    
    print("\nAvailable functions:")
    print("  - authenticate(zap, target_url, username, password)")
    print("  - run_spider(zap, target_url, max_depth)")
    print("  - run_ajax_spider(zap, target_url, max_duration)")
    print("  - run_active_scan(zap, target_url, policy)")
    print("  - get_alerts(zap)")
    print("  - get_status(zap)")
    print("\nModule loaded successfully.")
