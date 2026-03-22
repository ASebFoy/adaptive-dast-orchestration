"""
ReAct DAST Agent for LLM-Driven Security Testing Orchestration

This module implements a ReAct (Reasoning + Acting) agent that orchestrates
OWASP ZAP for dynamic application security testing, focusing exclusively
on injection vulnerability detection.

Architecture Components:
    - Agent Core: ReAct loop implementation with state management
    - LLM Reasoning Interface: GPT-4o integration for decision making
    - Tool Abstraction Layer: ZAP API wrapper methods
    - DAST Execution Environment: ZAP scanner coordination

Usage:
    config = {
        "zap_api_key": "your-zap-api-key",
        "zap_url": "http://localhost:8080",
        "openai_api_key": "your-openai-api-key",
        "target_url": "http://localhost:3000",
        "max_iterations": 50,
        "max_tokens": 100000,
        "time_limit_minutes": 60,
        "temperature": 0
    }
    agent = ReActDastAgent(config)
    results = agent.run()

Author: Anton Sebastian Foy
Date: 2025
"""

import json
import os
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import requests
from openai import OpenAI
from zapv2 import ZAPv2


# =============================================================================
# Configuration and Constants
# =============================================================================

SYSTEM_PROMPT = """You are an autonomous security testing agent orchestrating OWASP ZAP to detect INJECTION vulnerabilities in a web application. Your objective is to maximise detection coverage of injection points including SQL injection, NoSQL injection, command injection, template injection, LDAP injection, XPath injection, and XXE vulnerabilities.

Focus EXCLUSIVELY on injection types. Do NOT scan for or report other vulnerability classes like XSS, CSRF, or authentication issues.

Available tools:
- authenticate: Log in to the target application using pre-configured test credentials. Args: {} (leave empty - credentials are already configured)
- run_spider: Crawl the application to discover URLs and endpoints. Args: {"max_depth": int}
- run_ajax_spider: Crawl JavaScript-rendered content using a headless browser. Args: {"max_duration": int}
- run_active_scan: Execute active scanning with injection-specific payloads. Args: {"target": str (optional)}
- get_alerts: Retrieve current injection vulnerability findings. Args: {}
- get_status: Get comprehensive status of the scanner and agent state. Args: {}
- complete: Signal that testing is finished. Args: {"reason": str}

Constraints:
- You may ONLY use the tools listed above. Do not attempt other actions.
- You cannot generate custom payloads or access capabilities beyond the defined tools.
- All scanning is restricted to the target application domain.
- Reason about what actions will maximise injection detection given the current state.

Output format â€” you MUST use exactly this structure:
THOUGHT: [your reasoning about current state and what to do next]
ACTION: [tool_name]
ARGS: {"key": "value"}

When you have completed testing and gathered sufficient results, use ACTION: complete with ARGS: {"reason": "explanation"}."""

# Ground truth aligned injection rule IDs (SQL + NoSQL only)
# SQL Injection rules: 40018-40024
# NoSQL Injection rule: 40033
# These are the ONLY rules that align with thesis ground truth
SQL_INJECTION_RULE_IDS = {40018, 40019, 40020, 40021, 40022, 40023, 40024}
NOSQL_INJECTION_RULE_IDS = {40033}
GROUND_TRUTH_INJECTION_RULE_IDS = SQL_INJECTION_RULE_IDS | NOSQL_INJECTION_RULE_IDS


class TerminationReason(Enum):
    """Enumeration of possible agent termination reasons."""
    MAX_ITERATIONS = "max_iterations_reached"
    TOKEN_BUDGET = "token_budget_exhausted"
    COST_LIMIT = "cost_limit_exceeded"
    TIME_LIMIT = "time_limit_exceeded"
    AGENT_FINISHED = "agent_initiated_finish"
    ERROR = "unrecoverable_error"


@dataclass
class AgentState:
    """Tracks the current state of the ReAct agent execution."""
    iteration: int = 0
    tokens_used: int = 0
    prompt_tokens_used: int = 0
    completion_tokens_used: int = 0
    cost_usd: float = 0.0
    start_time: float = field(default_factory=time.time)
    is_authenticated: bool = False
    spider_completed: bool = False
    ajax_spider_completed: bool = False
    active_scan_completed: bool = False
    urls_discovered: int = 0
    alerts_found: int = 0
    termination_reason: Optional[TerminationReason] = None
    
    @property
    def elapsed_minutes(self) -> float:
        """Calculate elapsed time in minutes since agent start."""
        return (time.time() - self.start_time) / 60


@dataclass
class TranscriptEntry:
    """Single entry in the reasoning transcript."""
    iteration: int
    timestamp: str
    observation: dict
    thought: str
    action: str
    args: dict
    result: dict
    tokens_this_call: int


# =============================================================================
# Main Agent Class
# =============================================================================

class ReActDastAgent:
    """
    ReAct-based DAST orchestration agent using GPT-4o for reasoning.
    
    This agent implements the ReAct (Reasoning + Acting) framework to
    intelligently orchestrate OWASP ZAP for injection vulnerability
    detection. The agent observes the current scanner state, reasons
    about the next action using GPT-4o, and executes the chosen tool.
    
    Attributes:
        config: Configuration dictionary containing API keys and parameters
        zap: ZAPv2 API client instance
        openai_client: OpenAI API client instance
        state: Current agent execution state
        transcript: List of reasoning transcript entries
        logger: Logger instance for this agent
        
    Example:
        >>> config = {"zap_api_key": "key", "openai_api_key": "key", ...}
        >>> agent = ReActDastAgent(config)
        >>> results = agent.run()
        >>> print(f"Found {len(results['alerts'])} injection vulnerabilities")
    """
    
    def __init__(self, config: dict) -> None:
        """
        Initialize the ReAct DAST agent with configuration.
        
        Args:
            config: Dictionary containing:
                - zap_api_key: API key for ZAP authentication
                - zap_url: ZAP proxy URL (default: http://localhost:8080)
                - openai_api_key: OpenAI API key for GPT-4o
                - target_url: Target application URL to scan
                - max_iterations: Maximum agent iterations (default: 50)
                - max_tokens: Token budget limit (default: 100000)
                - cost_limit_usd: Cost limit in USD (default: 5.00)
                - time_limit_minutes: Time limit in minutes (default: 60)
                - temperature: LLM temperature (default: 0 for deterministic)
        """
        self.config = config
        
        # Initialize ZAP client
        zap_url = config.get("zap_url", "http://localhost:8080")
        zap_api_key = config.get("zap_api_key", "")
        self.zap = ZAPv2(apikey=zap_api_key, proxies={"http": zap_url, "https": zap_url})
        
        # Initialize OpenAI client
        openai_api_key = config.get("openai_api_key", "")
        self.openai_client = OpenAI(api_key=openai_api_key)
        
        # Configuration parameters
        self.target_url = config.get("target_url", "http://localhost:3000")
        self.max_iterations = config.get("max_iterations", 50)
        self.max_tokens = config.get("max_tokens", 100000)
        self.cost_limit_usd = config.get("cost_limit_usd", 5.00)
        self.time_limit_minutes = config.get("time_limit_minutes", 60)
        self.temperature = config.get("temperature", 0)
        
        # State management
        self.state = AgentState()
        self.transcript: list[TranscriptEntry] = []
        
        # Logging
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # File logging (optional, configured via setup_file_logging)
        self.file_handler: Optional[logging.FileHandler] = None
        
        self.logger.info("ReAct DAST Agent initialized")
        self.logger.info(f"  Target URL: {self.target_url}")
        self.logger.info(f"  Max iterations: {self.max_iterations}")
        self.logger.info(f"  Token budget: {self.max_tokens}")
        self.logger.info(f"  Time limit: {self.time_limit_minutes} minutes")
    
    def setup_file_logging(self, output_dir: str) -> None:
        """
        Configure file logging for agent execution.
        
        Args:
            output_dir: Directory where log file will be created
        """
        os.makedirs(output_dir, exist_ok=True)
        log_file = os.path.join(
            output_dir,
            f"agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        self.file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.file_handler.setFormatter(formatter)
        self.logger.addHandler(self.file_handler)
        
        self.logger.info(f"File logging configured: {log_file}")
    
    def cleanup_file_logging(self) -> None:
        """Remove file handler from logger."""
        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
            self.file_handler.close()
            self.file_handler = None
    
    # =========================================================================
    # Agent Execution
    # =========================================================================
    
    def run(self) -> dict:
        """
        Execute the ReAct agent loop.
        
        Returns:
            Complete execution results including alerts, metrics, and transcript
        """
        self.logger.info("=" * 60)
        self.logger.info("STARTING REACT DAST AGENT EXECUTION")
        self.logger.info("=" * 60)
        
        try:
            # Configure injection-only scan policy
            self._configure_injection_policy()
            
            # Main ReAct loop
            while not self._should_terminate():
                self.state.iteration += 1
                self.logger.info(f"\n{'=' * 40}")
                self.logger.info(f"ITERATION {self.state.iteration}")
                self.logger.info(f"{'=' * 40}")
                
                # Observe current state
                observation = self._observe()
                
                # Get next action from LLM
                thought, action, args, tokens_used = self._reason(observation)
                
                # Execute action
                result = self._act(action, args)
                
                # Log iteration
                self._log_iteration(
                    self.state.iteration,
                    observation,
                    thought,
                    action,
                    args,
                    result,
                    tokens_used
                )
                
                # Update state
                self._update_state(result, tokens_used)
            
            # Compile final results
            results = self._compile_results()
            
            return results
            
        except Exception as e:
            self.logger.error(f"Fatal error in agent execution: {e}")
            self.state.termination_reason = TerminationReason.ERROR
            return self._compile_results()
    
    def _should_terminate(self) -> bool:
        """Check if agent should terminate based on limits or completion."""
        if self.state.termination_reason:
            return True
        
        if self.state.iteration >= self.max_iterations:
            self.logger.warning(f"Max iterations ({self.max_iterations}) reached")
            self.state.termination_reason = TerminationReason.MAX_ITERATIONS
            return True
        
        if self.state.tokens_used >= self.max_tokens:
            self.logger.warning(f"Token budget ({self.max_tokens}) exhausted")
            self.state.termination_reason = TerminationReason.TOKEN_BUDGET
            return True
        
        if self.state.cost_usd >= self.cost_limit_usd:
            self.logger.warning(f"Cost limit (${self.cost_limit_usd}) exceeded")
            self.state.termination_reason = TerminationReason.COST_LIMIT
            return True
        
        if self.state.elapsed_minutes >= self.time_limit_minutes:
            self.logger.warning(f"Time limit ({self.time_limit_minutes} minutes) exceeded")
            self.state.termination_reason = TerminationReason.TIME_LIMIT
            return True
        
        return False
    
    def _observe(self) -> dict:
        """
        Observe the current state of ZAP and the scanning process.
        
        Returns:
            Observation dictionary containing current state information
        """
        try:
            urls = self.zap.core.urls()
            alerts = self._get_injection_alerts()
            
            observation = {
                "iteration": self.state.iteration,
                "elapsed_minutes": round(self.state.elapsed_minutes, 2),
                "is_authenticated": self.state.is_authenticated,
                "spider_completed": self.state.spider_completed,
                "ajax_spider_completed": self.state.ajax_spider_completed,
                "active_scan_completed": self.state.active_scan_completed,
                "urls_discovered": len(urls),
                "injection_alerts_count": len(alerts),
                "tokens_used": self.state.tokens_used,
                "tokens_remaining": self.max_tokens - self.state.tokens_used
            }
            
            # Add alert summary if any exist
            if alerts:
                observation["alerts_summary"] = {
                    "by_risk": self._summarize_alerts_by_risk(alerts),
                    "by_type": self._summarize_alerts_by_type(alerts)
                }
            
            return observation
            
        except Exception as e:
            self.logger.error(f"Error in observation: {e}")
            return {
                "error": str(e),
                "iteration": self.state.iteration
            }
    
    def _reason(self, observation: dict) -> tuple[str, str, dict, int]:
        """
        Use LLM to reason about next action based on observation.
        
        Args:
            observation: Current state observation
            
        Returns:
            Tuple of (thought, action, args, tokens_used)
        """
        # Build conversation history
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]
        
        # Add observation
        observation_text = f"Current state:\n{json.dumps(observation, indent=2)}"
        messages.append({"role": "user", "content": observation_text})
        
        # Call OpenAI API
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=self.temperature,
                max_tokens=2000
            )
            
            # Extract response
            content = response.choices[0].message.content
            
            # Calculate tokens and cost
            prompt_tokens = response.usage.prompt_tokens
            completion_tokens = response.usage.completion_tokens
            total_tokens = response.usage.total_tokens
            
            # GPT-4o pricing (as of 2025)
            cost = (prompt_tokens * 2.50 / 1_000_000) + (completion_tokens * 10.00 / 1_000_000)
            
            self.state.prompt_tokens_used += prompt_tokens
            self.state.completion_tokens_used += completion_tokens
            self.state.cost_usd += cost
            
            # Parse response
            thought, action, args = self._parse_llm_response(content)
            
            self.logger.info(f"LLM Response:")
            self.logger.info(f"  Thought: {thought[:200]}{'...' if len(thought) > 200 else ''}")
            self.logger.info(f"  Action: {action}")
            self.logger.info(f"  Args: {json.dumps(args)}")
            self.logger.info(f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
            self.logger.info(f"  Cost: ${cost:.6f}")
            
            return thought, action, args, total_tokens
            
        except Exception as e:
            self.logger.error(f"Error in reasoning: {e}")
            return f"Error: {e}", "get_status", {}, 0
    
    def _parse_llm_response(self, content: str) -> tuple[str, str, dict]:
        """
        Parse LLM response into thought, action, and args.
        
        Args:
            content: Raw LLM response text
            
        Returns:
            Tuple of (thought, action, args)
        """
        # Extract THOUGHT
        thought_match = re.search(r'THOUGHT:\s*(.+?)(?=ACTION:|$)', content, re.DOTALL | re.IGNORECASE)
        thought = thought_match.group(1).strip() if thought_match else "No thought provided"
        
        # Extract ACTION
        action_match = re.search(r'ACTION:\s*(\w+)', content, re.IGNORECASE)
        action = action_match.group(1).strip() if action_match else "get_status"
        
        # Extract ARGS
        args_match = re.search(r'ARGS:\s*(\{.+?\})', content, re.DOTALL | re.IGNORECASE)
        if args_match:
            try:
                args = json.loads(args_match.group(1))
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse ARGS JSON, using empty dict")
                args = {}
        else:
            args = {}
        
        return thought, action, args
    
    def _act(self, action: str, args: dict) -> dict:
        """
        Execute the specified action with given arguments.
        
        Args:
            action: Action name to execute
            args: Arguments for the action
            
        Returns:
            Result dictionary from action execution
        """
        self.logger.info(f"Executing action: {action}({json.dumps(args)})")
        
        # Map action names to methods
        action_map = {
            "authenticate": self.authenticate,
            "run_spider": self.run_spider,
            "run_ajax_spider": self.run_ajax_spider,
            "run_active_scan": self.run_active_scan,
            "get_alerts": self.get_alerts,
            "get_status": self.get_status,
            "complete": self.complete
        }
        
        # Execute action
        if action in action_map:
            try:
                method = action_map[action]
                result = method(**args)
                return result
            except TypeError as e:
                self.logger.error(f"Invalid arguments for {action}: {e}")
                return {
                    "success": False,
                    "error": f"Invalid arguments: {e}"
                }
        else:
            self.logger.warning(f"Unknown action: {action}")
            return {
                "success": False,
                "error": f"Unknown action: {action}"
            }
    
    def _update_state(self, result: dict, tokens_used: int) -> None:
        """
        Update agent state based on action result.
        
        Args:
            result: Result from action execution
            tokens_used: Tokens consumed in this iteration
        """
        self.state.tokens_used += tokens_used
        
        # Update URL count
        try:
            self.state.urls_discovered = len(self.zap.core.urls())
        except Exception:
            pass
        
        # Update alert count
        try:
            self.state.alerts_found = len(self._get_injection_alerts())
        except Exception:
            pass
    
    # =========================================================================
    # Tool Methods (Actions)
    # =========================================================================
    
    def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> dict:
        """
        Authenticate to the target application.
        
        Args:
            username: Email/username for authentication (default from env or test@juice-sh.op)
            password: Password for authentication (default from env or test123)
            
        Returns:
            Dictionary with authentication result
        """
        if username is None:
            username = os.getenv("TEST_USER_EMAIL", "test@juice-sh.op")
        if password is None:
            password = os.getenv("TEST_USER_PASSWORD", "test123")
        self.logger.info(f"Authenticating as {username}...")
        
        try:
            # Send login request through ZAP proxy
            login_url = f"{self.target_url}/rest/user/login"
            
            # Get ZAP proxy settings
            zap_proxy = self.config.get("zap_url", "http://localhost:8080")
            proxies = {
                "http": zap_proxy,
                "https": zap_proxy
            }
            
            response = requests.post(
                login_url,
                json={"email": username, "password": password},
                proxies=proxies,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                if "authentication" in data and "token" in data["authentication"]:
                    token = data["authentication"]["token"]
                    
                    # Add authorization header to ZAP requests
                    self.zap.replacer.add_rule(
                        description="Auth Token",
                        enabled="true",
                        matchtype="REQ_HEADER",
                        matchregex="false",
                        matchstring="Authorization",
                        replacement=f"Bearer {token}",
                        initiators=""
                    )
                    
                    self.state.is_authenticated = True
                    self.logger.info("Authentication successful")
                    
                    return {
                        "success": True,
                        "message": "Authentication successful",
                        "token_received": True
                    }
            
            self.logger.warning(f"Authentication failed: {response.status_code}")
            return {
                "success": False,
                "error": f"Authentication failed with status {response.status_code}",
                "response": response.text[:500] if response.text else None
            }
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def run_spider(self, max_depth: int = 10) -> dict:
        """
        Run the traditional ZAP spider for URL discovery.
        
        Args:
            max_depth: Maximum crawl depth (default: 10)
            
        Returns:
            Dictionary with spider execution result
        """
        self.logger.info(f"Starting spider with max_depth={max_depth}...")
        
        try:
            # Configure spider max depth before starting
            self.zap.spider.set_option_max_depth(max_depth)
            
            # Start the spider (subtreeonly=True enforces domain scope constraint Â§5.7)
            scan_id = self.zap.spider.scan(
                url=self.target_url,
                maxchildren=0,
                recurse=True,
                contextname=None,
                subtreeonly=True
            )
            
            self.logger.info(f"Spider started with scan ID: {scan_id}")
            
            # Wait for spider to complete
            while True:
                progress = int(self.zap.spider.status(scan_id))
                self.logger.info(f"Spider progress: {progress}%")
                
                if progress >= 100:
                    break
                    
                if self.state.elapsed_minutes >= self.time_limit_minutes:
                    self.zap.spider.stop(scan_id)
                    self.logger.warning("Spider stopped due to time limit")
                    break
                    
                time.sleep(5)
            
            # Get results
            urls_found = self.zap.core.urls()
            
            self.state.spider_completed = True
            self.state.urls_discovered = len(urls_found)
            self.logger.info(f"Spider completed. URLs found: {len(urls_found)}")
            
            return {
                "success": True,
                "message": "Spider completed",
                "urls_found": len(urls_found),
                "scan_id": scan_id
            }
            
        except Exception as e:
            self.logger.error(f"Spider error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def run_ajax_spider(self, max_duration: int = 10) -> dict:
        """
        Run the AJAX spider for JavaScript-rendered content discovery.
        
        Args:
            max_duration: Maximum duration in minutes (default: 10)
            
        Returns:
            Dictionary with AJAX spider execution result
        """
        self.logger.info(f"Starting AJAX spider with max_duration={max_duration} minutes...")
        
        try:
            # Configure AJAX spider
            self.zap.ajaxSpider.set_option_max_duration(str(max_duration))
            
            # Start AJAX spider
            self.zap.ajaxSpider.scan(
                url=self.target_url,
                inscope=None,
                contextname=None,
                subtreeonly=None
            )
            
            self.logger.info("AJAX spider started")
            
            # Wait for completion
            while self.zap.ajaxSpider.status == "running":
                urls_count = int(self.zap.ajaxSpider.number_of_results)
                self.logger.info(f"AJAX spider running... URLs found: {urls_count}")
                
                if self.state.elapsed_minutes >= self.time_limit_minutes:
                    self.zap.ajaxSpider.stop()
                    self.logger.warning("AJAX spider stopped due to time limit")
                    break
                    
                time.sleep(10)
            
            # Get results
            urls_found = self.zap.core.urls()
            
            self.state.ajax_spider_completed = True
            self.state.urls_discovered = len(urls_found)
            self.logger.info(f"AJAX spider completed. Total URLs: {len(urls_found)}")
            
            return {
                "success": True,
                "message": "AJAX spider completed",
                "urls_found": len(urls_found)
            }
            
        except Exception as e:
            self.logger.error(f"AJAX spider error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def run_active_scan(self, target: Optional[str] = None) -> dict:
        """
        Run active scan with injection-only policy.
        
        Args:
            target: Specific URL to scan (default: entire discovered site)
            
        Returns:
            Dictionary with active scan execution result
        """
        scan_target = target or self.target_url
        self.logger.info(f"Starting active scan on: {scan_target}")
        
        try:
            # Start active scan with injection-only policy
            scan_id = self.zap.ascan.scan(
                url=scan_target,
                recurse=True,
                inscopeonly=None,
                scanpolicyname="injection-only",
                method=None,
                postdata=None,
                contextid=None
            )
            
            self.logger.info(f"Active scan started with ID: {scan_id}")
            
            # Wait for scan to complete
            while True:
                progress = int(self.zap.ascan.status(scan_id))
                self.logger.info(f"Active scan progress: {progress}%")
                
                if progress >= 100:
                    break
                    
                if self.state.elapsed_minutes >= self.time_limit_minutes:
                    self.zap.ascan.stop(scan_id)
                    self.logger.warning("Active scan stopped due to time limit")
                    break
                    
                time.sleep(10)
            
            # Get scan stats
            alerts = self._get_injection_alerts()
            
            self.state.active_scan_completed = True
            self.logger.info(f"Active scan completed. Injection alerts: {len(alerts)}")
            
            return {
                "success": True,
                "message": "Active scan completed",
                "injection_alerts_found": len(alerts),
                "scan_id": scan_id,
                "final_progress": progress
            }
            
        except Exception as e:
            self.logger.error(f"Active scan error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _configure_injection_policy(self) -> None:
        """Configure ZAP scan policy to only enable ground-truth aligned injection scanners."""
        # Ground truth injection scanner rule IDs ONLY
        # SQL injection: 40018-40024
        # NoSQL injection: 40033
        injection_rules = list(GROUND_TRUTH_INJECTION_RULE_IDS)
        
        try:
            # Try to add a new policy (may fail if exists)
            try:
                self.zap.ascan.add_scan_policy(
                    scanpolicyname="injection-only",
                    alertthreshold="MEDIUM",
                    attackstrength="MEDIUM"
                )
            except Exception:
                pass  # Policy may already exist
            
            # Disable all scanners first by setting alert threshold to OFF
            for scanner in self.zap.ascan.scanners("injection-only"):
                scanner_id = scanner.get("id")
                if scanner_id:
                    self.zap.ascan.set_scanner_alert_threshold(
                        id=scanner_id,
                        alertthreshold="OFF",
                        scanpolicyname="injection-only"
                    )
            
            # Enable only ground-truth aligned injection scanners
            for rule_id in injection_rules:
                try:
                    self.zap.ascan.set_scanner_attack_strength(
                        id=rule_id,
                        attackstrength="MEDIUM",
                        scanpolicyname="injection-only"
                    )
                    self.zap.ascan.set_scanner_alert_threshold(
                        id=rule_id,
                        alertthreshold="MEDIUM",
                        scanpolicyname="injection-only"
                    )
                except Exception as e:
                    self.logger.warning(f"Could not configure scanner {rule_id}: {e}")
            
            self.logger.info(f"Configured injection-only policy with {len(injection_rules)} scanners")
            
        except Exception as e:
            self.logger.error(f"Error configuring scan policy: {e}")
    
    def get_alerts(self) -> dict:
        """
        Get current injection vulnerability alerts.
        
        Returns:
            Dictionary containing filtered injection alerts
        """
        self.logger.info("Retrieving injection alerts...")
        
        try:
            alerts = self._get_injection_alerts()
            
            # Format alerts for return
            formatted_alerts = []
            for alert in alerts:
                formatted_alerts.append({
                    "name": alert.get("name"),
                    "pluginId": alert.get("pluginId"),
                    "risk": alert.get("risk"),
                    "confidence": alert.get("confidence"),
                    "url": alert.get("url"),
                    "param": alert.get("param"),
                    "attack": alert.get("attack", "")[:200],  # Truncate long attacks
                    "evidence": alert.get("evidence", "")[:200],
                    "cweid": alert.get("cweid"),
                    "description": alert.get("description", "")[:300]
                })
            
            return {
                "success": True,
                "total_alerts": len(formatted_alerts),
                "alerts": formatted_alerts,
                "by_risk": self._summarize_alerts_by_risk(alerts),
                "by_type": self._summarize_alerts_by_type(alerts)
            }
            
        except Exception as e:
            self.logger.error(f"Error retrieving alerts: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_status(self) -> dict:
        """
        Get comprehensive current status of the agent and ZAP.
        
        Returns:
            Dictionary containing full status information
        """
        self.logger.info("Getting status...")
        
        try:
            return {
                "success": True,
                "agent": {
                    "iteration": self.state.iteration,
                    "elapsed_minutes": round(self.state.elapsed_minutes, 2),
                    "time_remaining_minutes": round(
                        self.time_limit_minutes - self.state.elapsed_minutes, 2
                    ),
                    "tokens_used": self.state.tokens_used,
                    "tokens_remaining": self.max_tokens - self.state.tokens_used,
                    "is_authenticated": self.state.is_authenticated,
                    "spider_completed": self.state.spider_completed,
                    "ajax_spider_completed": self.state.ajax_spider_completed,
                    "active_scan_completed": self.state.active_scan_completed,
                },
                "zap": {
                    "version": self.zap.core.version,
                    "urls_discovered": len(self.zap.core.urls()),
                    "messages_count": self.zap.core.number_of_messages(),
                    "total_alerts": self.zap.core.number_of_alerts(),
                    "injection_alerts": len(self._get_injection_alerts())
                },
                "progress_summary": self._get_progress_summary()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting status: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def complete(self, reason: str) -> dict:
        """
        Signal agent completion.
        
        Args:
            reason: Explanation for completion
            
        Returns:
            Dictionary with completion acknowledgment
        """
        self.logger.info(f"Agent completing: {reason}")
        self.state.termination_reason = TerminationReason.AGENT_FINISHED
        
        return {
            "success": True,
            "message": "Agent finished",
            "reason": reason
        }
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _get_progress_summary(self) -> str:
        """Generate human-readable progress summary."""
        phases = []
        if self.state.is_authenticated:
            phases.append("âœ“ Authenticated")
        if self.state.spider_completed:
            phases.append("âœ“ Spider")
        if self.state.ajax_spider_completed:
            phases.append("âœ“ AJAX Spider")
        if self.state.active_scan_completed:
            phases.append("âœ“ Active Scan")
        
        if not phases:
            return "No phases completed"
        return " â†’ ".join(phases)
    
    def _get_injection_alerts(self) -> list[dict]:
        """
        Get all alerts filtered to ground-truth aligned injection vulnerabilities only.
        
        Only includes alerts from SQL Injection (40018-40024) and NoSQL Injection (40033)
        rules, matching the thesis ground truth evaluation criteria.
        
        Returns:
            List of alert dictionaries for ground-truth injection vulnerabilities
        """
        try:
            all_alerts = self.zap.core.alerts()
            
            injection_alerts = []
            for alert in all_alerts:
                # Get plugin ID
                plugin_id = alert.get("pluginId")
                
                # Skip alerts without pluginId
                if not plugin_id:
                    continue
                
                # Convert to int safely
                try:
                    plugin_id_int = int(plugin_id)
                except (ValueError, TypeError):
                    continue
                
                # ONLY include alerts from ground truth injection rule IDs
                if plugin_id_int in GROUND_TRUTH_INJECTION_RULE_IDS:
                    injection_alerts.append(alert)
            
            return injection_alerts
            
        except Exception as e:
            self.logger.error(f"Error getting injection alerts: {e}")
            return []
    
    def _summarize_alerts_by_risk(self, alerts: list[dict]) -> dict:
        """Summarize alerts by risk level."""
        summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for alert in alerts:
            risk = alert.get("risk", "Informational")
            if risk in summary:
                summary[risk] += 1
        return summary
    
    def _summarize_alerts_by_type(self, alerts: list[dict]) -> dict:
        """Summarize alerts by vulnerability type."""
        summary = {}
        for alert in alerts:
            name = alert.get("name", "Unknown")
            summary[name] = summary.get(name, 0) + 1
        return summary
    
    # =========================================================================
    # Logging and Results
    # =========================================================================
    
    def _log_iteration(
        self,
        iteration: int,
        observation: dict,
        thought: str,
        action: str,
        args: dict,
        result: dict,
        tokens_this_call: int = 0
    ) -> None:
        """Log a complete iteration to the transcript."""
        entry = TranscriptEntry(
            iteration=iteration,
            timestamp=datetime.now().isoformat(),
            observation=observation,
            thought=thought,
            action=action,
            args=args,
            result=result,
            tokens_this_call=tokens_this_call
        )
        self.transcript.append(entry)
    
    def _compile_results(self) -> dict:
        """
        Compile final results after agent termination.
        
        Returns:
            Comprehensive results dictionary
        """
        self.logger.info("Compiling final results...")
        
        # Get final alerts
        injection_alerts = self._get_injection_alerts()
        
        # Format alerts for output
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
                "attack": alert.get("attack"),
                "evidence": alert.get("evidence"),
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "reference": alert.get("reference")
            })
        
        # Format transcript for output
        formatted_transcript = []
        for entry in self.transcript:
            formatted_transcript.append({
                "iteration": entry.iteration,
                "timestamp": entry.timestamp,
                "thought": entry.thought,
                "action": entry.action,
                "args": entry.args,
                "tokens_this_call": entry.tokens_this_call,
                "result_summary": {
                    "success": entry.result.get("success"),
                    "message": entry.result.get("message", entry.result.get("error", ""))
                }
            })
        
        # Get HTTP request count
        try:
            http_requests = int(self.zap.core.number_of_messages())
        except Exception:
            http_requests = 0
        
        results = {
            "alerts": formatted_alerts,
            "http_requests": http_requests,
            "urls_discovered": self.state.urls_discovered,
            "duration_minutes": round(self.state.elapsed_minutes, 2),
            "iterations": self.state.iteration,
            "tokens_used": self.state.tokens_used,
            "cost_usd": round(self.state.cost_usd, 4),
            "transcript": formatted_transcript,
            "termination_reason": (
                self.state.termination_reason.value 
                if self.state.termination_reason 
                else "unknown"
            ),
            "summary": {
                "total_injection_alerts": len(formatted_alerts),
                "alerts_by_risk": self._summarize_alerts_by_risk(injection_alerts),
                "alerts_by_type": self._summarize_alerts_by_type(injection_alerts),
                "urls_discovered": self.state.urls_discovered,
                "phases_completed": {
                    "authentication": self.state.is_authenticated,
                    "spider": self.state.spider_completed,
                    "ajax_spider": self.state.ajax_spider_completed,
                    "active_scan": self.state.active_scan_completed
                }
            }
        }
        
        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info("FINAL RESULTS SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"  Termination reason:  {results['termination_reason']}")
        self.logger.info(f"  Total iterations:    {results['iterations']}")
        self.logger.info(f"  Duration:            {results['duration_minutes']} minutes")
        self.logger.info(f"  Tokens used:         {results['tokens_used']}")
        self.logger.info(f"  API cost:            ${results['cost_usd']:.4f}")
        self.logger.info(f"  HTTP requests:       {results['http_requests']}")
        self.logger.info(f"  URLs discovered:     {results['urls_discovered']}")
        self.logger.info(f"  Injection alerts:    {len(formatted_alerts)}")
        
        # Phases completed
        phases = results['summary']['phases_completed']
        self.logger.info(f"  Phases completed:")
        self.logger.info(f"    Authentication:    {'YES' if phases['authentication'] else 'NO'}")
        self.logger.info(f"    Spider:            {'YES' if phases['spider'] else 'NO'}")
        self.logger.info(f"    AJAX Spider:       {'YES' if phases['ajax_spider'] else 'NO'}")
        self.logger.info(f"    Active Scan:       {'YES' if phases['active_scan'] else 'NO'}")
        
        # Alerts by risk
        by_risk = results['summary']['alerts_by_risk']
        self.logger.info(f"  Alerts by risk:      High={by_risk.get('High', 0)}, Medium={by_risk.get('Medium', 0)}, Low={by_risk.get('Low', 0)}")
        
        # Alerts by type
        by_type = results['summary']['alerts_by_type']
        if by_type:
            self.logger.info(f"  Alerts by type:")
            for vuln_type, count in by_type.items():
                self.logger.info(f"    - {vuln_type}: {count}")
        
        # Per-alert detail
        if formatted_alerts:
            self.logger.info("")
            self.logger.info("-" * 40)
            self.logger.info("INJECTION ALERTS FOUND:")
            self.logger.info("-" * 40)
            for i, alert in enumerate(formatted_alerts, 1):
                self.logger.info(
                    f"  [{i}] {alert.get('name', 'Unknown')}\n"
                    f"      Risk={alert.get('risk')} | Confidence={alert.get('confidence')}\n"
                    f"      URL={alert.get('url', 'N/A')}\n"
                    f"      Param={alert.get('param', 'N/A')} | CWE={alert.get('cweid', 'N/A')} | PluginId={alert.get('pluginId', 'N/A')}"
                )
        else:
            self.logger.info("  No injection alerts were found.")
        
        # Iteration timeline
        self.logger.info("")
        self.logger.info("-" * 40)
        self.logger.info("ITERATION TIMELINE:")
        self.logger.info("-" * 40)
        for entry in self.transcript:
            self.logger.info(
                f"  #{entry.iteration} [{entry.timestamp}] "
                f"{entry.action}({json.dumps(entry.args) if entry.args else ''}) "
                f"â†’ {'OK' if entry.result.get('success') else 'FAIL'} "
                f"| tokens={entry.tokens_this_call}"
            )
            self.logger.info(f"    Thought: {entry.thought[:120]}{'...' if len(entry.thought) > 120 else ''}")
        
        self.logger.info("=" * 60)
        
        return results


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Example usage of the ReAct DAST Agent."""
    import os
    
    # Configuration
    config = {
        "zap_api_key": os.environ.get("ZAP_API_KEY", ""),
        "zap_url": os.environ.get("ZAP_URL", "http://localhost:8080"),
        "openai_api_key": os.environ.get("OPENAI_API_KEY", ""),
        "target_url": os.environ.get("TARGET_URL", "http://localhost:3000"),
        "max_iterations": 50,
        "max_tokens": 100000,
        "cost_limit_usd": 5.00,
        "time_limit_minutes": 60,
        "temperature": 0
    }
    
    # Validate required environment variables
    if not config["zap_api_key"]:
        print("ERROR: ZAP_API_KEY environment variable not set")
        return
    if not config["openai_api_key"]:
        print("ERROR: OPENAI_API_KEY environment variable not set")
        return
    
    # Initialize and run agent
    agent = ReActDastAgent(config)
    
    # Set up file logging
    output_dir = os.environ.get("AGENT_OUTPUT_DIR", os.path.join(".", "results", "agent"))
    agent.setup_file_logging(output_dir)
    
    results = agent.run()
    
    # Save results into results/agent/ (never project root)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(
        output_dir,
        f"agent_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    agent.cleanup_file_logging()
    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()