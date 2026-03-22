#!/usr/bin/env python3
# Environment Variables:
# - TARGET_URL: URL for ZAP/agent inside Docker network (default: http://juice-shop:3000)
# - HOST_TARGET_URL: URL for host readiness checks and setup_user.py (default: http://localhost:3000)
# - ZAP_URL: ZAP API URL from host (default: http://localhost:8080)
# - ZAP_API_KEY: ZAP API key (required)

import os
import sys
import time
import subprocess
import argparse
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} - RESET - {msg}", flush=True)


def get_requests_session() -> requests.Session:
    """Create a requests session with retry logic and connection pooling."""
    session = requests.Session()
    
    # Configure retries
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
        pool_block=False
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    log(f"RUN: {' '.join(cmd)}")
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        log("ERROR: command failed")
        if proc.stdout.strip():
            log(f"STDOUT:\n{proc.stdout.strip()}")
        if proc.stderr.strip():
            log(f"STDERR:\n{proc.stderr.strip()}")
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return proc


def wait_for_http_ok(
    url: str, 
    timeout_s: int, 
    interval_s: float = 2.0,
    session: Optional[requests.Session] = None
) -> None:
    """Wait for HTTP 200 with improved error handling."""
    log(f"Waiting for HTTP 200: {url} (timeout {timeout_s}s)")
    start = time.time()
    last_err: Optional[str] = None
    
    if session is None:
        session = get_requests_session()

    attempt = 0
    while time.time() - start < timeout_s:
        attempt += 1
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                log(f"OK: {url} (after {attempt} attempts)")
                return
            last_err = f"status={r.status_code}"
            log(f"Attempt {attempt}: Got status {r.status_code}, retrying...")
        except requests.exceptions.Timeout:
            last_err = "Timeout"
            log(f"Attempt {attempt}: Timeout, retrying...")
        except requests.exceptions.ConnectionError as e:
            last_err = f"ConnectionError: {str(e)[:100]}"
            log(f"Attempt {attempt}: Connection error, retrying...")
        except Exception as e:
            last_err = repr(e)[:200]
            log(f"Attempt {attempt}: {type(e).__name__}, retrying...")

        time.sleep(interval_s)

    raise TimeoutError(
        f"Timed out waiting for {url} after {attempt} attempts ({timeout_s}s). "
        f"Last error: {last_err}"
    )


def wait_for_zap_api(zap_url: str, zap_api_key: str, timeout_s: int) -> None:
    url = f"{zap_url.rstrip('/')}/JSON/core/view/version/?apikey={zap_api_key}"
    session = get_requests_session()
    wait_for_http_ok(url, timeout_s=timeout_s, session=session)


def zap_api_get(
    zap_url: str, 
    path: str, 
    zap_api_key: str, 
    params: Optional[dict] = None, 
    timeout: int = 15,
    session: Optional[requests.Session] = None
):
    """Make ZAP API GET request with retry logic."""
    url = f"{zap_url.rstrip('/')}{path}"
    params = params or {}
    params["apikey"] = zap_api_key
    
    if session is None:
        session = get_requests_session()
    
    try:
        r = session.get(url, params=params, timeout=timeout)
        if r.status_code != 200:
            raise RuntimeError(f"ZAP API GET failed {url}: HTTP {r.status_code} - {r.text[:200]}")
        return r.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"ZAP API request failed: {e}")


def clear_zap_session(
    zap_url: str, 
    zap_api_key: str,
    session: Optional[requests.Session] = None
) -> None:
    log("Clearing ZAP session (newSession overwrite=true)")
    if session is None:
        session = get_requests_session()
    
    _ = zap_api_get(
        zap_url,
        "/JSON/core/action/newSession/",
        zap_api_key,
        params={"overwrite": "true"},
        timeout=20,
        session=session
    )
    log("ZAP session cleared")


def get_zap_message_count(
    zap_url: str, 
    zap_api_key: str,
    session: Optional[requests.Session] = None
) -> int:
    if session is None:
        session = get_requests_session()
    
    j = zap_api_get(
        zap_url, 
        "/JSON/core/view/numberOfMessages/", 
        zap_api_key, 
        timeout=15,
        session=session
    )
    val = j.get("numberOfMessages", "0")
    try:
        return int(val)
    except Exception:
        return 0


def verify_zap_can_reach_juice_shop_inside_container() -> None:
    log("Verifying ZAP container can reach Juice Shop at http://juice-shop:3000")
    
    # Wait for container to stabilize after restart
    log("Waiting 10s for ZAP container to stabilize...")
    time.sleep(10)
    
    # Try the docker exec command with retry logic
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        log(f"Docker exec attempt {attempt}/{max_retries}")
        proc = run_cmd(
            ["docker-compose", "exec", "-T", "zap", "curl", "-sS", "http://juice-shop:3000/rest/admin/application-version"],
            check=False,
        )
        
        if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
            log("OK: ZAP container -> Juice Shop connectivity verified")
            return
        
        if attempt < max_retries:
            log(f"Attempt {attempt} failed, retrying in 5s...")
            time.sleep(5)
    
    # All retries failed
    raise RuntimeError(
        "ZAP container cannot reach Juice Shop via http://juice-shop:3000.\n"
        "Check docker-compose network + your YAML URLs.\n"
        f"curl output: {proc.stdout.strip()[:200]!r} {proc.stderr.strip()[:200]!r}"
    )


def create_test_user(python_exe: str, host_target_url: str) -> None:
    log("Creating/verifying test user via setup_user.py")
    run_cmd([python_exe, "setup_user.py", "--target-url", host_target_url], check=True)
    log("Test user created/verified")


def ensure_containers_running() -> None:
    """Ensure Docker containers are running and healthy."""
    log("Checking Docker containers...")
    
    # Check if docker-compose is available
    proc = run_cmd(["docker-compose", "version"], check=False)
    if proc.returncode != 0:
        raise RuntimeError("docker-compose not found. Please install Docker Compose.")
    
    # Get container status
    proc = run_cmd(["docker-compose", "ps", "-q"], check=False)
    if not proc.stdout.strip():
        log("No containers running. Starting containers...")
        run_cmd(["docker-compose", "up", "-d"], check=True)
        log("Waiting 60s for containers to initialize...")
        time.sleep(60)
    else:
        log("Containers already running")


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset + sanity check for Juice Shop/ZAP experiments.")
    parser.add_argument("--restart-zap", action="store_true", help="Restart the ZAP container (slower; only if wedged).")
    parser.add_argument("--wait-juice-timeout", type=int, default=180, help="Seconds to wait for Juice Shop readiness (increased default).")
    parser.add_argument("--wait-zap-timeout", type=int, default=240, help="Seconds to wait for ZAP readiness (increased default).")
    parser.add_argument("--no-verify-zap-container-connectivity", action="store_true",
                        help="Skip ZAP container -> Juice Shop connectivity check.")
    parser.add_argument("--full-restart", action="store_true",
                        help="Do a full docker-compose down/up cycle (nuclear option).")
    args = parser.parse_args()

    # TARGET_URL: used by agent/ZAP inside Docker network
    target_url = os.getenv("TARGET_URL", "http://juice-shop:3000").rstrip("/")
    
    # HOST_TARGET_URL: used by this reset script running on host
    host_target_url = os.getenv("HOST_TARGET_URL", "http://localhost:3000").rstrip("/")

    zap_url = os.getenv("ZAP_URL", "http://localhost:8080").rstrip("/")
    zap_api_key = os.getenv("ZAP_API_KEY", "").strip()

    if not zap_api_key:
        log("ERROR: ZAP_API_KEY is empty. Load your .env into this shell first.")
        log("Tip: set -a; source .env; set +a")
        return 2

    python_exe = sys.executable

    # Create a session for reuse
    session = get_requests_session()

    try:
        log("=" * 60)
        log("RESET STARTING")
        log("=" * 60)
        log(f"TARGET_URL (Docker network): {target_url}")
        log(f"HOST_TARGET_URL (host access): {host_target_url}")
        log(f"ZAP_URL: {zap_url}")

        # Handle full restart if requested
        if args.full_restart:
            log("Full restart requested - bringing down all containers...")
            run_cmd(["docker-compose", "down"], check=False)
            log("Bringing containers back up...")
            run_cmd(["docker-compose", "up", "-d"], check=True)
            log("Waiting 90s for full initialization...")
            time.sleep(90)
        else:
            # Ensure containers are running
            ensure_containers_running()
            
            # Ensure containers are up (non-destructive)
            run_cmd(["docker-compose", "up", "-d"], check=True)

        # Restart Juice Shop for clean app state
        log("Restarting Juice Shop...")
        run_cmd(["docker-compose", "restart", "juice-shop"], check=True)
        log("Waiting 20s for Juice Shop to start...")
        time.sleep(20)

        # Wait for Juice Shop from host
        wait_for_http_ok(
            f"{host_target_url}/rest/admin/application-version", 
            timeout_s=args.wait_juice_timeout,
            session=session
        )

        # Optional: restart ZAP
        if args.restart_zap:
            log("Restarting ZAP container...")
            run_cmd(["docker-compose", "restart", "zap"], check=True)
            log("Waiting 30s for ZAP to start...")
            time.sleep(30)

        # Wait for ZAP API from host
        log("Waiting for ZAP API to be ready...")
        wait_for_zap_api(zap_url, zap_api_key, timeout_s=args.wait_zap_timeout)
        log("OK: ZAP API is ready")

        # Verify ZAP container can reach Juice Shop via docker DNS
        if not args.no_verify_zap_container_connectivity:
            verify_zap_can_reach_juice_shop_inside_container()

        # Clear ZAP session and confirm message count drops
        before = get_zap_message_count(zap_url, zap_api_key, session=session)
        log(f"ZAP message count BEFORE clear: {before}")
        clear_zap_session(zap_url, zap_api_key, session=session)
        time.sleep(2)
        after = get_zap_message_count(zap_url, zap_api_key, session=session)
        log(f"ZAP message count AFTER clear: {after}")
        if after > 20:
            raise RuntimeError(f"ZAP message count still high after newSession ({after}).")

        # Create test user (using host URL)
        create_test_user(python_exe, host_target_url)

        log("=" * 60)
        log("RESET COMPLETE: Environment is ready for a clean run")
        log("=" * 60)
        return 0

    except Exception as e:
        log("=" * 60)
        log(f"RESET FAILED: {e}")
        log("=" * 60)
        log("\nTroubleshooting tips:")
        log("1. Check containers: docker-compose ps")
        log("2. Check logs: docker-compose logs juice-shop --tail=50")
        log("3. Try full restart: python reset_environment.py --full-restart")
        log("4. Verify .env is loaded: echo $ZAP_API_KEY")
        return 1
    finally:
        # Close the session
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())