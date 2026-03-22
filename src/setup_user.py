#!/usr/bin/env python3
"""
Setup Test User for OWASP Juice Shop

Creates the test user account required for authenticated scanning.
This script should be run before each experimental run to ensure
the test user exists with known credentials.

Usage:
    python setup_user.py [--target-url http://localhost:3000]
    
The script will:
    1. Check if the test user already exists (by attempting login)
    2. If not, register a new user with the configured credentials
    3. Verify the user can authenticate successfully

Author: Thesis Experiment Infrastructure
"""

import argparse
import logging
import sys
import time

import requests

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_TARGET_URL = "http://localhost:3000"
TEST_USER_EMAIL = "test@juice-sh.op"
TEST_USER_PASSWORD = "test123"
TEST_USER_SECURITY_QUESTION = 1  # "Your eldest siblings middle name?"
TEST_USER_SECURITY_ANSWER = "test"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Main Functions
# =============================================================================

def check_juice_shop_available(target_url: str, max_retries: int = 30) -> bool:
    """
    Wait for Juice Shop to be available.
    
    Args:
        target_url: Base URL of Juice Shop
        max_retries: Maximum number of retry attempts
        
    Returns:
        True if Juice Shop is available, False otherwise
    """
    logger.info(f"Checking if Juice Shop is available at {target_url}...")
    
    for attempt in range(max_retries):
        try:
            response = requests.get(f"{target_url}/rest/admin/application-version", timeout=5)
            if response.status_code == 200:
                version = response.json().get("version", "unknown")
                logger.info(f"Juice Shop v{version} is available")
                return True
        except requests.exceptions.RequestException:
            pass
        
        if attempt < max_retries - 1:
            logger.debug(f"Attempt {attempt + 1}/{max_retries} failed, retrying...")
            time.sleep(2)
    
    logger.error(f"Juice Shop not available after {max_retries} attempts")
    return False


def user_exists(target_url: str, email: str, password: str) -> bool:
    """
    Check if the user already exists by attempting to log in.
    
    Args:
        target_url: Base URL of Juice Shop
        email: User email
        password: User password
        
    Returns:
        True if login succeeds, False otherwise
    """
    logger.info(f"Checking if user {email} already exists...")
    
    try:
        response = requests.post(
            f"{target_url}/rest/user/login",
            json={"email": email, "password": password},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if "authentication" in data and "token" in data["authentication"]:
                logger.info(f"User {email} already exists and can authenticate")
                return True
        
        logger.info(f"User {email} does not exist or wrong credentials")
        return False
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error checking user existence: {e}")
        return False


def register_user(
    target_url: str,
    email: str,
    password: str,
    security_question: int,
    security_answer: str
) -> bool:
    """
    Register a new user in Juice Shop.
    
    Args:
        target_url: Base URL of Juice Shop
        email: User email
        password: User password
        security_question: Security question ID (1-14)
        security_answer: Answer to security question
        
    Returns:
        True if registration succeeds, False otherwise
    """
    logger.info(f"Registering new user: {email}...")
    
    try:
        # Juice Shop registration endpoint
        response = requests.post(
            f"{target_url}/api/Users/",
            json={
                "email": email,
                "password": password,
                "passwordRepeat": password,
                "securityQuestion": {
                    "id": security_question,
                    "question": "Your eldest siblings middle name?"
                },
                "securityAnswer": security_answer
            },
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully registered user: {email}")
            return True
        elif response.status_code == 400:
            # May indicate user already exists
            error_msg = response.json().get("message", "Unknown error")
            if "already" in error_msg.lower():
                logger.info(f"User {email} already registered")
                return True
            logger.error(f"Registration failed: {error_msg}")
            return False
        else:
            logger.error(f"Registration failed with status {response.status_code}")
            logger.debug(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Registration request failed: {e}")
        return False


def verify_authentication(target_url: str, email: str, password: str) -> dict:
    """
    Verify that the user can authenticate and return the token.
    
    Args:
        target_url: Base URL of Juice Shop
        email: User email
        password: User password
        
    Returns:
        Dictionary with authentication result
    """
    logger.info(f"Verifying authentication for {email}...")
    
    try:
        response = requests.post(
            f"{target_url}/rest/user/login",
            json={"email": email, "password": password},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if "authentication" in data and "token" in data["authentication"]:
                token = data["authentication"]["token"]
                logger.info(f"Authentication verified successfully")
                return {
                    "success": True,
                    "token": token,
                    "message": "Authentication successful"
                }
        
        logger.error(f"Authentication failed with status {response.status_code}")
        return {
            "success": False,
            "token": None,
            "message": f"Authentication failed: {response.text[:200]}"
        }
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication request failed: {e}")
        return {
            "success": False,
            "token": None,
            "message": f"Request failed: {e}"
        }


def setup_test_user(target_url: str) -> dict:
    """
    Main function to set up the test user.
    
    Args:
        target_url: Base URL of Juice Shop
        
    Returns:
        Dictionary with setup result
    """
    logger.info("=" * 60)
    logger.info("Setting up test user for thesis experiment")
    logger.info("=" * 60)
    
    # Step 1: Check Juice Shop availability
    if not check_juice_shop_available(target_url):
        return {
            "success": False,
            "message": "Juice Shop is not available"
        }
    
    # Step 2: Check if user already exists
    if user_exists(target_url, TEST_USER_EMAIL, TEST_USER_PASSWORD):
        # User exists, verify authentication
        auth_result = verify_authentication(target_url, TEST_USER_EMAIL, TEST_USER_PASSWORD)
        if auth_result["success"]:
            return {
                "success": True,
                "message": "Test user already exists and can authenticate",
                "email": TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD
            }
    
    # Step 3: Register new user
    if not register_user(
        target_url,
        TEST_USER_EMAIL,
        TEST_USER_PASSWORD,
        TEST_USER_SECURITY_QUESTION,
        TEST_USER_SECURITY_ANSWER
    ):
        return {
            "success": False,
            "message": "Failed to register test user"
        }
    
    # Step 4: Verify authentication
    auth_result = verify_authentication(target_url, TEST_USER_EMAIL, TEST_USER_PASSWORD)
    if not auth_result["success"]:
        return {
            "success": False,
            "message": "User registered but authentication failed"
        }
    
    logger.info("=" * 60)
    logger.info("Test user setup complete!")
    logger.info(f"  Email: {TEST_USER_EMAIL}")
    logger.info(f"  Password: {TEST_USER_PASSWORD}")
    logger.info("=" * 60)
    
    return {
        "success": True,
        "message": "Test user created and verified",
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    }


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Set up test user for OWASP Juice Shop"
    )
    parser.add_argument(
        "--target-url",
        default=DEFAULT_TARGET_URL,
        help=f"Juice Shop URL (default: {DEFAULT_TARGET_URL})"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    result = setup_test_user(args.target_url)
    
    if result["success"]:
        print(f"\nâœ“ {result['message']}")
        sys.exit(0)
    else:
        print(f"\nâœ— {result['message']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
