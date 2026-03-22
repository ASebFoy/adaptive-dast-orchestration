#!/bin/bash

echo "════════════════════════════════════════════════════════════════"
echo "  AGENT OVERNIGHT EXPERIMENTS - STARTUP"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Go to project root
cd /root/thesis-artifact || exit 1

# Activate virtual environment
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate || exit 1
    echo "✓ Virtual environment activated"
else
    echo "⚠️  No virtual environment found, using system Python"
fi

# Load environment variables
echo "Loading environment variables..."
set -a
source .env
set +a

# Verify critical variables are set
echo ""
echo "Checking environment variables..."
if [ -z "$ZAP_API_KEY" ]; then
    echo "❌ ZAP_API_KEY not set"
    exit 1
fi
echo "✓ ZAP_API_KEY: $ZAP_API_KEY"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ OPENAI_API_KEY not set"
    exit 1
fi
echo "✓ OPENAI_API_KEY: ${OPENAI_API_KEY:0:15}..."

if [ -z "$TARGET_URL" ]; then
    echo "❌ TARGET_URL not set"
    exit 1
fi
echo "✓ TARGET_URL: $TARGET_URL"

if [ -z "$ZAP_URL" ]; then
    echo "❌ ZAP_URL not set"
    exit 1
fi
echo "✓ ZAP_URL: $ZAP_URL"

# Check Docker containers
echo ""
echo "Checking Docker containers..."
if docker ps | grep -q "thesis-zap"; then
    echo "✓ ZAP container running"
else
    echo "❌ ZAP container not running"
    echo "Starting Docker containers..."
    docker-compose up -d
    sleep 30
fi

if docker ps | grep -q "thesis-juice-shop"; then
    echo "✓ Juice Shop container running"
else
    echo "❌ Juice Shop container not running"
    echo "Starting Docker containers..."
    docker-compose up -d
    sleep 30
fi

# Check ZAP health
echo ""
echo "Checking ZAP API health..."
ZAP_HEALTH=$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY" 2>&1)

if [[ $ZAP_HEALTH == *"version"* ]]; then
    echo "✓ ZAP is responding"
else
    echo "⚠️  ZAP is not responding. Restarting..."
    docker-compose restart zap
    echo "Waiting 60 seconds for ZAP to initialize..."
    sleep 60
    
    ZAP_HEALTH=$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY" 2>&1)
    if [[ $ZAP_HEALTH != *"version"* ]]; then
        echo "❌ ZAP still not responding after restart"
        echo "Try: docker-compose logs zap --tail=50"
        exit 1
    fi
    echo "✓ ZAP is now responding"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ALL CHECKS PASSED - STARTING AGENT RUNS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Starting 8 agent runs (estimated duration: ~12 hours)"
echo ""

# Launch agent experiments
python3 overnight_agent.py --runs 8

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  AGENT EXPERIMENTS COMPLETE"
echo "════════════════════════════════════════════════════════════════"