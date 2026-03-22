#!/bin/bash

echo "=== Reset Script Starting ==="

# Go to project root
cd /root/thesis-artifact || exit 1

# Activate virtual environment
source venv/bin/activate || exit 1

# Load environment variables
set -a
source .env
set +a

# Check if ZAP is actually responding before running reset
echo "Checking ZAP health..."
ZAP_HEALTH=$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY" 2>&1)

if [[ $ZAP_HEALTH == *"version"* ]]; then
    echo "✓ ZAP is responding"
else
    echo "✗ ZAP is not responding. Restarting ZAP..."
    docker-compose restart zap
    echo "Waiting 120 seconds for ZAP to fully initialize..."
    sleep 120
    
    # Check again
    ZAP_HEALTH=$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY" 2>&1)
    if [[ $ZAP_HEALTH != *"version"* ]]; then
        echo "ERROR: ZAP still not responding after restart"
        echo "Try: docker-compose logs zap --tail=50"
        exit 1
    fi
    echo "✓ ZAP is now responding"
fi

# Run reset logic
python reset_environment.py

echo "=== Reset Script Finished ==="