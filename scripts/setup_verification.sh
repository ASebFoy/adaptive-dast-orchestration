#!/bin/bash

# Complete Setup Verification Script
# Checks ALL potential failure points before overnight experiments

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  COMPLETE SETUP VERIFICATION"
echo "  Thesis: Adaptive DAST Orchestration"
echo "════════════════════════════════════════════════════════════════"
echo ""

cd /root/thesis-artifact

FAILED=0

check() {
    if [ $? -eq 0 ]; then
        echo "✅ $1"
    else
        echo "❌ $1"
        FAILED=1
    fi
}

# ============================================================================
# SECTION 1: Directory Structure
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. DIRECTORY STRUCTURE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check configs directory
if [ -d "configs" ]; then
    echo "✅ configs/ directory exists"
else
    echo "❌ configs/ directory missing - creating..."
    mkdir -p configs
    FAILED=1
fi

# Check for ZAP config file
if [ -f "configs/zap-injection-baseline.yaml" ]; then
    echo "✅ configs/zap-injection-baseline.yaml exists"
elif [ -f "zap-injection-baseline.yaml" ]; then
    echo "⚠️  Moving zap-injection-baseline.yaml to configs/"
    cp zap-injection-baseline.yaml configs/
    echo "✅ configs/zap-injection-baseline.yaml created"
else
    echo "❌ zap-injection-baseline.yaml not found anywhere!"
    FAILED=1
fi

# Check reports directory
if [ ! -d "reports" ]; then
    echo "⚠️  reports/ directory missing - creating..."
    mkdir -p reports
    chmod 777 reports
fi

if [ -w "reports" ]; then
    echo "✅ reports/ directory writable"
else
    echo "❌ reports/ directory not writable"
    chmod 777 reports
    FAILED=1
fi

# Check results directory structure
mkdir -p results/debug/baseline results/debug/agent
echo "✅ results/ directory structure created"

# ============================================================================
# SECTION 2: Environment Variables
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. ENVIRONMENT VARIABLES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if .env exists
if [ -f ".env" ]; then
    echo "✅ .env file exists"
    
    # Load it
    set -a
    source .env 2>/dev/null
    set +a
else
    echo "⚠️  .env file missing - attempting to create template..."
    cat > .env << 'EOF'
# ZAP Configuration
ZAP_URL=http://localhost:8080
ZAP_API_KEY=thesis-zap-api-key
TARGET_URL=http://juice-shop:3000
HOST_TARGET_URL=http://localhost:3000

# OpenAI Configuration  
OPENAI_API_KEY=sk-proj-REPLACE-WITH-YOUR-KEY

# Optional
OPENAI_MODEL=gpt-4o-2024-08-06
EOF
    echo "❌ .env template created - EDIT IT with your OpenAI key!"
    echo "   nano .env"
    FAILED=1
fi

# Check required variables
required_vars=("ZAP_URL" "ZAP_API_KEY" "TARGET_URL" "OPENAI_API_KEY")
for var in "${required_vars[@]}"; do
    if [ -n "${!var}" ]; then
        if [ "$var" = "OPENAI_API_KEY" ]; then
            echo "✅ $var is set (${!var:0:10}...)"
        else
            echo "✅ $var=${!var}"
        fi
    else
        echo "❌ $var NOT SET - add to .env file!"
        FAILED=1
    fi
done

# Warn if using default OpenAI key placeholder
if [ "$OPENAI_API_KEY" = "sk-proj-REPLACE-WITH-YOUR-KEY" ]; then
    echo "❌ OPENAI_API_KEY is still the placeholder - replace it!"
    FAILED=1
fi

# ============================================================================
# SECTION 3: Docker Environment
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. DOCKER ENVIRONMENT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if Docker is running
if docker info > /dev/null 2>&1; then
    echo "✅ Docker daemon is running"
else
    echo "❌ Docker daemon not running!"
    FAILED=1
fi

# Check if containers exist
if docker ps -a | grep -q "thesis-zap"; then
    echo "✅ ZAP container exists"
    
    # Check if running
    if docker ps | grep -q "thesis-zap"; then
        echo "✅ ZAP container is running"
        
        # Check ZAP API key in container
        docker_key=$(docker exec thesis-zap env 2>/dev/null | grep ZAP_API_KEY | cut -d= -f2 || echo "UNKNOWN")
        
        if [ "$docker_key" = "$ZAP_API_KEY" ]; then
            echo "✅ Docker ZAP_API_KEY matches .env"
        else
            echo "❌ ZAP_API_KEY MISMATCH!"
            echo "   Docker container: $docker_key"
            echo "   .env file:        $ZAP_API_KEY"
            echo ""
            echo "   FIX: Run these commands:"
            echo "   set -a; source .env; set +a"
            echo "   docker-compose down"
            echo "   docker-compose up -d"
            FAILED=1
        fi
    else
        echo "⚠️  ZAP container not running - starting..."
        docker-compose up -d
        sleep 30
    fi
else
    echo "⚠️  ZAP container doesn't exist - starting..."
    # Make sure env vars are loaded for docker-compose
    set -a
    source .env 2>/dev/null
    set +a
    docker-compose up -d
    sleep 30
fi

if docker ps -a | grep -q "thesis-juice-shop"; then
    echo "✅ Juice Shop container exists"
    
    if docker ps | grep -q "thesis-juice-shop"; then
        echo "✅ Juice Shop container is running"
    else
        echo "⚠️  Juice Shop container not running - starting..."
        docker-compose up -d
        sleep 30
    fi
else
    echo "⚠️  Juice Shop container doesn't exist - starting..."
    docker-compose up -d
    sleep 30
fi

# ============================================================================
# SECTION 4: Service Connectivity
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. SERVICE CONNECTIVITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 5

# Check ZAP API
if curl -s --max-time 10 "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY" > /dev/null 2>&1; then
    zap_version=$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
    echo "✅ ZAP API responding (version: $zap_version)"
else
    echo "❌ Cannot connect to ZAP API at http://localhost:8080"
    echo "   Check: docker logs thesis-zap"
    FAILED=1
fi

# Check Juice Shop
if curl -s --max-time 10 http://localhost:3000 > /dev/null 2>&1; then
    echo "✅ Juice Shop responding at http://localhost:3000"
else
    echo "❌ Cannot connect to Juice Shop at http://localhost:3000"
    echo "   Check: docker logs thesis-juice-shop"
    FAILED=1
fi

# Check OpenAI API
if curl -s --max-time 10 \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    https://api.openai.com/v1/models > /dev/null 2>&1; then
    echo "✅ OpenAI API accessible"
else
    echo "❌ Cannot connect to OpenAI API"
    echo "   Check your OPENAI_API_KEY"
    FAILED=1
fi

# ============================================================================
# SECTION 5: Required Files
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. REQUIRED FILES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

required_files=(
    "overnight_baseline.py"
    "overnight_agent.py"
    "baseline_runner.py"
    "react_dast_agent.py"
    "reset_environment.py"
    "evaluate.py"
    "analyze_results.py"
    "tools.py"
    "ground_truth_injection.json"
    "setup_user.py"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file MISSING"
        FAILED=1
    fi
done

# ============================================================================
# SECTION 6: Python Dependencies
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. PYTHON DEPENDENCIES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

python_packages=("requests" "anthropic" "openai" "python-dotenv")

for package in "${python_packages[@]}"; do
    if python3 -c "import ${package//-/_}" 2>/dev/null; then
        echo "✅ $package installed"
    else
        echo "❌ $package NOT installed"
        echo "   Install: pip3 install $package --break-system-packages"
        FAILED=1
    fi
done

# ============================================================================
# SECTION 7: System Resources
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. SYSTEM RESOURCES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check disk space
available_kb=$(df / | awk 'NR==2 {print $4}')
available_gb=$((available_kb / 1024 / 1024))

if [ $available_gb -ge 5 ]; then
    echo "✅ Disk space: ${available_gb}GB free (need 5GB minimum)"
else
    echo "❌ Disk space: ${available_gb}GB free - need at least 5GB!"
    echo "   Free up space:"
    echo "   docker system prune -a -f"
    FAILED=1
fi

# Check current results size
if [ -d "results" ]; then
    results_size=$(du -sh results 2>/dev/null | cut -f1)
    echo "ℹ️  Current results size: $results_size"
fi

# Check memory
total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
total_mem_gb=$((total_mem_kb / 1024 / 1024))

if [ $total_mem_gb -ge 4 ]; then
    echo "✅ Memory: ${total_mem_gb}GB (recommended 4GB+)"
else
    echo "⚠️  Memory: ${total_mem_gb}GB (recommended 4GB+ for stability)"
fi

# ============================================================================
# SECTION 8: Reset Script Test
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. RESET SCRIPT TEST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Testing reset_environment.py speed..."
start_time=$(date +%s)
python3 reset_environment.py > /tmp/reset_test.log 2>&1

if [ $? -eq 0 ]; then
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    if [ $duration -lt 90 ]; then
        echo "✅ Reset completed in ${duration}s (< 90s timeout)"
    else
        echo "⚠️  Reset took ${duration}s - might timeout during overnight runs"
        echo "   Consider increasing timeout in overnight scripts"
    fi
else
    echo "❌ Reset script failed!"
    echo "   Check log: /tmp/reset_test.log"
    FAILED=1
fi

# ============================================================================
# SECTION 9: tmux Availability
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "9. SESSION PERSISTENCE (tmux)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v tmux &> /dev/null; then
    tmux_version=$(tmux -V)
    echo "✅ tmux installed ($tmux_version)"
else
    echo "❌ tmux NOT installed - you WILL lose experiments on SSH timeout!"
    echo "   Install: apt-get update && apt-get install -y tmux"
    FAILED=1
fi

# ============================================================================
# FINAL SUMMARY
# ============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  SETUP VERIFICATION SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "✅✅✅ ALL CHECKS PASSED ✅✅✅"
    echo ""
    echo "System is ready for overnight experiments!"
    echo ""
    echo "Next steps:"
    echo "  1. Run comprehensive smoke test:"
    echo "     ./comprehensive_smoke_test.sh"
    echo ""
    echo "  2. If smoke test passes, launch overnight runs:"
    echo "     tmux new -s baseline"
    echo "     python3 overnight_baseline.py --runs 8"
    echo "     # Detach: Ctrl+b, d"
    echo ""
    echo "     tmux new -s agent"
    echo "     python3 overnight_agent.py --runs 8"
    echo "     # Detach: Ctrl+b, d"
    echo ""
    exit 0
else
    echo "❌❌❌ SOME CHECKS FAILED ❌❌❌"
    echo ""
    echo "Fix the issues above before running experiments!"
    echo ""
    echo "Common fixes:"
    echo "  • Missing .env: nano .env (add your OPENAI_API_KEY)"
    echo "  • API key mismatch: set -a; source .env; set +a"
    echo "                      docker-compose down && docker-compose up -d"
    echo "  • Missing packages: pip3 install <package> --break-system-packages"
    echo "  • Missing tmux: apt-get install -y tmux"
    echo ""
    exit 1
fi