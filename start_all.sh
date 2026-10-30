#!/bin/bash
# ======================================================================
#   Unified Security Operations Center (SOC) Launcher for macOS / Linux
#   Single Host Link: http://localhost:8000
# ======================================================================

set -e

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}======================================================================${NC}"
echo -e "${GREEN}  STARTING UNIFIED SECURITY OPERATIONS CENTER (SOC)${NC}"
echo -e "${YELLOW}  Single Host Link: http://localhost:8000${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo ""

# Find python3
PYTHON_BIN="$(which python3 || echo "python")"

# Check port 5000 for macOS AirPlay conflict
if lsof -iTCP:5000 -sTCP:LISTEN >/dev/null 2>&1; then
    PORT_OWNER=$(lsof -iTCP:5000 -sTCP:LISTEN | tail -n 1 | awk '{print $1}')
    if [[ "$PORT_OWNER" == "ControlCe"* ]]; then
        echo -e "${YELLOW}[!] WARNING: macOS AirPlay Receiver (ControlCenter) is listening on Port 5000.${NC}"
        echo -e "${YELLOW}    Please toggle OFF 'AirPlay Receiver' in:${NC}"
        echo -e "${YELLOW}    System Settings -> General -> AirDrop & Handoff -> AirPlay Receiver${NC}"
        echo ""
    fi
fi

# Track child PIDs for clean exit
PIDS=()
cleanup() {
    echo ""
    echo -e "${YELLOW}[!] Shutting down all SOC services...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo -e "${GREEN}[OK] All services stopped.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 0. Ensure Local Self-Hosted Ollama is Running (Zero API keys required)
if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo -e "${CYAN}[0/4] Starting local self-hosted Ollama engine (llama3.2)...${NC}"
    ollama serve > "$ROOT_DIR/ollama.log" 2>&1 &
    PIDS+=($!)
    sleep 1
else
    echo -e "${GREEN}[OK] Local Ollama LLM server active (http://localhost:11434)${NC}"
fi

# 1. Start Insider Threat Detection System (Port 5001)
echo -e "${CYAN}[1/4] Launching Insider Threat Detection System (Port 5001)...${NC}"
cd "$ROOT_DIR/src/insider-threat"
"$PYTHON_BIN" run.py > "$ROOT_DIR/insider_threat.log" 2>&1 &
PIDS+=($!)

# 2. Start NIDS Flask ML API (Port 5005)
echo -e "${CYAN}[2/4] Launching NIDS ML API Engine (Port 5005)...${NC}"
cd "$ROOT_DIR/src/flask-api"
PORT=5005 "$PYTHON_BIN" run.py > "$ROOT_DIR/nids_api.log" 2>&1 &
PIDS+=($!)

# 3. Start NIDS React Frontend (Port 3000)
echo -e "${CYAN}[3/4] Launching NIDS React Dashboard (Port 3000)...${NC}"
cd "$ROOT_DIR/src/frontend/my-app"
npm start > "$ROOT_DIR/frontend.log" 2>&1 &
PIDS+=($!)

# 4. Start Unified Portal Gateway (Port 8000)
echo -e "${CYAN}[4/4] Launching Unified SOC Portal Gateway (Port 8000)...${NC}"
cd "$ROOT_DIR"
"$PYTHON_BIN" unified_soc_portal.py &
PIDS+=($!)


sleep 3

# Open browser if on macOS
if command -v open >/dev/null 2>&1; then
    echo -e "${GREEN}[OK] Opening Unified Host Link in default browser: http://localhost:8000${NC}"
    open "http://localhost:8000" || true
fi

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}  All services active! Access the unified console at: http://localhost:8000${NC}"
echo -e "${YELLOW}  Press Ctrl+C to terminate all background services.${NC}"
echo -e "${GREEN}======================================================================${NC}"

# Keep running
wait
