#!/bin/bash

# NetSentinel Launcher
# This script sets up dependencies, configures permissions, and launches the application.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️ Starting NetSentinel Setup & Launch Sequence...${NC}"

# 1. System Dependency Check: Nmap
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}nmap not found. Installing...${NC}"
    sudo apt-get update -y && sudo apt-get install -y nmap
else
    echo -e "${GREEN}✓ nmap is installed.${NC}"
fi

# 2. Configure Permissions (setcap)
echo -e "${BLUE}Configuring nmap network capabilities...${NC}"
NMAP_PATH=$(which nmap)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_PATH"
echo -e "${GREEN}✓ nmap capabilities configured (passwordless scanning enabled).${NC}"

# 3. Python Dependency Check
echo -e "${BLUE}Checking Python dependencies...${NC}"
pip install -r requirements.txt --quiet
echo -e "${GREEN}✓ Python dependencies verified.${NC}"

# 4. Launch Backend & UI
echo -e "${BLUE}Launching NetSentinel API & Web Dashboard...${NC}"
# Kill existing instance if any
PID=$(pgrep -f "network_audit_server.py" || true)
if [ ! -z "$PID" ]; then
    echo "Stopping existing server (PID: $PID)..."
    kill $PID || true
    sleep 2
fi

# Run in background
nohup python3 -u network_audit_server.py > server.log 2>&1 &
SERVER_PID=$!

echo -e "${GREEN}🚀 NetSentinel is now running in the background (PID: $SERVER_PID)${NC}"
echo -e "${GREEN}   Web Dashboard: http://localhost:8000/ui${NC}"
echo -e "${GREEN}   API Health:    http://localhost:8000/health${NC}"

# 5. CLI / Agent Option
echo -e "\n${BLUE}--- CLI & Agent Information ---${NC}"
echo -e "To interact with the NetSentinel AI Agent, run:"
echo -e "  python run_agent.py"
echo -e "\nTo view server logs, run:"
echo -e "  tail -f server.log"
echo -e "---------------------------------\n"
