#!/bin/bash
# Integrated Web Application Startup Script

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================================"
echo "  Network Anomaly Detection - Integrated Web Application"
echo "================================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run with sudo${NC}"
    echo ""
    echo "Usage:"
    echo "  sudo ./start_integrated_app.sh <interface> [threshold]"
    echo ""
    echo "Examples:"
    echo "  sudo ./start_integrated_app.sh eth0"
    echo "  sudo ./start_integrated_app.sh enp1s0 0.7"
    echo "  sudo ./start_integrated_app.sh wlan0 0.8"
    echo ""
    exit 1
fi

# Get interface from argument
INTERFACE=${1:-}
THRESHOLD=${2:-0.7}

if [ -z "$INTERFACE" ]; then
    echo -e "${RED}ERROR: Network interface not specified${NC}"
    echo ""
    echo "Available interfaces:"
    ip -br link show | grep -v lo
    echo ""
    echo "Usage:"
    echo "  sudo ./start_integrated_app.sh <interface> [threshold]"
    echo ""
    echo "Example:"
    echo "  sudo ./start_integrated_app.sh eth0 0.7"
    echo ""
    exit 1
fi

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}ERROR: Interface '$INTERFACE' not found${NC}"
    echo ""
    echo "Available interfaces:"
    ip -br link show | grep -v lo
    echo ""
    exit 1
fi

echo -e "${GREEN}✓${NC} Interface: $INTERFACE"
echo -e "${GREEN}✓${NC} Threshold: $THRESHOLD"
echo ""

# Check dependencies
echo "Checking dependencies..."
python3 -c "import fastapi, uvicorn, scapy, joblib, pandas" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠${NC} Some dependencies are missing"
    echo "Installing requirements..."
    pip3 install -r requirements.txt
fi

# Start the application
echo ""
echo "================================================================"
echo "Starting Integrated Web Application..."
echo "================================================================"
echo ""
echo -e "${GREEN}Web Interface:${NC} http://localhost:8000"
echo -e "${GREEN}API Endpoint:${NC}  http://localhost:8000/api/stats"
echo ""
echo "Press Ctrl+C to stop"
echo ""

python3 integrated_web_app.py --interface "$INTERFACE" --threshold "$THRESHOLD"
