#!/bin/bash

# Test script for the fixed Clay UI version
# This version properly handles text/background synchronization

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "════════════════════════════════════════════════════════"
echo "     Testing debork Clay UI - Fixed Version"
echo "     No grey boxes, perfect text/bg alignment"
echo "════════════════════════════════════════════════════════"
echo -e "${RESET}"

# Check if binary exists
if [ ! -f "./debork-clay-fixed" ]; then
    echo -e "${YELLOW}Building fixed version...${RESET}"
    make clay-fixed
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Build successful${RESET}"
    else
        echo -e "${RED}✗ Build failed${RESET}"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}Key improvements in this version:${RESET}"
echo "  • Fixed text/background synchronization"
echo "  • No transparent bounding boxes rendered"
echo "  • Proper alpha channel filtering (a < 250 ignored)"
echo "  • Two-pass rendering (backgrounds then text)"
echo "  • Clean container hierarchy without spurious backgrounds"
echo ""

echo -e "${GREEN}Launching in demo mode...${RESET}"
echo -e "${CYAN}Controls:${RESET}"
echo "  ↑/↓ or j/k - Navigate"
echo "  Enter      - Select"
echo "  q          - Quit"
echo ""
echo -e "${YELLOW}Press Enter to start...${RESET}"
read

# Run the fixed version
./debork-clay-fixed --demo
