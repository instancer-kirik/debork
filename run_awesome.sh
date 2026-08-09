#!/bin/bash

# ============================================================================
# debork Awesome Clay UI - Launch Script
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Configuration
BINARY="./debork-clay-awesome"
SOURCE="src/c/debork_clay_awesome.c"

# ============================================================================
# Functions
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║         ${BOLD}⚡ DEBORK AWESOME EDITION ⚡${RESET}${CYAN}              ║"
    echo "║          Beautiful Terminal Boot Rescue            ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

check_terminal() {
    # Check terminal capabilities
    if [ ! -t 1 ]; then
        echo -e "${RED}Error: This program requires an interactive terminal${RESET}"
        exit 1
    fi

    # Check for true color support
    if [[ "${COLORTERM}" == "truecolor" ]] || [[ "${COLORTERM}" == "24bit" ]]; then
        echo -e "${GREEN}✓${RESET} True color terminal detected"
    else
        echo -e "${YELLOW}⚠${RESET} No true color support detected. Colors may be limited."
        echo "   For best experience, use a modern terminal like:"
        echo "   - kitty, alacritty, wezterm, or modern gnome-terminal/konsole"
    fi

    # Check terminal size
    COLS=$(tput cols)
    LINES=$(tput lines)
    if [ $COLS -lt 80 ] || [ $LINES -lt 24 ]; then
        echo -e "${YELLOW}⚠${RESET} Terminal size is ${COLS}x${LINES}. Recommended minimum: 80x24"
        echo "   Please resize your terminal for optimal experience."
    else
        echo -e "${GREEN}✓${RESET} Terminal size: ${COLS}x${LINES}"
    fi
}

build_if_needed() {
    if [ ! -f "$BINARY" ]; then
        echo -e "${YELLOW}Binary not found. Building...${RESET}"
        make clay-awesome
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Build successful!${RESET}"
        else
            echo -e "${RED}✗ Build failed!${RESET}"
            exit 1
        fi
    elif [ "$SOURCE" -nt "$BINARY" ]; then
        echo -e "${YELLOW}Source file is newer than binary. Rebuilding...${RESET}"
        make clay-awesome
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Rebuild successful!${RESET}"
        else
            echo -e "${RED}✗ Rebuild failed!${RESET}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓${RESET} Binary is up to date"
    fi
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --demo, -d     Run in demo mode (default)"
    echo "  --real, -r     Run in real mode (requires root)"
    echo "  --build, -b    Force rebuild before running"
    echo "  --clean, -c    Clean and rebuild"
    echo "  --help, -h     Show this help message"
    echo ""
    echo "Keyboard shortcuts in the UI:"
    echo "  ↑/↓ or j/k    Navigate menu"
    echo "  Enter         Select item"
    echo "  q             Quit"
    echo "  Ctrl+L        Refresh screen"
    echo ""
    echo "Examples:"
    echo "  $0             # Run in demo mode"
    echo "  $0 --build     # Rebuild and run"
    echo "  sudo $0 --real # Run as root for real system rescue"
}

# ============================================================================
# Main Script
# ============================================================================

# Default to demo mode for safety
MODE="--demo"
FORCE_BUILD=false
CLEAN_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --demo|-d)
            MODE="--demo"
            shift
            ;;
        --real|-r)
            MODE=""
            shift
            ;;
        --build|-b)
            FORCE_BUILD=true
            shift
            ;;
        --clean|-c)
            CLEAN_BUILD=true
            shift
            ;;
        --help|-h)
            print_banner
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${RESET}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Clear screen for clean start
clear

# Print banner
print_banner

# Check terminal capabilities
check_terminal
echo ""

# Clean if requested
if [ "$CLEAN_BUILD" = true ]; then
    echo -e "${YELLOW}Cleaning build artifacts...${RESET}"
    make clean
    echo -e "${GREEN}✓ Clean complete${RESET}"
    echo ""
fi

# Build if needed or forced
if [ "$FORCE_BUILD" = true ]; then
    echo -e "${YELLOW}Forcing rebuild...${RESET}"
    rm -f "$BINARY"
fi
build_if_needed
echo ""

# Check if running as root when in real mode
if [ -z "$MODE" ] && [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Real mode requires root privileges${RESET}"
    echo "Please run with sudo: sudo $0 --real"
    echo "Or use demo mode: $0 --demo"
    exit 1
fi

# Launch the program
if [ -n "$MODE" ]; then
    echo -e "${MAGENTA}🎮 Launching in DEMO MODE${RESET}"
    echo -e "${CYAN}This is safe for testing - no system changes will be made${RESET}"
else
    echo -e "${RED}⚠️  LAUNCHING IN REAL MODE${RESET}"
    echo -e "${YELLOW}System changes will be applied! Be careful!${RESET}"
    echo -n "Press Enter to continue or Ctrl+C to cancel..."
    read
fi

echo ""
echo -e "${BOLD}Starting debork...${RESET}"
sleep 1

# Run the program
exec "$BINARY" $MODE
