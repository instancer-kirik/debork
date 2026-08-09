#!/bin/bash

# Run script for debork-cute - The kawaii boot rescue tool
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

# Cute emoji/symbols
HEART="♥"
STAR="★"
SPARKLE="✨"
PENGUIN="🐧"
CHECK="✓"
CROSS="✗"

print_header() {
    echo -e "${MAGENTA}╭────────────────────────────────────╮${RESET}"
    echo -e "${MAGENTA}│${WHITE}  ${HEART} debork-cute launcher ${HEART}        ${MAGENTA}│${RESET}"
    echo -e "${MAGENTA}│${CYAN}    Kawaii Boot Rescue Tool ${SPARKLE}     ${MAGENTA}│${RESET}"
    echo -e "${MAGENTA}╰────────────────────────────────────╯${RESET}"
    echo
}

print_help() {
    print_header
    echo -e "${YELLOW}Usage:${RESET} $0 [OPTIONS]"
    echo
    echo -e "${CYAN}Options:${RESET}"
    echo -e "  ${GREEN}--build${RESET}     Build the cute version before running"
    echo -e "  ${GREEN}--clean${RESET}     Clean build artifacts before building"
    echo -e "  ${GREEN}--demo${RESET}      Run in demo mode (safe, no system changes)"
    echo -e "  ${GREEN}--real${RESET}      Run in real mode (requires root)"
    echo -e "  ${GREEN}--debug${RESET}     Build with debug symbols"
    echo -e "  ${GREEN}--help${RESET}      Show this help message"
    echo
    echo -e "${CYAN}Examples:${RESET}"
    echo -e "  $0              ${WHITE}# Run in demo mode${RESET}"
    echo -e "  $0 --build      ${WHITE}# Build and run in demo mode${RESET}"
    echo -e "  sudo $0 --real  ${WHITE}# Run in real mode (as root)${RESET}"
    echo
}

# Parse arguments
BUILD=false
CLEAN=false
DEMO=true
DEBUG=false

for arg in "$@"; do
    case $arg in
        --build)
            BUILD=true
            ;;
        --clean)
            CLEAN=true
            BUILD=true
            ;;
        --demo)
            DEMO=true
            ;;
        --real)
            DEMO=false
            ;;
        --debug)
            DEBUG=true
            BUILD=true
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            echo -e "${RED}${CROSS} Unknown option: $arg${RESET}"
            print_help
            exit 1
            ;;
    esac
done

print_header

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}${STAR} Cleaning build artifacts...${RESET}"
    make clean
    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS} Clean failed!${RESET}"
        exit 1
    fi
    echo -e "${GREEN}${CHECK} Clean completed!${RESET}"
    echo
fi

# Build if requested or if binary doesn't exist
if [ "$BUILD" = true ] || [ ! -f "debork-cute" ]; then
    echo -e "${YELLOW}${STAR} Building debork-cute...${RESET}"

    if [ "$DEBUG" = true ]; then
        gcc -g -O0 -DDEBUG -Wall -Wextra -std=c11 -o debork-cute src/c/debork_cute.c -lm
    else
        make cute
    fi

    if [ $? -ne 0 ]; then
        echo -e "${RED}${CROSS} Build failed!${RESET}"
        echo -e "${YELLOW}Make sure you have:${RESET}"
        echo -e "  - GCC installed (with C11 support)"
        echo -e "  - Math library available (-lm)"
        echo -e "  - Source file: src/c/debork_cute.c"
        exit 1
    fi
    echo -e "${GREEN}${CHECK} Build successful!${RESET}"
    echo
fi

# Check if binary exists
if [ ! -f "debork-cute" ]; then
    echo -e "${RED}${CROSS} debork-cute binary not found!${RESET}"
    echo -e "${YELLOW}Run with --build to compile it first.${RESET}"
    exit 1
fi

# Run the program
if [ "$DEMO" = true ]; then
    echo -e "${CYAN}${PENGUIN} Starting debork-cute in DEMO mode...${RESET}"
    echo -e "${YELLOW}(Safe mode - no system changes will be made)${RESET}"
    echo
    ./debork-cute --demo
else
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}${CROSS} Real mode requires root privileges!${RESET}"
        echo -e "${YELLOW}Try: sudo $0 --real${RESET}"
        echo -e "${CYAN}Or run in demo mode: $0 --demo${RESET}"
        exit 1
    fi

    echo -e "${CYAN}${PENGUIN} Starting debork-cute in REAL mode...${RESET}"
    echo -e "${RED}⚠️  WARNING: This mode can modify your system!${RESET}"
    echo -e "${YELLOW}Press Ctrl+C within 3 seconds to cancel...${RESET}"
    sleep 3
    echo
    ./debork-cute
fi

# Exit code from debork-cute
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}${CHECK} debork-cute exited successfully! ${SPARKLE}${RESET}"
else
    echo -e "${YELLOW}debork-cute exited with code: $EXIT_CODE${RESET}"
fi

echo -e "${MAGENTA}${HEART} Thanks for using debork-cute! Stay kawaii! ${HEART}${RESET}"
