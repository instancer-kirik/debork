#!/bin/bash
# debork Build Script for Rescue Scenarios
# This script can build debork even in minimal rescue environments

set -e

echo "debork Boot Rescue Tool - Build Script"
echo "======================================="

# Check if we're running as root (recommended for rescue scenarios)
if [[ $EUID -eq 0 ]]; then
    echo "⚠ Running as root - this is OK for rescue scenarios"
fi

# Detect available D compilers
DC=""
if command -v dmd >/dev/null 2>&1; then
    DC="dmd"
    echo "✓ Found DMD compiler"
elif command -v ldc2 >/dev/null 2>&1; then
    DC="ldc2"
    echo "✓ Found LDC2 compiler"
elif command -v gdc >/dev/null 2>&1; then
    DC="gdc"
    echo "✓ Found GDC compiler"
else
    echo "✗ No D compiler found!"
    echo ""
    echo "Please install a D compiler:"
    echo "  Arch/Manjaro: sudo pacman -S dmd"
    echo "  Ubuntu/Debian: sudo apt install dmd-compiler"
    echo "  Fedora: sudo dnf install dmd"
    echo "  Or download from: https://dlang.org/download.html"
    exit 1
fi

# Check if source file exists
if [[ ! -f "fixer.d" ]]; then
    echo "✗ Source file 'fixer.d' not found!"
    echo "Make sure you're in the debork directory"
    exit 1
fi

# Build options
BUILD_TYPE="release"
OUTPUT="debork"
DFLAGS=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug|-d)
            BUILD_TYPE="debug"
            shift
            ;;
        --static|-s)
            BUILD_TYPE="static"
            OUTPUT="debork-static"
            shift
            ;;
        --output|-o)
            OUTPUT="$2"
            shift 2
            ;;
        --help|-h)
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --debug, -d     Build with debug symbols"
            echo "  --static, -s    Build static binary for rescue"
            echo "  --output, -o    Specify output filename"
            echo "  --help, -h      Show this help"
            echo ""
            echo "Examples:"
            echo "  $0              # Standard release build"
            echo "  $0 --debug      # Debug build"
            echo "  $0 --static     # Static rescue binary"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set compiler flags based on build type and compiler
case $BUILD_TYPE in
    "release")
        case $DC in
            "dmd")
                DFLAGS="-O -release -inline"
                ;;
            "ldc2")
                DFLAGS="-O3 -release -enable-inlining"
                ;;
            "gdc")
                DFLAGS="-O3 -frelease -finline-functions"
                ;;
        esac
        echo "Building release version..."
        ;;
    "debug")
        case $DC in
            "dmd")
                DFLAGS="-g -debug"
                ;;
            "ldc2")
                DFLAGS="-g -d-debug"
                ;;
            "gdc")
                DFLAGS="-g -fdebug"
                ;;
        esac
        echo "Building debug version..."
        ;;
    "static")
        case $DC in
            "dmd")
                DFLAGS="-O -release -inline -static"
                ;;
            "ldc2")
                DFLAGS="-O3 -release -enable-inlining -static"
                ;;
            "gdc")
                DFLAGS="-O3 -frelease -finline-functions -static"
                ;;
        esac
        echo "Building static version for rescue scenarios..."
        ;;
esac

# Build the binary
echo "Compiler: $DC"
echo "Flags: $DFLAGS"
echo "Output: $OUTPUT"
echo ""

# Compile
if [[ $DC == "dmd" ]]; then
    $DC $DFLAGS -of$OUTPUT fixer.d
elif [[ $DC == "ldc2" ]]; then
    $DC $DFLAGS -of=$OUTPUT fixer.d
else # gdc
    $DC $DFLAGS -o $OUTPUT fixer.d
fi

# Check if build was successful
if [[ -f "$OUTPUT" ]]; then
    echo "✓ Build successful!"
    echo ""

    # Show binary info
    if command -v file >/dev/null 2>&1; then
        echo "Binary info:"
        file "$OUTPUT"
    fi

    if command -v du >/dev/null 2>&1; then
        SIZE=$(du -h "$OUTPUT" | cut -f1)
        echo "Size: $SIZE"
    fi

    echo ""
    echo "Usage: sudo ./$OUTPUT"

    # Make executable
    chmod +x "$OUTPUT"

    # Offer to install system-wide
    if [[ $BUILD_TYPE == "release" ]] && [[ $EUID -eq 0 ]]; then
        echo ""
        read -p "Install to /usr/local/bin? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp "$OUTPUT" /usr/local/bin/debork
            chmod +x /usr/local/bin/debork
            echo "✓ Installed to /usr/local/bin/debork"
            echo "Run with: debork"
        fi
    fi

    # For rescue scenarios, show copy instructions
    if [[ $BUILD_TYPE == "static" ]]; then
        echo ""
        echo "For rescue scenarios:"
        echo "1. Copy '$OUTPUT' to your rescue USB/CD"
        echo "2. Boot from rescue media"
        echo "3. Run: sudo ./$OUTPUT"
    fi

else
    echo "✗ Build failed!"
    exit 1
fi

echo ""
echo "Build complete!"
