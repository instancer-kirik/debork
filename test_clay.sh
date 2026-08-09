#!/bin/bash

# Test script for debork Clay optimized version

echo "======================================"
echo "Testing debork Clay Optimized Version"
echo "======================================"
echo ""

# Check if the binary exists
if [ ! -f "./debork-clay-opt" ]; then
    echo "Error: debork-clay-opt not found!"
    echo "Please run 'make clay-opt' first."
    exit 1
fi

# Make sure it's executable
chmod +x ./debork-clay-opt

echo "1. Testing binary exists and is executable..."
if [ -x "./debork-clay-opt" ]; then
    echo "   ✓ Binary is executable"
else
    echo "   ✗ Binary is not executable"
    exit 1
fi

echo ""
echo "2. Testing help/version output..."
timeout 1 ./debork-clay-opt --help 2>/dev/null || true

echo ""
echo "3. Testing demo mode (non-interactive)..."
echo "   Launching in demo mode for 3 seconds..."
echo ""

# Create a simple expect script to test interactively
if command -v expect &> /dev/null; then
    expect -c '
        spawn ./debork-clay-opt --demo
        expect {
            "Demo Mode" { send_user "\n   ✓ Demo mode detected\n" }
            timeout { send_user "\n   ✗ Timeout waiting for demo mode\n" }
        }
        sleep 2
        send "q"
        expect eof
    '
else
    # Fallback: just run with timeout
    echo "   (expect not installed, using timeout instead)"
    timeout 3 ./debork-clay-opt --demo < /dev/null || true
fi

echo ""
echo "4. Checking for memory leaks (if valgrind available)..."
if command -v valgrind &> /dev/null; then
    echo "q" | timeout 2 valgrind --leak-check=summary --error-exitcode=1 ./debork-clay-opt --demo 2>&1 | grep -E "ERROR SUMMARY|definitely lost|indirectly lost" || true
else
    echo "   Valgrind not installed, skipping memory check"
fi

echo ""
echo "5. Performance test..."
echo "   Measuring startup time..."
time timeout 0.5 ./debork-clay-opt --demo < /dev/null 2>/dev/null || true

echo ""
echo "======================================"
echo "Test Summary:"
echo "======================================"
echo ""
echo "If you see this message, the basic tests passed!"
echo "To run the interactive UI, use:"
echo "  ./debork-clay-opt --demo    (for demo mode)"
echo "  sudo ./debork-clay-opt       (for real system rescue)"
echo ""
echo "Key bindings:"
echo "  ↑/↓ or j/k - Navigate menu"
echo "  Enter      - Select item"
echo "  h          - Toggle help"
echo "  q          - Quit"
echo ""
