#!/bin/bash
# Test script for debork Clay UI

echo "🎨 Testing debork Clay UI..."
echo "================================"
echo ""

# Check if the binary exists
if [ ! -f "./build/debork-clay" ]; then
    echo "❌ Error: debork-clay not found!"
    echo "   Please build it first with: make -f Makefile.c clay"
    exit 1
fi

# Function to test the UI with automated input
test_ui() {
    echo "📱 Starting UI demo mode..."
    echo "   This will navigate through the menu automatically"
    echo ""

    # Create a named pipe for input
    PIPE=$(mktemp -u)
    mkfifo "$PIPE"

    # Start the program with the pipe as input
    ./build/debork-clay --demo < "$PIPE" &
    PID=$!

    # Send automated input to navigate the menu
    exec 3>"$PIPE"

    # Wait a moment for the UI to load
    sleep 0.5

    # Navigate down twice
    echo -n "j" >&3
    sleep 0.5
    echo -n "j" >&3
    sleep 0.5

    # Navigate up once
    echo -n "k" >&3
    sleep 0.5

    # Navigate down again
    echo -n "j" >&3
    sleep 0.5
    echo -n "j" >&3
    sleep 0.5

    # Hold for viewing
    sleep 2

    # Quit
    echo -n "q" >&3

    # Clean up
    exec 3>&-
    rm "$PIPE"
    wait $PID 2>/dev/null

    echo ""
    echo "✅ UI demo complete!"
}

# Function for interactive test
interactive_test() {
    echo "🎮 Starting interactive mode..."
    echo ""
    echo "Controls:"
    echo "  ↑/↓ or j/k - Navigate menu"
    echo "  Enter      - Select item"
    echo "  q          - Quit"
    echo ""
    echo "Press any key to start..."
    read -n 1

    ./build/debork-clay --demo
}

# Main menu
echo "Choose test mode:"
echo "1) Automated demo (shows UI navigation)"
echo "2) Interactive mode (you control it)"
echo "3) Quick view (just show and exit)"
echo ""
read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        test_ui
        ;;
    2)
        interactive_test
        ;;
    3)
        echo "Quick view - UI will display for 3 seconds..."
        timeout 3 ./build/debork-clay --demo 2>/dev/null || true
        echo "Done!"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "🎉 Test complete!"
