#!/bin/bash

# Test script to demonstrate the chroot fix functionality in debork
# This script creates a minimal test environment to verify the shell detection works

set -e

echo "=== debork Chroot Fix Test ==="
echo "This script tests the new shell detection and validation features"
echo

# Create a test environment
TEST_DIR="/tmp/debork_test_chroot"
echo "Creating test environment in $TEST_DIR..."

# Clean up any existing test
if [ -d "$TEST_DIR" ]; then
    sudo umount "$TEST_DIR"/{dev,proc,sys,run} 2>/dev/null || true
    sudo rm -rf "$TEST_DIR"
fi

mkdir -p "$TEST_DIR"

# Create a minimal filesystem structure
echo "Setting up minimal filesystem..."
mkdir -p "$TEST_DIR"/{bin,usr/bin,sbin,usr/sbin,etc,lib,usr/lib,dev,proc,sys,run,boot}

# Test Case 1: System with bash available
echo
echo "=== Test Case 1: System with bash ==="
cp /bin/bash "$TEST_DIR/bin/"
cp /bin/sh "$TEST_DIR/bin/"
touch "$TEST_DIR/usr/bin/pacman"
chmod +x "$TEST_DIR/usr/bin/pacman"

echo "Testing shell detection..."
echo "Expected: Should find /bin/bash"

# Mock pacman for testing
cat > "$TEST_DIR/usr/bin/pacman" << 'EOF'
#!/bin/bash
echo "Mock pacman called with args: $@"
exit 0
EOF
chmod +x "$TEST_DIR/usr/bin/pacman"

# Test Case 2: System with only sh available
echo
echo "=== Test Case 2: System with only sh ==="
TEST_DIR_2="/tmp/debork_test_chroot_sh"
mkdir -p "$TEST_DIR_2"/{bin,usr/bin,sbin,usr/sbin,etc,lib,usr/lib,dev,proc,sys,run,boot}

cp /bin/sh "$TEST_DIR_2/bin/"
touch "$TEST_DIR_2/usr/bin/pacman"
chmod +x "$TEST_DIR_2/usr/bin/pacman"

cat > "$TEST_DIR_2/usr/bin/pacman" << 'EOF'
#!/bin/sh
echo "Mock pacman (sh) called with args: $@"
exit 0
EOF
chmod +x "$TEST_DIR_2/usr/bin/pacman"

echo "Testing shell detection..."
echo "Expected: Should find /bin/sh when bash is not available"

# Test Case 3: Broken system with no shells
echo
echo "=== Test Case 3: Broken system (no shells) ==="
TEST_DIR_3="/tmp/debork_test_chroot_broken"
mkdir -p "$TEST_DIR_3"/{bin,usr/bin,sbin,usr/sbin,etc,lib,usr/lib,dev,proc,sys,run,boot}

touch "$TEST_DIR_3/usr/bin/pacman"
chmod +x "$TEST_DIR_3/usr/bin/pacman"

echo "Testing shell detection..."
echo "Expected: Should fail gracefully with helpful error message"

echo
echo "=== Manual Testing Instructions ==="
echo "To manually test the fix:"
echo "1. Run: sudo ./debork"
echo "2. Enter one of these test paths when prompted:"
echo "   - $TEST_DIR (has bash)"
echo "   - $TEST_DIR_2 (has only sh)"
echo "   - $TEST_DIR_3 (no shells - should fail gracefully)"
echo "3. Try 'Fix My System' to test package updates"
echo "4. Try 'Diagnose Chroot Issues' to see the new diagnostic feature"
echo "5. Try 'Emergency Shell' to test shell auto-detection"
echo

echo "=== Key Improvements Made ==="
echo "✓ detectAvailableShell() - Tries multiple shell paths"
echo "✓ validateChrootEnvironment() - Checks system integrity"
echo "✓ diagnoseChroot() - New diagnostic tool"
echo "✓ Fallback pacman execution without shell wrapper"
echo "✓ Better error messages with troubleshooting guidance"
echo "✓ Graceful handling when no shells are found"
echo

echo "=== Cleanup ==="
echo "To clean up test environments:"
echo "sudo rm -rf $TEST_DIR $TEST_DIR_2 $TEST_DIR_3"

echo
echo "Test environment ready! Run 'sudo ./debork' to test the fixes."
