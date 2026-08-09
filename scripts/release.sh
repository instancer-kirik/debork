#!/bin/bash
# debork Release Script
# Builds static binaries for multiple architectures and creates downloadable releases

set -e

VERSION="1.0.0"
PROJECT="debork"
GITHUB_REPO="debork/debork"
RELEASE_DIR="releases"

echo "debork Release Builder v$VERSION"
echo "================================="

# Clean previous releases
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

# Check dependencies
echo "Checking dependencies..."
if ! command -v dmd >/dev/null 2>&1; then
    echo "✗ DMD compiler not found"
    echo "Install with: sudo pacman -S dmd"
    exit 1
fi

if ! command -v upx >/dev/null 2>&1; then
    echo "⚠ UPX not found - binaries will be larger"
    echo "Install with: sudo pacman -S upx"
    UPX_AVAILABLE=false
else
    UPX_AVAILABLE=true
fi

echo "✓ Dependencies OK"

# Build function
build_binary() {
    local arch="$1"
    local output="$2"
    local flags="$3"

    echo "Building $arch binary..."

    # Compile
    dmd -O -release -inline $flags -of="$output" fixer.d

    # Strip symbols to reduce size
    strip "$output" 2>/dev/null || true

    # Compress with UPX if available
    if [ "$UPX_AVAILABLE" = true ]; then
        upx --best "$output" 2>/dev/null || true
    fi

    # Make executable
    chmod +x "$output"

    echo "✓ Built $output ($(du -h "$output" | cut -f1))"
}

# Build binaries for different architectures
echo ""
echo "Building release binaries..."

# x86_64 (most common)
build_binary "x86_64" "$RELEASE_DIR/debork-linux-x86_64" ""

# Create installer script
cat > "$RELEASE_DIR/install.sh" << 'EOF'
#!/bin/bash
# debork Quick Installer

set -e

ARCH=$(uname -m)
BINARY=""

case $ARCH in
    x86_64)
        BINARY="debork-linux-x86_64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

if [ ! -f "$BINARY" ]; then
    echo "Binary $BINARY not found in current directory"
    exit 1
fi

echo "Installing debork for $ARCH..."

# Install to /usr/local/bin
sudo cp "$BINARY" /usr/local/bin/debork
sudo chmod +x /usr/local/bin/debork

# Create debork symlink
sudo ln -sf /usr/local/bin/debork /usr/local/bin/debork

echo "✓ debork installed!"
echo "Usage: sudo debork  or  sudo debork"
EOF

chmod +x "$RELEASE_DIR/install.sh"

# Create portable package
echo ""
echo "Creating portable packages..."

cd "$RELEASE_DIR"

# Create main package
tar czf "debork-$VERSION-linux.tar.gz" \
    debork-linux-x86_64 \
    install.sh

# Create individual architecture packages
for binary in debork-linux-*; do
    if [ -f "$binary" ]; then
        arch_name=$(echo "$binary" | cut -d'-' -f3)
        tar czf "debork-$VERSION-$arch_name.tar.gz" "$binary" install.sh
    fi
done

cd ..

# Create one-liner download script
cat > "$RELEASE_DIR/get-debork.sh" << EOF
#!/bin/bash
# debork One-Liner Installer
# Usage: curl -sSL https://get.debork.dev | sudo bash

set -e

ARCH=\$(uname -m)
VERSION="$VERSION"
BASE_URL="https://github.com/$GITHUB_REPO/releases/download/v\$VERSION"

case \$ARCH in
    x86_64)
        BINARY="debork-linux-x86_64"
        ;;
    *)
        echo "Unsupported architecture: \$ARCH"
        exit 1
        ;;
esac

echo "Downloading debork \$VERSION for \$ARCH..."

# Download binary
curl -sSL "\$BASE_URL/\$BINARY" -o /tmp/debork
chmod +x /tmp/debork

# Install
mv /tmp/debork /usr/local/bin/debork
ln -sf /usr/local/bin/debork /usr/local/bin/debork

echo "✓ debork installed!"
echo "Usage: sudo debork  or  sudo debork"
EOF

chmod +x "$RELEASE_DIR/get-debork.sh"

# Create checksums
echo ""
echo "Generating checksums..."
cd "$RELEASE_DIR"
sha256sum * > SHA256SUMS
cd ..

# Create release notes
cat > "$RELEASE_DIR/RELEASE_NOTES.md" << EOF
# debork v$VERSION Release Notes

Cross-platform Linux boot rescue tool with TUI interface.

## Quick Install

### One-liner (recommended for rescue scenarios):
\`\`\`bash
curl -sSL https://get.debork.dev | sudo bash
\`\`\`

### Manual download:
\`\`\`bash
# Download for your architecture
wget https://github.com/$GITHUB_REPO/releases/download/v$VERSION/debork-$VERSION-linux.tar.gz

# Extract and install
tar xzf debork-$VERSION-linux.tar.gz
sudo ./install.sh
\`\`\`

### Package managers:
\`\`\`bash
# Arch Linux (AUR)
yay -S debork
# or
yay debork

# Manual build from AUR
git clone https://aur.archlinux.org/debork.git
cd debork && makepkg -si
\`\`\`

## Usage

\`\`\`bash
sudo debork    # Full interface
sudo debork     # Same thing, shorter name
\`\`\`

## What's New in v$VERSION

- Multi-bootloader support (GRUB, rEFInd, systemd-boot)
- Interactive TUI for rescue scenarios
- Automatic boot configuration detection
- Kernel/initramfs management
- Emergency chroot shell
- Cross-platform compatibility

## Supported Systems

- ✅ CachyOS (rEFInd issues)
- ✅ Arch Linux and derivatives
- ✅ Ubuntu/Debian family
- ✅ Fedora/RHEL family
- ✅ openSUSE family
- ✅ Any Linux with standard boot structure

## Files in this Release

- \`debork-linux-x86_64\` - Main binary for 64-bit systems
- \`install.sh\` - Installation script
- \`get-debork.sh\` - One-liner installer script
- \`SHA256SUMS\` - Checksums for verification

## Verification

\`\`\`bash
sha256sum -c SHA256SUMS
\`\`\`
EOF

# Summary
echo ""
echo "========================================="
echo "Release v$VERSION built successfully!"
echo "========================================="
echo ""
echo "Files created in $RELEASE_DIR/:"
ls -la "$RELEASE_DIR/"
echo ""
echo "Upload these files to GitHub releases:"
echo "1. Create release: https://github.com/$GITHUB_REPO/releases/new"
echo "2. Tag: v$VERSION"
echo "3. Upload all files from $RELEASE_DIR/"
echo ""
echo "One-liner for users:"
echo "curl -sSL https://get.debork.dev | sudo bash"
echo ""
echo "Package install:"
echo "yay debork"
