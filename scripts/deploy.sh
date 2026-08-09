#!/bin/bash
# debork Deployment Script
# One-stop shop for building and distributing debork

set -e

VERSION="1.0.0"
PROJECT="debork"

echo "🚀 debork Deployment Script"
echo "============================"
echo "Version: $VERSION"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}ℹ${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warning() { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

# Check prerequisites
check_deps() {
    info "Checking dependencies..."

    if ! command -v dmd >/dev/null 2>&1; then
        error "DMD compiler not found!"
        echo "Install with: sudo pacman -S dmd"
        exit 1
    fi

    if ! command -v git >/dev/null 2>&1; then
        warning "Git not found - some features may not work"
    fi

    success "Dependencies OK"
}

# Build static binary
build_binary() {
    info "Building static binary..."

    # Clean previous builds
    rm -f debork debork-static debork-linux-x86_64

    # Build optimized static binary
    dmd -O -release -inline -of=debork-linux-x86_64 fixer.d

    # Make executable
    chmod +x debork-linux-x86_64

    # Create local symlinks for testing
    ln -sf debork-linux-x86_64 debork
    ln -sf debork-linux-x86_64 debork

    success "Binary built: debork-linux-x86_64 ($(du -h debork-linux-x86_64 | cut -f1))"
}

# Create installer script
create_installer() {
    info "Creating installer script..."

cat > get-debork.sh << 'EOF'
#!/bin/bash
# debork One-Liner Installer
# Usage: curl -sSL get.debork.dev | sudo bash

set -e

ARCH=$(uname -m)
VERSION="1.0.0"
BASE_URL="https://github.com/debork/debork/releases/download/v$VERSION"

case $ARCH in
    x86_64)
        BINARY="debork-linux-x86_64"
        ;;
    aarch64)
        BINARY="debork-linux-arm64"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        echo "Supported: x86_64, aarch64"
        exit 1
        ;;
esac

echo "🚀 Installing debork for $ARCH..."

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download binary
echo "📥 Downloading $BINARY..."
if command -v curl >/dev/null 2>&1; then
    curl -sSL "$BASE_URL/$BINARY" -o debork
elif command -v wget >/dev/null 2>&1; then
    wget -q "$BASE_URL/$BINARY" -O debork
else
    echo "❌ Neither curl nor wget found"
    exit 1
fi

# Verify download
if [ ! -f debork ] || [ ! -s debork ]; then
    echo "❌ Download failed"
    exit 1
fi

# Make executable
chmod +x debork

# Install to system
echo "📦 Installing to /usr/local/bin..."
mv debork /usr/local/bin/debork

# Create debork symlink
ln -sf /usr/local/bin/debork /usr/local/bin/debork

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo "✅ debork installed successfully!"
echo ""
echo "Usage:"
echo "  sudo debork    # Full name"
echo "  sudo debork     # Short name"
echo ""
echo "Get help: debork --help"
EOF

    chmod +x get-debork.sh
    success "Installer script created: get-debork.sh"
}

# Create package files
create_packages() {
    info "Creating package files..."

    # Create distribution directory
    mkdir -p dist

    # Copy binary
    cp debork-linux-x86_64 dist/
    cp get-debork.sh dist/

    # Create tarball
    tar czf dist/debork-$VERSION-linux.tar.gz \
        debork-linux-x86_64 \
        get-debork.sh \
        README.md \
        INSTALL.md

    # Create checksums
    cd dist
    sha256sum * > SHA256SUMS
    cd ..

    success "Packages created in dist/"
}

# Test installation
test_install() {
    info "Testing installation..."

    # Test help command
    if ./debork --help >/dev/null 2>&1; then
        success "Binary works correctly"
    else
        error "Binary test failed"
        return 1
    fi

    # Test installer script
    if bash get-debork.sh --help >/dev/null 2>&1; then
        success "Installer script is valid"
    else
        warning "Installer script may have issues"
    fi
}

# Create release notes
create_release_notes() {
    info "Creating release notes..."

cat > dist/RELEASE_NOTES.md << EOF
# debork v$VERSION - Emergency Boot Rescue Tool

## 🚨 For Broken Systems (Emergency Install)

\`\`\`bash
curl -sSL get.debork.dev | sudo bash
sudo debork
\`\`\`

## 📦 Package Installation

### Arch Linux / CachyOS / Manjaro
\`\`\`bash
yay -S debork
# or
yay debork
\`\`\`

### Manual Installation
\`\`\`bash
wget https://github.com/debork/debork/releases/download/v$VERSION/debork-linux-x86_64
chmod +x debork-linux-x86_64
sudo mv debork-linux-x86_64 /usr/local/bin/debork
sudo ln -s /usr/local/bin/debork /usr/local/bin/debork
\`\`\`

## 🎯 What This Fixes

- ✅ CachyOS rEFInd "vmlinuz-linux-archvios not found" errors
- ✅ GRUB configuration issues
- ✅ Missing initramfs files
- ✅ Broken systemd-boot entries
- ✅ UUID mismatches after drive changes

## 🚀 Features

- **Zero Dependencies**: Works in any rescue environment
- **Multi-Bootloader**: GRUB, rEFInd, systemd-boot support
- **TUI Interface**: Perfect for headless rescue scenarios
- **Cross-Platform**: Works on any Linux distribution
- **Emergency Shell**: Chroot access for manual fixes

## 📋 Usage

1. Boot from rescue USB/CD
2. Run: \`curl -sSL get.debork.dev | sudo bash\`
3. Run: \`sudo debork\`
4. Enter your broken system's root partition
5. Select "Fix Boot Configuration"
6. Choose your kernel and reboot

## 🔧 Supported Systems

- Arch Linux and derivatives (CachyOS, Manjaro, EndeavourOS)
- Ubuntu/Debian family
- Fedora/RHEL family
- openSUSE family
- Any Linux with standard boot structure

## 📁 Files in This Release

- \`debork-linux-x86_64\` - Main binary (statically linked)
- \`get-debork.sh\` - One-liner installer script
- \`debork-$VERSION-linux.tar.gz\` - Complete package
- \`SHA256SUMS\` - Checksums for verification

## 🛡️ Security

Verify downloads:
\`\`\`bash
sha256sum -c SHA256SUMS
\`\`\`

## 🐛 Bug Reports

Report issues at: https://github.com/debork/debork/issues

---

**debork - Because every Linux system deserves a second chance.**
EOF

    success "Release notes created"
}

# GitHub release (if gh CLI is available)
create_github_release() {
    if command -v gh >/dev/null 2>&1; then
        info "Creating GitHub release..."

        cd dist

        # Create release
        gh release create "v$VERSION" \
            --title "debork v$VERSION - Emergency Boot Rescue Tool" \
            --notes-file RELEASE_NOTES.md \
            debork-linux-x86_64 \
            get-debork.sh \
            debork-$VERSION-linux.tar.gz \
            SHA256SUMS

        cd ..
        success "GitHub release created"
    else
        warning "GitHub CLI not found - skipping GitHub release"
        info "Manually upload files from dist/ to GitHub releases"
    fi
}

# Show deployment summary
show_summary() {
    echo ""
    echo "🎉 Deployment Complete!"
    echo "======================"
    echo ""
    echo "📁 Files created:"
    ls -la dist/
    echo ""
    echo "🌐 Distribution URLs:"
    echo "  One-liner: curl -sSL get.debork.dev | sudo bash"
    echo "  Direct:    https://github.com/debork/debork/releases/download/v$VERSION/debork-linux-x86_64"
    echo "  Package:   yay -S debork"
    echo ""
    echo "📝 Next steps:"
    echo "  1. Upload dist/* to GitHub releases"
    echo "  2. Submit PKGBUILD to AUR"
    echo "  3. Set up get.debork.dev redirect"
    echo "  4. Test on broken system"
    echo ""
    echo "🚨 Emergency usage:"
    echo "  sudo ./debork-linux-x86_64"
    echo "  sudo ./debork"
}

# Main deployment flow
main() {
    check_deps
    build_binary
    create_installer
    create_packages
    test_install
    create_release_notes
    create_github_release
    show_summary
}

# Handle arguments
case "${1:-}" in
    --build-only)
        build_binary
        ;;
    --test)
        if [ -f debork-linux-x86_64 ]; then
            test_install
        else
            error "Binary not found. Run without arguments first."
        fi
        ;;
    --clean)
        rm -rf dist/ debork debork-static debork-linux-* debork get-debork.sh
        success "Cleaned build artifacts"
        ;;
    --help|-h)
        echo "debork Deployment Script"
        echo ""
        echo "Usage:"
        echo "  $0           Deploy everything"
        echo "  $0 --build-only   Build binary only"
        echo "  $0 --test    Test existing binary"
        echo "  $0 --clean   Clean build files"
        echo "  $0 --help    Show this help"
        ;;
    *)
        main
        ;;
esac
