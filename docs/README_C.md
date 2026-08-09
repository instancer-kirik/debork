# debork - C Version with Clay TUI

A complete rewrite of debork in C with Clay for terminal UI rendering and optional Cosmopolitan libc support for ultimate portability.

## Overview

This is a C implementation of the debork Linux boot rescue tool, featuring:

- **Clay-based TUI** - Modern, responsive terminal UI using the Clay immediate mode GUI library
- **Cosmopolitan libc support** - Build truly portable binaries that run on multiple operating systems
- **Zero dependencies** - Static binary with everything built-in
- **Smaller footprint** - More efficient than the D version
- **Better compatibility** - Works on more systems and rescue environments

## Features

### Core Functionality
- ✅ Multi-bootloader support (GRUB, rEFInd, systemd-boot)
- ✅ Interactive TUI interface with keyboard navigation
- ✅ Automatic boot configuration detection and repair
- ✅ Kernel and initramfs management
- ✅ Emergency shell access for manual repairs
- ✅ System information display
- ✅ Configuration backup and restore

### C Version Advantages
- **Portability** - Single binary works everywhere
- **Performance** - Faster startup and lower memory usage
- **Clay UI** - Smooth, modern terminal interface
- **Cosmopolitan** - Optional APE format for cross-platform compatibility
- **Minimal size** - ~500KB static binary vs 2MB+ for D version

## Building

### Quick Build

```bash
# Standard static Linux binary
make

# Ultra-portable Cosmopolitan build
make cosmopolitan

# Debug build
make debug
```

### Build Options

#### Standard Build (Recommended for Linux)
```bash
make standard
```
Creates a statically linked Linux binary with all features.

#### Cosmopolitan Build (Maximum Portability)
```bash
make cosmopolitan
```
Creates an Actually Portable Executable (APE) that runs on:
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)
- FreeBSD, OpenBSD, NetBSD

#### Using the Build Script
```bash
./build_cosmo.sh         # Auto-detect and build best version
./build_cosmo.sh cosmo   # Force Cosmopolitan build
./build_cosmo.sh standard # Force standard build
./build_cosmo.sh clean   # Clean build artifacts
```

### Requirements

#### For Standard Build
- GCC or Clang
- Standard C library
- POSIX environment

#### For Cosmopolitan Build
- GCC
- wget (for downloading Cosmopolitan)
- Basic POSIX tools

## Installation

### System-wide Installation
```bash
sudo make install
```

### Portable Installation
```bash
# Create portable package
make package

# Extract anywhere
tar xzf build/debork-portable.tar.gz
cd debork-portable
sudo ./install.sh
```

### Manual Installation
```bash
# Copy binary
sudo cp build/debork /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/debork
```

## Usage

### Basic Usage
```bash
# Run the tool (requires root)
sudo debork

# Enable debug output
sudo debork --debug

# Show help
debork --help
```

### Interactive Menu

When you run debork, you'll see an interactive menu:

```
╔══════════════════════════════════════════════════════════════╗
║                    debork Boot Rescue Tool                  ║
║              Cross-Platform Linux System Fixer              ║
╚══════════════════════════════════════════════════════════════╝

Select an option:

→ Fix My System (Complete Repair)
  Emergency Shell (Manual Fixes)
  Regenerate Initramfs Only
  Fix Boot Configuration Only
  Show System Information
  Exit

Use ↑/↓ to navigate, Enter to select, 'q' to quit
```

### Navigation
- **↑/↓ or j/k** - Navigate menu
- **Enter** - Select option
- **q** - Quit
- **ESC** - Cancel/Back

### Repair Options

#### 1. Fix My System (Complete Repair)
Automatic comprehensive repair that:
- Updates package database
- Fixes broken packages
- Regenerates initramfs
- Repairs bootloader configuration

#### 2. Emergency Shell
Drops into a chroot shell for manual repairs:
- Full access to broken system
- Network connectivity for package downloads
- Run custom repair commands

#### 3. Regenerate Initramfs Only
Rebuilds initial RAM filesystem:
- Detects mkinitcpio, dracut, or update-initramfs
- Automatically uses correct tool for your distro

#### 4. Fix Boot Configuration Only
Repairs bootloader without other changes:
- Updates GRUB configuration
- Reinstalls rEFInd
- Updates systemd-boot

#### 5. Show System Information
Displays detected configuration:
- Partition details
- Installed kernels
- Bootloader type
- Mount points

## Technical Details

### Clay UI System

The C version uses Clay for immediate mode GUI rendering in the terminal:

```c
// UI rendering with Clay
CLAY(CLAY_ID("MainContainer"),
     CLAY_LAYOUT({
         .sizing = CLAY_SIZING_GROW(),
         .padding = CLAY_PADDING_ALL(10)
     }),
     CLAY_RECTANGLE({.color = (Clay_Color){0, 0, 0, 255}})) {
    // UI elements here
}
```

Clay provides:
- Responsive layouts
- Smooth rendering
- Minimal memory usage
- Zero dependencies

### Architecture

```
debork.c
├── TUI System (Clay-based)
│   ├── Menu rendering
│   ├── Input handling
│   └── Status display
├── System Detection
│   ├── Partition scanning
│   ├── Bootloader detection
│   └── Kernel enumeration
├── Repair Functions
│   ├── Mount/unmount
│   ├── Chroot operations
│   └── Package management
└── Bootloader Support
    ├── GRUB
    ├── rEFInd
    └── systemd-boot
```

### Memory Usage

- **Static binary**: ~500KB
- **Runtime memory**: <10MB
- **Clay UI buffer**: 1MB
- **Total footprint**: Minimal

## Comparison with D Version

| Feature | C Version | D Version |
|---------|-----------|-----------|
| Binary size | ~500KB | ~2MB+ |
| Dependencies | None | D runtime |
| UI Framework | Clay | Native D |
| Portability | Excellent | Good |
| Build time | Fast | Moderate |
| Memory usage | Minimal | Higher |
| Cross-platform | Yes (with Cosmo) | Linux only |

## Troubleshooting

### Build Issues

**Problem**: Cosmopolitan build fails
```bash
# Use standard build instead
make standard
```

**Problem**: Missing headers
```bash
# Install development packages
sudo apt install build-essential  # Debian/Ubuntu
sudo dnf install gcc make         # Fedora
sudo pacman -S base-devel         # Arch
```

### Runtime Issues

**Problem**: Permission denied
```bash
# Must run as root
sudo debork
```

**Problem**: Mount fails
```bash
# Check device exists
ls -la /dev/nvme*  # NVMe drives
ls -la /dev/sd*    # SATA drives

# Verify filesystem
sudo fdisk -l
```

**Problem**: Chroot fails
```bash
# System may be too damaged
# Use emergency shell and manually install base packages
```

## Development

### Project Structure
```
debork/
├── debork.c          # Main C implementation
├── clay.h            # Clay UI library (header-only)
├── Makefile.c        # C version Makefile
├── build_cosmo.sh    # Cosmopolitan build script
└── README_C.md       # This file
```

### Building for Development
```bash
# Debug build with symbols
make debug

# Run with GDB
gdb build/debork-debug

# Check for issues
make check

# Format code
make format
```

### Contributing

1. Keep it simple and portable
2. Maintain static linking
3. Test in rescue environments
4. Document any platform-specific code

## License

MIT License - Same as original debork

## Credits

- **Clay** - Immediate mode GUI by Niclas Olofsson
- **Cosmopolitan** - Portable C library by Justine Tunney
- **Original debork** - D version authors

## Support

For issues specific to the C version:
- Check build logs in `build/`
- Enable debug mode: `sudo debork --debug`
- Review `/tmp/debork.log`

For general debork support:
- See main project documentation
- Report issues on GitHub