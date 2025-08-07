# debork - Linux Boot Rescue Tool

A comprehensive D-language TUI-based system for fixing broken Linux installations from rescue environments.

## Features

- **Automatic Partition Detection**: Scans and identifies Linux partitions automatically
- **Robust Btrfs Support**: Advanced subvolume detection and mounting, especially for Arch/CachyOS systems
- **Multi-Bootloader Support**: Works with GRUB, rEFInd, and systemd-boot
- **Package Manager Integration**: Supports pacman, apt, yum/dnf, and zypper
- **Emergency Shell**: Chroot environment with proper mount bindings
- **Filesystem Repair**: Built-in filesystem checking and repair tools
- **Network Configuration**: Automatic network setup for package updates

## Installation

### Prerequisites

- D compiler (DMD >= 2.090.0, LDC >= 1.20.0, or GDC >= 9.0.0)
- DUB (D package manager)
- Linux system with standard utilities (mount, chroot, blkid)

### Building from Source

```bash
git clone https://github.com/instancer-kirik/debork.git
cd debork
dub build --build=release
```

The binary will be created in the project root and `bin/` directory.

## Usage

Run debork as root from a live USB or rescue environment:

```bash
sudo ./debork
```

### Command Line Options

- `--help`, `-h`: Show help message
- `--debug`, `-d`: Enable debug mode with verbose logging
- `--verbose`, `-v`: Enable verbose output
- `--version`: Show version information

### Interactive Menu

1. **Select Partition**: Choose the partition to repair or enter a custom device path
2. **Repair Options**:
   - Update System Packages
   - Regenerate Initramfs
   - Fix Bootloader
   - Emergency Shell
   - Advanced Options

### Advanced Options

- Repair Filesystem
- Fix File Permissions
- Remount with Different Options
- View Mount Information
- Test Chroot Environment

## Supported Systems

### Filesystems
- ext4, ext3, ext2
- Btrfs (with subvolume support)
- XFS
- F2FS
- ReiserFS

### Linux Distributions
- Arch Linux / CachyOS
- Debian / Ubuntu
- Fedora
- Red Hat / CentOS
- openSUSE

## Architecture

The project follows a modular design:

```
debork/
├── src/
│   ├── main.d              # Application entry point
│   ├── core/
│   │   ├── types.d         # Core data structures
│   │   └── logger.d        # Logging system
│   ├── filesystem/
│   │   ├── mount.d         # Mount operations
│   │   └── btrfs.d         # Btrfs-specific handling
│   ├── system/
│   │   ├── chroot.d        # Chroot management
│   │   └── detection.d     # System detection
│   ├── ui/
│   │   └── tui.d           # Terminal UI
│   └── repair/
│       └── operations.d    # Repair operations
└── dub.json                # Build configuration
```

## Btrfs Subvolume Detection

debork includes sophisticated Btrfs subvolume detection with multiple strategies:

1. **Automatic Detection**: Scans for common subvolume patterns (@, root, rootfs)
2. **Fallback Patterns**: Tries multiple naming conventions
3. **Additional Subvolumes**: Automatically mounts @home, @var, etc. when present

## Safety Features

- **Non-destructive**: All operations are designed to be safe
- **Validation**: Verifies Linux system presence before operations
- **Rollback**: Proper cleanup on failures
- **Logging**: Comprehensive logging to `/tmp/debork.log`

## Troubleshooting

### Common Issues

1. **"Must be run as root"**: Always run with sudo
2. **"No partitions detected"**: Manually enter device path
3. **Btrfs subvolume not found**: Tool will try multiple patterns automatically

### Debug Mode

Run with `--debug` for detailed logging:

```bash
sudo ./debork --debug
```

Check the log file for details:
```bash
cat /tmp/debork.log
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Setup

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Building for Development

```bash
dub build --build=debug
dub test  # Run unit tests
```

## License

MIT License - see LICENSE file for details

## Author

Created by instancer-kirik

## Acknowledgments

- Inspired by various system rescue tools
- Built with the D programming language
- Special focus on Arch/CachyOS btrfs configurations

## Version History

- **2.0.0** - Complete rewrite in D with modular architecture
- Focus on robust btrfs subvolume handling
- Improved error handling and recovery

## Support

For issues, questions, or suggestions, please open an issue on [GitHub](https://github.com/instancer-kirik/debork/issues).