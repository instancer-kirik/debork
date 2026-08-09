# debork - Cross-Platform Linux Boot Rescue Tool

A comprehensive TUI-based system for fixing broken Linux installations from rescue environments.

## Features

- **Multi-bootloader Support**: GRUB, rEFInd, and systemd-boot
- **Interactive TUI Interface**: Perfect for rescue scenarios without GUI
- **Automatic Detection**: Identifies bootloader type and system configuration
- **Cross-platform**: Works on any Linux distribution
- **Kernel Management**: Scan, select, and configure kernels/initramfs
- **Emergency Shell**: Chroot into broken system for manual fixes
- **Portable**: Single binary that can be sideloaded onto rescue media

## Quick Start

### For Your Current Broken System (CachyOS rEFInd Issue)

1. Boot from a rescue USB/CD with D compiler support
2. Compile debork:
   ```bash
   make
   ```
3. Run as root:
   ```bash
   sudo ./debork
   ```
4. Enter your root partition (e.g., `/dev/sda2`)
5. Select "Fix Boot Configuration" from the menu
6. Choose your kernel and let debork fix the rEFInd config

## Installation

### From Source
```bash
# Install D compiler (dmd, ldc2, or gdc)
# On Arch/CachyOS:
sudo pacman -S dmd

# Build and install
make
sudo make install
```

### Portable Rescue Binary
```bash
make static
# Copy debork-static to your rescue media
```

### Portable Package
```bash
make package
# Creates package/debork-portable.tar.gz
```

## Usage

### Basic Operation
1. Boot from rescue media or working Linux system
2. Run `sudo debork`
3. Enter the device path of your broken system's root partition
4. Navigate the TUI menu to perform repairs

### Menu Options

- **Show System Information**: Display detected configuration
- **Fix Boot Configuration**: Auto-repair bootloader configs
- **Regenerate Initramfs**: Rebuild initramfs files
- **Manual Kernel Selection**: Choose specific kernel for rEFInd
- **Emergency Shell**: Chroot into system for manual fixes
- **Unmount and Exit**: Safely unmount and quit

### Supported Scenarios

#### rEFInd Missing Kernel (Your Current Issue)
- Detects available kernels automatically
- Rebuilds `refind_linux.conf` with correct paths
- Handles missing initramfs files

#### GRUB Issues
- Regenerates GRUB configuration
- Reinstalls GRUB to boot device
- Fixes UUID mismatches

#### systemd-boot Problems
- Recreates loader entries
- Fixes boot timeout and default settings
- Updates kernel paths

#### Missing Initramfs
- Regenerates all initramfs files
- Updates bootloader configs accordingly
- Handles multiple kernel versions

## Technical Details

### Requirements
- D compiler (dmd, ldc2, or gdc)
- Root privileges
- Linux system with standard utilities (mount, chroot, etc.)

### Supported Distributions
- Arch Linux and derivatives (CachyOS, Manjaro, etc.)
- Debian/Ubuntu family
- Red Hat/Fedora family
- SUSE family
- Any Linux with standard boot structure

### Bootloader Support

#### GRUB (GRUB2)
- Auto-detects GRUB installation
- Runs `grub-mkconfig` in chroot
- Optional GRUB reinstallation

#### rEFInd
- Scans for rEFInd installation
- Rebuilds `refind_linux.conf`
- Interactive kernel selection
- UUID-based root identification

#### systemd-boot
- Creates/updates loader.conf
- Generates boot entries for all kernels
- Proper initramfs handling

### File Locations
- Mount point: `/mnt/debork`
- Log file: `/tmp/debork.log`
- Backup configs: `/tmp/debork-backup-*`

## Troubleshooting

### Common Issues

#### "Permission denied"
- Ensure you're running as root: `sudo debork`

#### "Device not found"
- Check device path with `lsblk` or `fdisk -l`
- Use full device path (e.g., `/dev/sda2`, not `sda2`)

#### "No kernels found"
- Check if `/boot` is mounted separately
- Verify kernel files exist in `/boot`
- Try regenerating initramfs

#### "Unknown bootloader"
- Manually identify your bootloader
- Check for GRUB in `/boot/grub`
- Check for rEFInd in `/boot/efi/EFI/refind`

#### "chroot: failed to run command '/bin/bash': No such file or directory"
This error occurs when the essential shell programs are missing from your system:

**Immediate Solution:**
1. Use the "Diagnose Chroot Issues" menu option to see what's missing
2. Try the "Emergency Shell" option (debork now auto-detects available shells)
3. If that fails, boot from live USB and manually install bash:
   ```bash
   # Mount your system partition
   sudo mount /dev/sdXY /mnt
   
   # Install bash and essential packages
   sudo arch-chroot /mnt pacman -S bash coreutils
   ```

**Root Causes:**
- Incomplete system installation
- Corrupted package database
- Wrong partition mounted (not your Linux root)
- System packages accidentally removed

**Prevention:**
- Always verify you're mounting the correct root partition
- Use `lsblk` to identify your system partition before running debork

### Debug Mode
```bash
sudo debork --debug
```
Enables verbose logging and additional error information.

### Emergency Recovery
If debork fails, use the Emergency Shell option to:
1. Manually inspect the system
2. Run distribution-specific repair tools
3. Fix issues debork couldn't handle

## Building

### Standard Build
```bash
make              # Release build
make debug        # Debug build with symbols
make static       # Static binary for rescue
```

### Cross-Compiler Testing
```bash
make test-ldc     # Test with LDC compiler
make test-gdc     # Test with GDC compiler
```

### Development
```bash
make clean        # Clean build artifacts
make help         # Show all targets
```

## Contributing

debork is designed to be extensible. To add support for new bootloaders:

1. Add enum value to `BootLoader`
2. Implement detection in `detectBootLoader()`
3. Add fix method (e.g., `fixNewBootloader()`)
4. Update main menu switch statement

### Code Structure
- `deborkTUI`: Main TUI class
- `SystemInfo`: System configuration data
- `KernelInfo`: Kernel/initramfs information
- Bootloader-specific fix methods

## License

MIT License - See LICENSE file for details

## Security

debork requires root privileges to:
- Mount filesystems
- Access boot directories
- Modify bootloader configurations
- Run chroot commands

Always verify the source before running as root.

## FAQ

**Q: Will this fix my CachyOS rEFInd issue?**
A: Yes, debork specifically handles the "vmlinuz-linux-archvios not found" error by detecting available kernels and rebuilding the rEFInd configuration.

**Q: Can I use this on other distributions?**
A: Yes, debork is designed to work with any Linux distribution using supported bootloaders.

**Q: What if my bootloader isn't supported?**
A: Use the Emergency Shell feature to manually fix the issue, or submit a feature request.

**Q: Is it safe to use on a production system?**
A: debork creates backups before making changes, but always backup important data first.

**Q: Can I run this from a rescue USB?**
A: Yes, compile a static binary with `make static` and copy it to your rescue media.

## Support

For issues, feature requests, or questions:
- Check the troubleshooting section
- Use debug mode for more information
- Create an issue with detailed system information

---

**debork** - Because every Linux system deserves a second chance.
