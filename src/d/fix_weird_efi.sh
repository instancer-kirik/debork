#!/bin/bash

# Fix for weird dual-EFI partition setup with CachyOS
# This handles the unusual case where:
# - /boot is on nvme0n1p1 (FAT32 EFI partition)
# - /boot/efi is on nvme0n1p7 (another EFI partition)
# - Kernel is on p1, rEFInd is on p7

set -e

echo "========================================="
echo "  Weird Dual-EFI CachyOS Boot Fixer"
echo "========================================="
echo ""
echo "This script fixes the unusual setup where:"
echo "  • /boot is on EFI partition 1 (FAT32)"
echo "  • /boot/efi is on EFI partition 7 (FAT16)"
echo "  • Kernel is on p1, rEFInd is on p7"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

# Detect the root partition and filesystem
echo "Detecting root filesystem..."
ROOT_DEVICE=$(mount | grep "on / " | awk '{print $1}')
ROOT_UUID=$(blkid -s UUID -o value $ROOT_DEVICE)
ROOT_FS=$(blkid -s TYPE -o value $ROOT_DEVICE)

echo "  Root device: $ROOT_DEVICE"
echo "  Root UUID: $ROOT_UUID"
echo "  Root filesystem: $ROOT_FS"

# Check if btrfs and get subvolume
ROOTFLAGS=""
if [ "$ROOT_FS" = "btrfs" ]; then
    SUBVOL=$(mount | grep "on / " | grep -oP 'subvol=\K[^,)]*' || echo "@")
    ROOTFLAGS="rootflags=subvol=$SUBVOL"
    echo "  Btrfs subvolume: $SUBVOL"
fi

# Mount the partitions if needed
echo ""
echo "Checking mount points..."

if ! mountpoint -q /mnt/boot 2>/dev/null; then
    mkdir -p /mnt/boot
    mount /dev/nvme0n1p1 /mnt/boot
    echo "  Mounted nvme0n1p1 at /mnt/boot"
else
    echo "  /mnt/boot already mounted"
fi

if ! mountpoint -q /mnt/boot/efi 2>/dev/null; then
    mkdir -p /mnt/boot/efi
    mount /dev/nvme0n1p7 /mnt/boot/efi
    echo "  Mounted nvme0n1p7 at /mnt/boot/efi"
else
    echo "  /mnt/boot/efi already mounted"
fi

# Check what we have
echo ""
echo "Checking boot files..."
if [ -f /mnt/boot/vmlinuz-linux-cachyos ]; then
    echo "  ✓ Found kernel: vmlinuz-linux-cachyos"
else
    echo "  ✗ Kernel not found!"
    exit 1
fi

if [ -f /mnt/boot/initramfs-linux-cachyos.img ]; then
    echo "  ✓ Found initramfs: initramfs-linux-cachyos.img"
else
    echo "  ✗ Initramfs not found!"
    exit 1
fi

# Clean up misplaced files
echo ""
echo "Cleaning up misplaced files..."

# Remove kernels from wrong locations in EFI
for dir in /mnt/boot/efi/EFI/CachyOS /mnt/boot/efi/EFI/Linux /mnt/boot/efi/EFI/cachyos; do
    if [ -d "$dir" ]; then
        echo "  Cleaning $dir..."
        rm -f "$dir"/vmlinuz* 2>/dev/null || true
        rm -f "$dir"/initramfs* 2>/dev/null || true
        # Remove directory if empty
        rmdir "$dir" 2>/dev/null || true
    fi
done

# Fix refind_linux.conf
echo ""
echo "Creating refind_linux.conf..."
cat > /mnt/boot/refind_linux.conf << EOF
"Boot with standard options" "root=UUID=$ROOT_UUID $ROOTFLAGS rw quiet splash"
"Boot to single-user mode" "root=UUID=$ROOT_UUID $ROOTFLAGS rw single"
"Boot with minimal options" "root=UUID=$ROOT_UUID $ROOTFLAGS ro"
EOF

echo "  Created with root=UUID=$ROOT_UUID $ROOTFLAGS"

# Check if rEFInd exists
REFIND_DIR="/mnt/boot/efi/EFI/refind"
if [ ! -d "$REFIND_DIR" ]; then
    echo ""
    echo "rEFInd not found at $REFIND_DIR"
    echo "Installing rEFInd..."

    # Try to install from the running system
    if command -v refind-install &> /dev/null; then
        refind-install --root /mnt
    else
        echo "  refind-install not found. Please install refind package."
        exit 1
    fi
fi

# Create/update refind.conf
echo ""
echo "Updating rEFInd configuration..."

REFIND_CONF="$REFIND_DIR/refind.conf"

# Backup existing config
if [ -f "$REFIND_CONF" ]; then
    cp "$REFIND_CONF" "$REFIND_CONF.bak"
    echo "  Backed up existing refind.conf"
fi

# Check if our manual entry already exists
if grep -q "CachyOS Linux (Fixed)" "$REFIND_CONF" 2>/dev/null; then
    echo "  Manual entry already exists"
else
    # Add manual entry for CachyOS
    cat >> "$REFIND_CONF" << EOF

# Manual CachyOS entry - fixed for dual-EFI setup
menuentry "CachyOS Linux (Fixed)" {
    icon     /EFI/refind/icons/os_arch.png
    volume   "SYSTEM_DRV"
    loader   /vmlinuz-linux-cachyos
    initrd   /initramfs-linux-cachyos.img
    options  "root=UUID=$ROOT_UUID $ROOTFLAGS rw quiet splash"
    submenuentry "Boot to single-user mode" {
        options "root=UUID=$ROOT_UUID $ROOTFLAGS rw single"
    }
    submenuentry "Boot with minimal options" {
        options "root=UUID=$ROOT_UUID $ROOTFLAGS ro"
    }
}
EOF
    echo "  Added manual CachyOS entry"
fi

# Add scan and hide options if not present
if ! grep -q "also_scan_dirs" "$REFIND_CONF" 2>/dev/null; then
    echo "" >> "$REFIND_CONF"
    echo "# Scan the first EFI partition for kernels" >> "$REFIND_CONF"
    echo "also_scan_dirs +,@/" >> "$REFIND_CONF"
    echo "  Added scan directories"
fi

if ! grep -q "dont_scan_volumes" "$REFIND_CONF" 2>/dev/null; then
    echo "" >> "$REFIND_CONF"
    echo "# Hide auto-detected entries from SYSTEM_DRV to avoid duplicates" >> "$REFIND_CONF"
    echo 'dont_scan_volumes "SYSTEM_DRV"' >> "$REFIND_CONF"
    echo "  Added volume exclusions"
fi

if ! grep -q "dont_scan_dirs" "$REFIND_CONF" 2>/dev/null; then
    echo "" >> "$REFIND_CONF"
    echo "# Hide OpenSUSE duplicates" >> "$REFIND_CONF"
    echo "dont_scan_dirs /EFI/opensuse,/EFI/Microsoft/Boot" >> "$REFIND_CONF"
    echo "  Added directory exclusions"
fi

# Ensure rEFInd is in boot order
echo ""
echo "Checking EFI boot order..."
if command -v efibootmgr &> /dev/null; then
    if efibootmgr | grep -q "rEFInd"; then
        echo "  ✓ rEFInd is in boot order"
    else
        echo "  Adding rEFInd to boot order..."
        efibootmgr --create --disk /dev/nvme0n1 --part 7 --label "rEFInd" --loader '\EFI\refind\refind_x64.efi' 2>/dev/null || true
    fi
else
    echo "  efibootmgr not available (normal in chroot)"
fi

echo ""
echo "========================================="
echo "  Fix Complete!"
echo "========================================="
echo ""
echo "Summary:"
echo "  • Cleaned up misplaced kernel files"
echo "  • Created proper refind_linux.conf"
echo "  • Added manual CachyOS entry to rEFInd"
echo "  • Configured rEFInd to hide duplicates"
echo ""
echo "You should now see 'CachyOS Linux (Fixed)' in rEFInd menu"
echo "This entry should boot correctly."
echo ""
echo "If you still see duplicate entries, they're harmless."
echo "Just use the 'CachyOS Linux (Fixed)' entry."
