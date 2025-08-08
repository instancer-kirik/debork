module debork.repair.operations;

import std.process;
import std.file;
import std.path;
import std.string;
import std.algorithm;
import std.conv;
import std.format;
import std.regex;
import std.array : join;
import debork.core.types;
import debork.core.logger;
import debork.system.chroot;
import debork.ui.tui;

class RepairOperations {
    private TUI ui;

    this(TUI ui) {
        this.ui = ui;
    }

    /**
     * Complete system repair workflow
     */
    RepairResult performCompleteRepair(ref SystemInfo sysInfo, RepairConfig config = RepairConfig()) {
        RepairResult result;

        Logger.info("Starting complete system repair");
        ui.printInfo("Starting complete system repair...");

        // Validate environment first
        if (!ChrootManager.validateChrootEnvironment(sysInfo)) {
            result.success = false;
            result.errors ~= "Chroot environment validation failed";
            return result;
        }

        // Step 1: Update packages
        if (config.updatePackages) {
            ui.printInfo("Step 1/3: Updating packages...");
            if (updatePackages(sysInfo)) {
                result.completedSteps ~= "Package update";
                ui.printStatus("✓ Packages updated successfully");
            } else {
                result.errors ~= "Package update failed";
                result.warnings ~= "Some packages may be out of date";
            }
        }

        // Step 2: Regenerate initramfs
        if (config.regenerateInitramfs) {
            ui.printInfo("Step 2/3: Regenerating initramfs...");
            if (regenerateInitramfs(sysInfo)) {
                result.completedSteps ~= "Initramfs regeneration";
                ui.printStatus("✓ Initramfs regenerated successfully");
            } else {
                result.errors ~= "Initramfs regeneration failed";
            }
        }

        // Step 3: Fix bootloader
        if (config.fixBootloader) {
            ui.printInfo("Step 3/3: Fixing bootloader...");
            if (fixBootloader(sysInfo)) {
                result.completedSteps ~= "Bootloader repair";
                ui.printStatus("✓ Bootloader fixed successfully");
            } else {
                result.errors ~= "Bootloader repair failed";
                result.warnings ~= "Manual bootloader configuration may be needed";
            }
        }

        // Determine overall success
        result.success = (result.errors.length == 0);

        if (result.success) {
            Logger.info("Complete system repair succeeded");
            ui.printStatus("System repair completed successfully!");
        } else {
            Logger.error("Complete system repair had failures");
            ui.printStatus("System repair completed with issues", true);
        }

        return result;
    }

    /**
     * Update system packages
     */
    bool updatePackages(ref SystemInfo sysInfo) {
        Logger.info("Updating system packages");

        if (!sysInfo.isValidated) {
            Logger.error("System not validated for package updates");
            return false;
        }

        try {
            bool success = false;

            // Method 1: Try with shell wrapper
            try {
                string command = getUpdateCommand(sysInfo.packageManager);
                auto process = ChrootManager.executeChrootCommand(sysInfo, command);
                auto exitCode = wait(process);

                if (exitCode == 0) {
                    Logger.info("Package update succeeded with shell method");
                    success = true;
                } else {
                    Logger.warning("Shell-based package update failed, trying direct method");
                }
            } catch (Exception e) {
                Logger.warning("Shell method failed: " ~ e.msg);
            }

            // Method 2: Direct execution fallback
            if (!success) {
                try {
                    string[] command = getDirectUpdateCommand(sysInfo.packageManager);
                    auto process = ChrootManager.executeChrootDirect(sysInfo, command);
                    auto exitCode = wait(process);

                    if (exitCode == 0) {
                        Logger.info("Package update succeeded with direct method");
                        success = true;
                    } else {
                        Logger.error("Direct package update also failed");
                    }
                } catch (Exception e) {
                    Logger.error("Direct method failed: " ~ e.msg);
                }
            }

            if (!success) {
                ui.printError("Package update failed");
                ui.printInfo("Possible causes:");
                ui.printInfo("• Network connectivity issues");
                ui.printInfo("• Corrupted package database");
                ui.printInfo("• Insufficient disk space");
                ui.printInfo("• Repository configuration problems");
            }

            return success;

        } catch (Exception e) {
            Logger.error("Exception during package update: " ~ e.msg);
            return false;
        }
    }

    /**
     * Regenerate initramfs for all kernels
     */
    bool regenerateInitramfs(ref SystemInfo sysInfo) {
        Logger.info("Regenerating initramfs");

        if (!sysInfo.isValidated) {
            Logger.error("System not validated for initramfs regeneration");
            return false;
        }

        try {
            // First, ensure mkinitcpio configuration is correct
            if (sysInfo.packageManager == PackageManager.PACMAN) {
                ensureMkinitcpioConfig(sysInfo);
                // Also verify UUID is properly detected
                verifyAndFixDeviceDetection(sysInfo);
                // Verify initramfs will be generated with correct modules
                verifyInitramfsModules(sysInfo);
                // Run comprehensive boot diagnostics
                runBootDiagnostics(sysInfo);
            }

            string[][] commands = getInitramfsCommands(sysInfo.packageManager);
            bool anySuccess = false;

            foreach (command; commands) {
                try {
                    auto process = ChrootManager.executeChrootDirect(sysInfo, command);
                    auto exitCode = wait(process);

                    if (exitCode == 0) {
                        Logger.info("Initramfs regeneration succeeded with: " ~ command.join(" "));
                        anySuccess = true;
                    } else {
                        Logger.warning("Initramfs command failed: " ~ command.join(" "));
                    }
                } catch (Exception e) {
                    Logger.warning("Exception with initramfs command: " ~ e.msg);
                }
            }

            if (!anySuccess) {
                ui.printError("Initramfs regeneration failed");
                ui.printInfo("Try manually running:");
                foreach (command; commands) {
                    ui.printInfo("• " ~ command.join(" "));
                }
            }

            return anySuccess;

        } catch (Exception e) {
            Logger.error("Exception during initramfs regeneration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Ensure mkinitcpio.conf has proper hooks for filesystem detection
     */
    private void ensureMkinitcpioConfig(ref SystemInfo sysInfo) {
        import std.file : readText, write;
        import std.string : indexOf, replace;

        string configPath = buildPath(sysInfo.mountPoint, "etc", "mkinitcpio.conf");

        if (!exists(configPath)) {
            Logger.warning("mkinitcpio.conf not found at: " ~ configPath);
            return;
        }

        try {
            string content = readText(configPath);
            string originalContent = content;
            bool modified = false;

            // Find the HOOKS line
            auto hooksIdx = content.indexOf("HOOKS=(");
            if (hooksIdx != -1) {
                auto hooksEnd = content.indexOf(")", hooksIdx);
                if (hooksEnd != -1) {
                    string hooksLine = content[hooksIdx .. hooksEnd + 1];
                    string newHooksLine = hooksLine;

                    // Essential hooks that must be present for device detection
                    string[] requiredHooks = ["base", "udev", "autodetect", "modconf", "block", "filesystems", "fsck"];

                    // Check if btrfs filesystem needs btrfs hook
                    if (sysInfo.isBtrfs && hooksLine.indexOf("btrfs") == -1) {
                        // Add btrfs hook before filesystems
                        newHooksLine = newHooksLine.replace("filesystems", "btrfs filesystems");
                        Logger.info("Adding btrfs hook to mkinitcpio.conf");
                        modified = true;
                    }

                    // Ensure fsck is at the end if not present
                    if (hooksLine.indexOf("fsck") == -1) {
                        newHooksLine = newHooksLine.replace(")", " fsck)");
                        Logger.info("Adding fsck hook to mkinitcpio.conf");
                        modified = true;
                    }

                    // Ensure block hook is present (critical for device detection)
                    if (hooksLine.indexOf("block") == -1) {
                        // Add block hook after modconf
                        if (hooksLine.indexOf("modconf") != -1) {
                            newHooksLine = newHooksLine.replace("modconf", "modconf block");
                        } else {
                            // Add it before filesystems
                            newHooksLine = newHooksLine.replace("filesystems", "block filesystems");
                        }
                        Logger.info("Adding block hook to mkinitcpio.conf");
                        modified = true;
                    }

                    // Check for keyboard hook if using encryption
                    if (hooksLine.indexOf("encrypt") != -1 && hooksLine.indexOf("keyboard") == -1) {
                        // Add keyboard before encrypt
                        newHooksLine = newHooksLine.replace("encrypt", "keyboard encrypt");
                        Logger.info("Adding keyboard hook before encrypt in mkinitcpio.conf");
                        modified = true;
                    }

                    if (modified) {
                        content = content.replace(hooksLine, newHooksLine);
                        Logger.info("Updated HOOKS line: " ~ newHooksLine);
                    }
                }
            }

            // Check MODULES line for necessary modules
            auto modulesIdx = content.indexOf("MODULES=(");
            if (modulesIdx != -1) {
                auto modulesEnd = content.indexOf(")", modulesIdx);
                if (modulesEnd != -1) {
                    string modulesLine = content[modulesIdx .. modulesEnd + 1];
                    string newModulesLine = modulesLine;

                    // Get required modules for early loading
                    string[] requiredModules;

                    // Add btrfs module if using btrfs
                    if (sysInfo.isBtrfs) {
                        requiredModules ~= "btrfs";
                        requiredModules ~= "crc32c";  // Required by btrfs
                    }

                    // Add storage controller modules for early loading
                    string[] storageModules = detectStorageModules();
                    requiredModules ~= storageModules;

                    // Add each required module if not present
                    foreach (mod; requiredModules) {
                        if (mod.length > 0 && modulesLine.indexOf(mod) == -1) {
                            if (newModulesLine == "MODULES=()") {
                                newModulesLine = "MODULES=(" ~ mod ~ ")";
                            } else {
                                newModulesLine = newModulesLine.replace(")", " " ~ mod ~ ")");
                            }
                            Logger.info("Adding module to mkinitcpio.conf: " ~ mod);
                            modified = true;
                        }
                    }

                    if (newModulesLine != modulesLine) {
                        content = content.replace(modulesLine, newModulesLine);
                        Logger.info("Updated MODULES line: " ~ newModulesLine);
                    }
                }
            }

            // Write back if modified
            if (modified) {
                // Backup original
                string backupPath = configPath ~ ".bak";
                write(backupPath, originalContent);
                Logger.info("Backed up original mkinitcpio.conf to: " ~ backupPath);

                // Write new content
                write(configPath, content);
                Logger.info("Updated mkinitcpio.conf with proper hooks and modules");
                ui.printInfo("Fixed mkinitcpio.conf configuration");
            }

        } catch (Exception e) {
            Logger.error("Failed to update mkinitcpio.conf: " ~ e.msg);
        }
    }

    /**
     * Verify and fix device detection issues
     */
    private void verifyAndFixDeviceDetection(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        // If UUID is empty, try to detect it
        if (sysInfo.uuid.length == 0) {
            Logger.warning("UUID not detected, attempting to find it");

            try {
                // Try blkid first
                auto result = executeShell("blkid -s UUID -o value " ~ sysInfo.device);
                if (result.status == 0 && result.output.strip().length > 0) {
                    sysInfo.uuid = result.output.strip();
                    Logger.info("Detected UUID: " ~ sysInfo.uuid);
                    ui.printInfo("Found filesystem UUID: " ~ sysInfo.uuid);
                } else {
                    // Try lsblk as fallback
                    result = executeShell("lsblk -no UUID " ~ sysInfo.device ~ " | head -n1");
                    if (result.status == 0 && result.output.strip().length > 0) {
                        sysInfo.uuid = result.output.strip();
                        Logger.info("Detected UUID via lsblk: " ~ sysInfo.uuid);
                    } else {
                        // Try blkid with full output parsing
                        result = executeShell("blkid " ~ sysInfo.device);
                        if (result.status == 0) {
                            auto output = result.output;
                            auto uuidStart = output.indexOf("UUID=\"");
                            if (uuidStart != -1) {
                                uuidStart += 6;
                                auto uuidEnd = output.indexOf("\"", uuidStart);
                                if (uuidEnd != -1) {
                                    sysInfo.uuid = output[uuidStart .. uuidEnd];
                                    Logger.info("Detected UUID from blkid output: " ~ sysInfo.uuid);
                                    ui.printInfo("Found filesystem UUID: " ~ sysInfo.uuid);
                                }
                            }
                        }
                    }
                }

                // If still no UUID, try to get PARTUUID as last resort
                if (sysInfo.uuid.length == 0) {
                    result = executeShell("blkid -s PARTUUID -o value " ~ sysInfo.device);
                    if (result.status == 0 && result.output.strip().length > 0) {
                        // Store PARTUUID but note it's different
                        sysInfo.uuid = result.output.strip();
                        Logger.warning("Using PARTUUID instead of UUID: " ~ sysInfo.uuid);
                        ui.printWarning("Using PARTUUID (not filesystem UUID): " ~ sysInfo.uuid);
                    }
                }
            } catch (Exception e) {
                Logger.error("Failed to detect UUID: " ~ e.msg);
            }
        }

        // Verify the device actually exists
        if (!exists(sysInfo.device)) {
            Logger.error("Device does not exist: " ~ sysInfo.device);
            ui.printError("Warning: Device " ~ sysInfo.device ~ " not found!");

            // Try to find the device by UUID if we have it
            if (sysInfo.uuid.length > 0) {
                string byUuidPath = "/dev/disk/by-uuid/" ~ sysInfo.uuid;
                if (exists(byUuidPath)) {
                    // Resolve the symlink to get the actual device
                    try {
                        auto result = executeShell("readlink -f " ~ byUuidPath);
                        if (result.status == 0 && result.output.length > 0) {
                            string actualDevice = result.output.strip();
                            Logger.info("Found device via UUID: " ~ actualDevice);
                            sysInfo.device = actualDevice;
                        }
                    } catch (Exception e) {
                        Logger.error("Failed to resolve device by UUID: " ~ e.msg);
                    }
                }
            }
        }
    }

    /**
     * Detect necessary storage controller modules
     */
    private string[] detectStorageModules() {
        import std.process : executeShell;
        import std.array : array;
        import std.algorithm : filter, uniq, sort;

        string[] modules;

        try {
            // Detect NVME controllers
            auto nvmeResult = executeShell("lspci -k | grep -A2 'Non-Volatile memory controller' | grep 'Kernel driver' | awk '{print $NF}'");
            if (nvmeResult.status == 0 && nvmeResult.output.length > 0) {
                auto nvmeModules = nvmeResult.output.strip().split("\n");
                foreach (mod; nvmeModules) {
                    if (mod.length > 0 && mod != "nvme") {
                        modules ~= mod.strip();
                    }
                }
                // Always include nvme if NVME controller detected
                if (nvmeModules.length > 0) {
                    modules ~= "nvme";
                }
            }

            // Detect SATA/AHCI controllers
            auto sataResult = executeShell("lspci -k | grep -A2 'SATA\\|AHCI' | grep 'Kernel driver' | awk '{print $NF}'");
            if (sataResult.status == 0 && sataResult.output.length > 0) {
                auto sataModules = sataResult.output.strip().split("\n");
                foreach (mod; sataModules) {
                    if (mod.length > 0) {
                        modules ~= mod.strip();
                    }
                }
            }

            // Check for virtio devices (virtual machines)
            auto virtioResult = executeShell("lspci | grep -i virtio");
            if (virtioResult.status == 0 && virtioResult.output.length > 0) {
                modules ~= "virtio_blk";
                modules ~= "virtio_pci";
                modules ~= "virtio_scsi";
            }

            // Check for VMware
            auto vmwareResult = executeShell("lspci | grep -i vmware");
            if (vmwareResult.status == 0 && vmwareResult.output.length > 0) {
                modules ~= "vmw_pvscsi";
            }

            // Check for Hyper-V
            auto hypervResult = executeShell("lspci | grep -i 'microsoft\\|hyper-v'");
            if (hypervResult.status == 0 && hypervResult.output.length > 0) {
                modules ~= "hv_storvsc";
                modules ~= "hv_vmbus";
            }

            // Remove duplicates and sort
            modules = modules.sort().uniq().array;

            if (modules.length > 0) {
                Logger.info("Detected storage modules: " ~ modules.join(", "));
            }

        } catch (Exception e) {
            Logger.warning("Failed to detect storage modules: " ~ e.msg);
        }

        return modules;
    }

    /**
     * Verify initramfs will include necessary modules
     */
    private void verifyInitramfsModules(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        try {
            // Check if we can determine the root filesystem module requirements
            auto fsResult = executeShell("lsmod | grep -E 'btrfs|ext4|xfs'");
            if (fsResult.status == 0 && fsResult.output.length > 0) {
                Logger.info("Currently loaded filesystem modules: " ~ fsResult.output.strip());
            }

            // For btrfs, ensure dependencies are available
            if (sysInfo.isBtrfs) {
                // Check if btrfs module is available
                auto btrfsCheck = executeShell("modinfo btrfs 2>/dev/null | grep -q filename");
                if (btrfsCheck.status != 0) {
                    ui.printWarning("btrfs module not found - kernel may not have btrfs support!");
                    Logger.error("btrfs kernel module not available");
                }

                // Ensure critical btrfs dependencies
                string configPath = buildPath(sysInfo.mountPoint, "etc", "mkinitcpio.conf");
                if (exists(configPath)) {
                    auto checkHooks = executeShell("grep '^HOOKS=' " ~ configPath ~ " | grep -q btrfs");
                    if (checkHooks.status != 0) {
                        ui.printWarning("btrfs hook missing from mkinitcpio.conf - fixing...");
                        ensureMkinitcpioConfig(sysInfo);
                    }
                }
            }

            // Verify the kernel command line will be correct
            string refindConf = buildPath(sysInfo.mountPoint, "boot", "refind_linux.conf");
            if (exists(refindConf)) {
                import std.file : readText;
                string content = readText(refindConf);

                // Check if root= parameter exists
                if (content.indexOf("root=") == -1) {
                    Logger.error("refind_linux.conf missing root= parameter!");
                    ui.printError("Boot configuration missing root device - regenerating...");
                    generateRefindLinuxConf(sysInfo);
                } else if (content.indexOf("root=\"\"") != -1 || content.indexOf("root= ") != -1) {
                    Logger.error("refind_linux.conf has empty root= parameter!");
                    ui.printError("Boot configuration has empty root device - regenerating...");
                    generateRefindLinuxConf(sysInfo);
                } else {
                    Logger.info("refind_linux.conf appears to have valid root= parameter");
                }
            }

        } catch (Exception e) {
            Logger.warning("Could not verify initramfs modules: " ~ e.msg);
        }
    }

    /**
     * Run comprehensive boot diagnostics
     */
    private void runBootDiagnostics(ref SystemInfo sysInfo) {
        import std.process : executeShell;
        import std.file : readText;

        ui.printInfo("Running boot diagnostics...");
        Logger.info("=== Boot Diagnostics Start ===");

        // 1. Check device and UUID
        ui.printInfo("Device Information:");
        ui.printInfo("  Device: " ~ sysInfo.device);
        ui.printInfo("  UUID: " ~ (sysInfo.uuid.length > 0 ? sysInfo.uuid : "NOT DETECTED"));
        ui.printInfo("  Filesystem: " ~ sysInfo.fstype);

        // Show if btrfs subvolume is detected
        if (sysInfo.isBtrfs) {
            ui.printInfo("  Btrfs root subvolume: " ~ sysInfo.btrfsInfo.rootSubvolume);
        }

        if (sysInfo.uuid.length == 0) {
            ui.printError("CRITICAL: No UUID detected - boot will fail!");

            // Try to detect it one more time
            auto blkidResult = executeShell("blkid " ~ sysInfo.device);
            if (blkidResult.status == 0) {
                ui.printInfo("blkid output: " ~ blkidResult.output.strip());
            }

            // Also check if device exists
            if (!exists(sysInfo.device)) {
                ui.printError("CRITICAL: Device does not exist: " ~ sysInfo.device);
            }
        }

        // 2. Check refind_linux.conf
        string refindConfPath = buildPath(sysInfo.mountPoint, "boot", "refind_linux.conf");
        if (exists(refindConfPath)) {
            try {
                string content = readText(refindConfPath);
                ui.printInfo("refind_linux.conf content:");
                auto lines = content.split("\n");
                foreach (line; lines[0 .. min(3, lines.length)]) {
                    ui.printInfo("  " ~ line);
                }

                // Check for empty root parameter
                if (content.indexOf("root= ") != -1 || content.indexOf("root=\"\"") != -1) {
                    ui.printError("CRITICAL: Empty root parameter detected!");
                }
                if (content.indexOf("root=") == -1) {
                    ui.printError("CRITICAL: No root parameter found!");
                }
            } catch (Exception e) {
                ui.printError("Could not read refind_linux.conf: " ~ e.msg);
            }
        } else {
            ui.printError("refind_linux.conf not found at: " ~ refindConfPath);
        }

        // 3. Check mkinitcpio.conf
        string mkinitcpioPath = buildPath(sysInfo.mountPoint, "etc", "mkinitcpio.conf");
        if (exists(mkinitcpioPath)) {
            auto hooksResult = executeShell("grep '^HOOKS=' " ~ mkinitcpioPath);
            if (hooksResult.status == 0) {
                ui.printInfo("mkinitcpio HOOKS: " ~ hooksResult.output.strip());

                // Check for critical hooks
                if (hooksResult.output.indexOf("block") == -1) {
                    ui.printError("CRITICAL: 'block' hook missing!");
                }
                if (sysInfo.isBtrfs && hooksResult.output.indexOf("btrfs") == -1) {
                    ui.printError("CRITICAL: 'btrfs' hook missing for btrfs filesystem!");
                }
            }

            auto modulesResult = executeShell("grep '^MODULES=' " ~ mkinitcpioPath);
            if (modulesResult.status == 0) {
                ui.printInfo("mkinitcpio MODULES: " ~ modulesResult.output.strip());
            }
        }

        // 4. Check kernel and initramfs files
        ui.printInfo("Boot files:");
        foreach (kernel; sysInfo.kernels) {
            ui.printInfo("  Kernel: " ~ kernel.path ~ " [" ~ (kernel.exists ? "EXISTS" : "MISSING") ~ "]");
            ui.printInfo("  Initrd: " ~ kernel.initrd ~ " [" ~ (kernel.initrdExists ? "EXISTS" : "MISSING") ~ "]");
        }

        // 5. Check if running in EFI mode
        if (exists("/sys/firmware/efi")) {
            ui.printInfo("System is running in UEFI mode");
        } else {
            ui.printWarning("System is running in BIOS/Legacy mode or EFI not accessible");
        }

        Logger.info("=== Boot Diagnostics End ===");
    }

    /**
     * Mount efivars for EFI operations in chroot
     */
    private void mountEfiVars(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        string efivarsMountPoint = buildPath(sysInfo.mountPoint, "sys/firmware/efi/efivars");

        try {
            // Check if efivars directory exists
            if (!exists(efivarsMountPoint)) {
                Logger.info("efivars mount point does not exist, skipping");
                return;
            }

            // Check if already mounted
            auto checkResult = executeShell("mountpoint -q " ~ efivarsMountPoint);
            if (checkResult.status == 0) {
                Logger.info("efivars already mounted");
                return;
            }

            // Try to mount efivars
            auto mountResult = executeShell("mount -t efivarfs efivarfs " ~ efivarsMountPoint);
            if (mountResult.status == 0) {
                Logger.info("Successfully mounted efivars");
            } else {
                Logger.warning("Could not mount efivars (normal in some environments)");
            }
        } catch (Exception e) {
            Logger.warning("Exception mounting efivars: " ~ e.msg);
        }
    }

    /**
     * Ensure fallback boot entry exists for rEFInd
     */
    private void ensureFallbackBootEntry(ref SystemInfo sysInfo) {
        import std.file : copy, mkdirRecurse;

        try {
            string efiBootDir = buildPath(sysInfo.efiDir, "EFI/BOOT");
            string refindEfi = buildPath(sysInfo.efiDir, "EFI/refind/refind_x64.efi");
            string fallbackEfi = buildPath(efiBootDir, "bootx64.efi");

            // Check if rEFInd exists
            if (!exists(refindEfi)) {
                Logger.warning("rEFInd EFI binary not found at: " ~ refindEfi);
                return;
            }

            // Create BOOT directory if it doesn't exist
            if (!exists(efiBootDir)) {
                mkdirRecurse(efiBootDir);
                Logger.info("Created EFI/BOOT directory");
            }

            // Copy rEFInd as fallback boot loader if not already there
            if (!exists(fallbackEfi)) {
                copy(refindEfi, fallbackEfi);
                Logger.info("Created fallback boot entry at EFI/BOOT/bootx64.efi");
                ui.printInfo("Created fallback boot entry for rEFInd");
            } else {
                Logger.info("Fallback boot entry already exists");
            }

            // Also copy refind.conf if it exists
            string refindConf = buildPath(sysInfo.efiDir, "EFI/refind/refind.conf");
            string fallbackConf = buildPath(efiBootDir, "refind.conf");
            if (exists(refindConf) && !exists(fallbackConf)) {
                copy(refindConf, fallbackConf);
                Logger.info("Copied rEFInd configuration to fallback location");
            }

        } catch (Exception e) {
            Logger.warning("Could not create fallback boot entry: " ~ e.msg);
        }
    }

    /**
     * Fix bootloader configuration
     */
    bool fixBootloader(ref SystemInfo sysInfo) {
        Logger.info("Fixing bootloader: " ~ bootLoaderToString(sysInfo.bootLoader));

        final switch (sysInfo.bootLoader) {
            case BootLoader.GRUB:
                return fixGrub(sysInfo);
            case BootLoader.REFIND:
                return fixRefind(sysInfo);
            case BootLoader.SYSTEMD_BOOT:
                return fixSystemdBoot(sysInfo);
            case BootLoader.UNKNOWN:
                ui.printWarning("Unknown bootloader - attempting auto-detection");
                return attemptBootloaderAutofix(sysInfo);
        }
    }

    /**
     * Fix GRUB bootloader
     */
    private bool fixGrub(ref SystemInfo sysInfo) {
        Logger.info("Fixing GRUB bootloader");

        try {
            // Regenerate GRUB configuration
            auto process = ChrootManager.executeChrootDirect(sysInfo, ["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]);
            auto exitCode = wait(process);

            if (exitCode == 0) {
                ui.printStatus("✓ GRUB configuration regenerated");

                // Try to reinstall GRUB if we can detect boot device
                string bootDevice = detectBootDevice(sysInfo.device);
                if (bootDevice.length > 0) {
                    auto installProcess = ChrootManager.executeChrootDirect(sysInfo, ["grub-install", bootDevice]);
                    auto installCode = wait(installProcess);

                    if (installCode == 0) {
                        ui.printStatus("✓ GRUB reinstalled to " ~ bootDevice);
                        return true;
                    } else {
                        ui.printWarning("GRUB configuration updated but reinstallation failed");
                        return true; // Config update is still useful
                    }
                } else {
                    ui.printWarning("Could not detect boot device for GRUB installation");
                    return true; // Config update is still useful
                }
            } else {
                ui.printError("GRUB configuration regeneration failed");
                return false;
            }

        } catch (Exception e) {
            Logger.error("Exception fixing GRUB: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix rEFInd bootloader
     */
    private bool fixRefind(ref SystemInfo sysInfo) {
        Logger.info("Fixing rEFInd bootloader");

        try {
            bool success = false;

            // Check for dual-EFI setup (kernel on different partition than rEFInd)
            bool isDualEfiSetup = detectDualEfiSetup(sysInfo);
            if (isDualEfiSetup) {
                ui.printInfo("Detected dual-EFI partition setup");
                return fixDualEfiRefind(sysInfo);
            }

            // First, detect where rEFInd is actually installed
            string refindLocation = detectRefindInstallation(sysInfo);
            if (refindLocation.length == 0) {
                ui.printWarning("rEFInd not found, installing...");
                installRefindProperly(sysInfo);
                refindLocation = detectRefindInstallation(sysInfo);
            }

            // Clean up wrongly placed kernels in EFI partition
            ui.printInfo("Cleaning up misplaced files...");
            cleanupMisplacedKernels(sysInfo);

            // First, clean up duplicate and incorrect rEFInd entries
            ui.printInfo("Cleaning up rEFInd entries...");
            cleanupRefindEntries(sysInfo);

            // Always generate proper refind_linux.conf for btrfs systems
            ui.printInfo("Generating rEFInd configuration for btrfs system...");
            // Generate refind_linux.conf configuration
            success = generateRefindLinuxConf(sysInfo);

            // Verify the configuration was actually written correctly
            verifyRefindLinuxConf(sysInfo);

            // Configure rEFInd to scan /boot for kernels
            configureRefindScanPaths(sysInfo, refindLocation);

            // Also create manual boot stanza in refind.conf for reliability
            createRefindManualStanza(sysInfo);

            // Mount efivars if not already mounted (needed for efibootmgr)
            mountEfiVars(sysInfo);

            // Ensure fallback boot entry exists
            ensureFallbackBootEntry(sysInfo);

            if (success) {
                ui.printStatus("✓ rEFInd configuration updated with btrfs support");
            }
            return success;

        } catch (Exception e) {
            Logger.error("Exception fixing rEFInd: " ~ e.msg);
            return false;
        }
    }

    /**
     * Detect dual-EFI partition setup
     */
    private bool detectDualEfiSetup(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        try {
            // Check if /boot is on a different partition than /boot/efi
            auto bootDev = executeShell("df /boot | tail -1 | awk '{print $1}'");
            auto efiDev = executeShell("df /boot/efi | tail -1 | awk '{print $1}'");

            if (bootDev.status == 0 && efiDev.status == 0) {
                string bootPartition = bootDev.output.strip();
                string efiPartition = efiDev.output.strip();

                // Check if both are FAT partitions (unusual setup)
                auto bootFs = executeShell("blkid -s TYPE -o value " ~ bootPartition);
                auto efiFs = executeShell("blkid -s TYPE -o value " ~ efiPartition);

                if (bootFs.status == 0 && efiFs.status == 0) {
                    string bootFsType = bootFs.output.strip().toLower();
                    string efiFsType = efiFs.output.strip().toLower();

                    if ((bootFsType.canFind("fat") || bootFsType.canFind("vfat")) &&
                        (efiFsType.canFind("fat") || efiFsType.canFind("vfat")) &&
                        bootPartition != efiPartition) {
                        Logger.info("Dual-EFI setup detected: /boot on " ~ bootPartition ~ ", /boot/efi on " ~ efiPartition);
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            Logger.warning("Could not detect dual-EFI setup: " ~ e.msg);
        }

        return false;
    }

    /**
     * Fix rEFInd for dual-EFI partition setup
     */
    bool fixDualEfiRefind(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        ui.printInfo("Handling dual-EFI partition configuration...");

        try {
            // Get the UUID of the boot partition (where kernel is)
            auto bootResult = executeShell("df /boot | tail -1 | awk '{print $1}'");
            if (bootResult.status != 0) {
                ui.printError("Could not determine boot partition");
                return false;
            }

            string bootDevice = bootResult.output.strip();

            // Get the UUID/label of the boot partition
            auto uuidResult = executeShell("blkid -s UUID -o value " ~ bootDevice);
            string bootVolumeId = uuidResult.status == 0 ? uuidResult.output.strip() : "";

            // If no UUID, try label
            if (bootVolumeId.length == 0) {
                auto labelResult = executeShell("blkid -s LABEL -o value " ~ bootDevice);
                bootVolumeId = labelResult.status == 0 ? labelResult.output.strip() : "";
            }

            if (bootVolumeId.length == 0) {
                ui.printError("Could not determine boot volume identifier");
                return false;
            }

            ui.printInfo("Boot partition volume: " ~ bootVolumeId);

            // Clean up misplaced initramfs files from EFI partition
            cleanupDualEfiMisplacedFiles(sysInfo);

            // Ensure refind_linux.conf is correct
            generateRefindLinuxConf(sysInfo);
            verifyRefindLinuxConf(sysInfo);

            // Add manual entry to rEFInd
            string refindConfPath = buildPath(sysInfo.efiDir, "EFI/refind/refind.conf");

            if (!exists(refindConfPath)) {
                ui.printWarning("refind.conf not found, creating basic configuration");
                createBasicRefindConf(refindConfPath);
            }

            // Check if manual entry already exists
            import std.file : readText;
            string refindContent = readText(refindConfPath);

            if (refindContent.indexOf("menuentry \"CachyOS Linux\"") == -1) {
                ui.printInfo("Adding manual boot entry for CachyOS...");

                // Backup configuration
                copy(refindConfPath, refindConfPath ~ ".bak");

                // Add manual entry
                string manualEntry = "\n\n# Manual CachyOS entry for dual-EFI setup\n";
                manualEntry ~= "menuentry \"CachyOS Linux\" {\n";
                manualEntry ~= "    icon     /EFI/refind/icons/os_arch.png\n";
                manualEntry ~= "    volume   " ~ bootVolumeId ~ "\n";
                manualEntry ~= "    loader   /vmlinuz-linux-cachyos\n";
                manualEntry ~= "    initrd   /initramfs-linux-cachyos.img\n";
                manualEntry ~= "    options  \"root=UUID=" ~ sysInfo.uuid ~ " rootflags=subvol=@ rw quiet splash\"\n";
                manualEntry ~= "}\n";

                append(refindConfPath, manualEntry);
                ui.printSuccess("Added manual CachyOS entry to rEFInd");

                // Also add exclusions to reduce duplicates
                if (refindContent.indexOf("dont_scan_volumes") == -1) {
                    append(refindConfPath, "\n# Hide duplicate entries\n");
                    append(refindConfPath, "dont_scan_volumes " ~ bootVolumeId ~ "\n");
                }
            } else {
                ui.printInfo("Manual CachyOS entry already exists");
            }

            ui.printSuccess("Dual-EFI rEFInd configuration completed");
            ui.printInfo("Look for 'CachyOS Linux' entry in rEFInd menu");

            return true;

        } catch (Exception e) {
            Logger.error("Failed to fix dual-EFI rEFInd: " ~ e.msg);
            ui.printError("Could not configure rEFInd for dual-EFI setup");
            return false;
        }
    }

    /**
     * Clean up misplaced files in dual-EFI setup
     */
    private void cleanupDualEfiMisplacedFiles(ref SystemInfo sysInfo) {
        import std.file : remove, dirEntries, SpanMode;
        import std.path : baseName;

        try {
            // Only remove initramfs from EFI directories (kernels should stay in /boot)
            string[] checkDirs = [
                buildPath(sysInfo.efiDir, "EFI/CachyOS"),
                buildPath(sysInfo.efiDir, "EFI/Linux"),
                buildPath(sysInfo.efiDir, "EFI/cachyos"),
                buildPath(sysInfo.efiDir, "EFI/linux")
            ];

            foreach (dir; checkDirs) {
                if (exists(dir)) {
                    foreach (entry; dirEntries(dir, "initramfs*", SpanMode.shallow)) {
                        ui.printInfo("Removing misplaced: " ~ baseName(entry.name));
                        try {
                            remove(entry.name);
                        } catch (Exception e) {
                            Logger.warning("Could not remove: " ~ e.msg);
                        }
                    }

                    // Remove directory if empty
                    try {
                        auto remaining = dirEntries(dir, SpanMode.shallow);
                        if (remaining.empty) {
                            rmdir(dir);
                            ui.printInfo("Removed empty directory: " ~ baseName(dir));
                        }
                    } catch (Exception e) {
                        // Directory not empty or couldn't remove
                    }
                }
            }
        } catch (Exception e) {
            Logger.warning("Error cleaning dual-EFI misplaced files: " ~ e.msg);
        }
    }

    /**
     * Create basic refind.conf if missing
     */
    private void createBasicRefindConf(string path) {
        import std.file : write, mkdirRecurse;
        import std.path : dirName;

        try {
            mkdirRecurse(dirName(path));

            string basicConf = "# rEFInd configuration\n";
            basicConf ~= "timeout 10\n";
            basicConf ~= "use_nvram false\n";
            basicConf ~= "scanfor manual,external,optical,internal\n";
            basicConf ~= "scan_all_linux_kernels true\n\n";

            write(path, basicConf);
            Logger.info("Created basic refind.conf");
        } catch (Exception e) {
            Logger.error("Could not create refind.conf: " ~ e.msg);
        }
    }

    /**
     * Detect where rEFInd is installed
     */
    private string detectRefindInstallation(ref SystemInfo sysInfo) {
        string[] possibleLocations = [
            buildPath(sysInfo.efiDir, "EFI/refind"),
            buildPath(sysInfo.efiDir, "EFI/BOOT"),
            buildPath(sysInfo.efiDir, "EFI/boot"),
            buildPath(sysInfo.efiDir, "EFI/rEFInd")
        ];

        foreach (location; possibleLocations) {
            string refindEfi = buildPath(location, "refind_x64.efi");
            string bootEfi = buildPath(location, "bootx64.efi");

            if (exists(refindEfi) || (exists(bootEfi) && exists(buildPath(location, "refind.conf")))) {
                Logger.info("Found rEFInd at: " ~ location);
                ui.printInfo("rEFInd located at: " ~ location);
                return location;
            }
        }

        Logger.warning("rEFInd installation not found");
        return "";
    }

    /**
     * Install rEFInd properly
     */
    private void installRefindProperly(ref SystemInfo sysInfo) {
        try {
            if (exists(buildPath(sysInfo.mountPoint, "usr/bin/refind-install"))) {
                ui.printInfo("Installing rEFInd...");
                auto process = ChrootManager.executeChrootDirect(sysInfo, ["refind-install"]);
                auto exitCode = wait(process);

                if (exitCode == 0) {
                    ui.printStatus("✓ rEFInd installed successfully");
                } else {
                    ui.printWarning("rEFInd installation had warnings");
                }
            } else {
                ui.printError("refind-install not found, please install refind package");
            }
        } catch (Exception e) {
            Logger.error("Failed to install rEFInd: " ~ e.msg);
        }
    }

    /**
     * Clean up misplaced kernels from EFI partition
     */
    private void cleanupMisplacedKernels(ref SystemInfo sysInfo) {
        import std.file : remove;
        import std.path : baseName;

        try {
            // Remove kernels that shouldn't be in EFI/CachyOS or EFI/Linux
            string[] wrongLocations = [
                buildPath(sysInfo.efiDir, "EFI/CachyOS"),
                buildPath(sysInfo.efiDir, "EFI/Linux"),
                buildPath(sysInfo.efiDir, "EFI/cachyos"),
                buildPath(sysInfo.efiDir, "EFI/linux")
            ];

            foreach (location; wrongLocations) {
                if (exists(location)) {
                    // Remove vmlinuz files (kernels don't belong here)
                    foreach (entry; dirEntries(location, "vmlinuz*", SpanMode.shallow)) {
                        Logger.info("Removing misplaced kernel: " ~ entry.name);
                        ui.printInfo("Removing kernel from EFI: " ~ baseName(entry.name));
                        try {
                            remove(entry.name);
                        } catch (Exception e) {
                            Logger.warning("Could not remove: " ~ e.msg);
                        }
                    }

                    // Also remove initramfs from here - they belong in /boot
                    foreach (entry; dirEntries(location, "initramfs*", SpanMode.shallow)) {
                        Logger.info("Removing misplaced initramfs: " ~ entry.name);
                        ui.printInfo("Removing initramfs from EFI: " ~ baseName(entry.name));
                        try {
                            remove(entry.name);
                        } catch (Exception e) {
                            Logger.warning("Could not remove: " ~ e.msg);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Logger.warning("Error cleaning misplaced kernels: " ~ e.msg);
        }
    }

    /**
     * Configure rEFInd to scan correct paths
     */
    private void configureRefindScanPaths(ref SystemInfo sysInfo, string refindLocation) {
        import std.file : readText, write, append;
        import std.string : indexOf, replace;

        if (refindLocation.length == 0) return;

        try {
            string refindConfPath = buildPath(refindLocation, "refind.conf");

            if (!exists(refindConfPath)) {
                // Create basic refind.conf
                ui.printInfo("Creating refind.conf...");
                string basicConf = "# rEFInd configuration\n" ~
                    "timeout 10\n" ~
                    "use_nvram false\n" ~
                    "scanfor manual,external,optical,internal\n" ~
                    "also_scan_dirs +,boot\n" ~
                    "dont_scan_dirs /EFI/opensuse,/EFI/Microsoft\n" ~
                    "scan_all_linux_kernels true\n\n";
                write(refindConfPath, basicConf);
            } else {
                // Update existing configuration
                string content = readText(refindConfPath);
                bool modified = false;

                // Ensure it scans /boot directory
                if (content.indexOf("also_scan_dirs") == -1) {
                    content ~= "\n# Added by debork - scan /boot for kernels\n";
                    content ~= "also_scan_dirs +,boot\n";
                    modified = true;
                }

                // Hide duplicate OpenSUSE entries
                if (content.indexOf("dont_scan_dirs") == -1) {
                    content ~= "dont_scan_dirs /EFI/opensuse\n";
                    modified = true;
                } else if (content.indexOf("/EFI/opensuse") == -1) {
                    content = content.replace("dont_scan_dirs", "dont_scan_dirs /EFI/opensuse,");
                    modified = true;
                }

                // Ensure Linux kernel scanning is enabled
                if (content.indexOf("scan_all_linux_kernels") == -1) {
                    content ~= "scan_all_linux_kernels true\n";
                    modified = true;
                }

                if (modified) {
                    // Backup and write
                    string backupPath = refindConfPath ~ ".bak";
                    copy(refindConfPath, backupPath);
                    write(refindConfPath, content);
                    ui.printInfo("Updated rEFInd configuration to scan /boot");
                }
            }
        } catch (Exception e) {
            Logger.error("Failed to configure rEFInd scan paths: " ~ e.msg);
        }
    }

    /**
     * Clean up duplicate and incorrect rEFInd entries
     */
    private void cleanupRefindEntries(ref SystemInfo sysInfo) {
        import std.file : dirEntries, SpanMode, remove;
        import std.path : baseName;

        try {
            // Clean up duplicate kernel entries in /boot
            ui.printInfo("Checking for duplicate boot entries...");

            // Remove any vmlinuz files directly in /boot/efi (they shouldn't be there)
            string efiBootDir = buildPath(sysInfo.efiDir, "EFI");
            if (exists(efiBootDir)) {
                foreach (entry; dirEntries(efiBootDir, "vmlinuz*", SpanMode.depth)) {
                    if (!entry.isDir) {
                        Logger.info("Removing misplaced kernel: " ~ entry.name);
                        ui.printInfo("Removing misplaced kernel from EFI: " ~ baseName(entry.name));
                        try {
                            remove(entry.name);
                        } catch (Exception e) {
                            Logger.warning("Could not remove: " ~ e.msg);
                        }
                    }
                }
            }

            // Check for and remove old/invalid refind_linux.conf files
            string[] possibleLocations = [
                buildPath(sysInfo.efiDir, "refind_linux.conf"),
                buildPath(sysInfo.efiDir, "EFI/refind_linux.conf"),
                buildPath(sysInfo.efiDir, "EFI/refind/refind_linux.conf"),
                buildPath(sysInfo.mountPoint, "refind_linux.conf")
            ];

            foreach (location; possibleLocations) {
                if (exists(location)) {
                    Logger.info("Found misplaced refind_linux.conf at: " ~ location);
                    ui.printInfo("Removing misplaced config: " ~ location);
                    try {
                        remove(location);
                    } catch (Exception e) {
                        Logger.warning("Could not remove: " ~ e.msg);
                    }
                }
            }

            // The only correct location for refind_linux.conf is /boot
            Logger.info("Cleaned up rEFInd entries");

        } catch (Exception e) {
            Logger.warning("Error during rEFInd cleanup: " ~ e.msg);
        }
    }

    /**
     * Verify refind_linux.conf has proper content
     */
    private void verifyRefindLinuxConf(ref SystemInfo sysInfo) {
        import std.file : readText;

        try {
            string confPath = buildPath(sysInfo.bootDir, "refind_linux.conf");

            if (!exists(confPath)) {
                ui.printError("refind_linux.conf not found after generation!");
                return;
            }

            string content = readText(confPath);

            // Check for critical issues
            bool hasIssues = false;

            if (content.indexOf("root=") == -1) {
                ui.printError("CRITICAL: No root= parameter in refind_linux.conf!");
                hasIssues = true;
            }

            if (content.indexOf("root=\"\"") != -1 || content.indexOf("root= ") != -1) {
                ui.printError("CRITICAL: Empty root= parameter detected!");
                hasIssues = true;
            }

            if (content.indexOf("UUID=") == -1 && content.indexOf("PARTUUID=") == -1 &&
                content.indexOf("/dev/") == -1) {
                ui.printError("CRITICAL: No device specification found!");
                hasIssues = true;
            }

            if (sysInfo.isBtrfs && content.indexOf("rootflags=subvol=") == -1) {
                ui.printWarning("Warning: No btrfs subvolume specified!");
                hasIssues = true;
            }

            // If there are issues, show the actual content for debugging
            if (hasIssues) {
                ui.printInfo("Current refind_linux.conf content:");
                auto lines = content.split("\n");
                foreach (i, line; lines) {
                    if (line.length > 0) {
                        ui.printInfo("  Line " ~ to!string(i+1) ~ ": " ~ line[0..min(line.length, 100)]);
                    }
                }

                // Try to fix it one more time
                ui.printInfo("Attempting to regenerate with forced parameters...");
                forceRegenerateRefindLinuxConf(sysInfo);
            } else {
                ui.printSuccess("refind_linux.conf appears valid");

                // Show the root parameter for confirmation
                auto rootStart = content.indexOf("root=");
                if (rootStart != -1) {
                    auto rootEnd = content.indexOf(" ", rootStart);
                    if (rootEnd == -1) rootEnd = content.indexOf("\"", rootStart);
                    if (rootEnd != -1) {
                        string rootParam = content[rootStart .. rootEnd];
                        ui.printInfo("Using: " ~ rootParam);
                    }
                }
            }

        } catch (Exception e) {
            Logger.error("Error verifying refind_linux.conf: " ~ e.msg);
        }
    }

    /**
     * Force regenerate refind_linux.conf with explicit parameters
     */
    private void forceRegenerateRefindLinuxConf(ref SystemInfo sysInfo) {
        import std.process : executeShell;
        import std.file : write;

        try {
            // Get UUID by any means necessary
            string uuid;
            string device = sysInfo.device;

            // Try multiple methods to get UUID
            auto result = executeShell("blkid -s UUID -o value " ~ device ~ " 2>/dev/null");
            if (result.status == 0 && result.output.strip().length > 0) {
                uuid = result.output.strip();
            } else {
                result = executeShell("lsblk -no UUID " ~ device ~ " 2>/dev/null | head -n1");
                if (result.status == 0 && result.output.strip().length > 0) {
                    uuid = result.output.strip();
                }
            }

            if (uuid.length == 0) {
                // Last resort - use device path
                ui.printWarning("Could not detect UUID, using device path directly");
                uuid = "";
            }

            // Build the root parameter
            string rootParam;
            if (uuid.length > 0) {
                rootParam = "root=UUID=" ~ uuid;
            } else {
                rootParam = "root=" ~ device;
            }

            // Add btrfs subvolume
            if (sysInfo.isBtrfs) {
                string subvol = sysInfo.btrfsInfo.rootSubvolume;
                if (subvol.length == 0) subvol = "@";
                if (subvol.startsWith("/")) subvol = subvol[1..$];
                rootParam ~= " rootflags=subvol=" ~ subvol;
            }

            // Find initrd
            string initrdParam = "";
            foreach (kernel; sysInfo.kernels) {
                if (kernel.initrdExists) {
                    initrdParam = "initrd=" ~ baseName(kernel.initrd);
                    break;
                }
            }

            // Build the configuration
            string content;
            if (initrdParam.length > 0) {
                content = format(
                    "\"Boot with standard options\" \"%s %s rw quiet splash\"\n" ~
                    "\"Boot to single-user mode\" \"%s %s rw single\"\n" ~
                    "\"Boot with minimal options\" \"%s ro\"\n",
                    rootParam, initrdParam,
                    rootParam, initrdParam,
                    rootParam
                );
            } else {
                content = format(
                    "\"Boot with standard options\" \"%s rw quiet splash\"\n" ~
                    "\"Boot to single-user mode\" \"%s rw single\"\n" ~
                    "\"Boot with minimal options\" \"%s ro\"\n",
                    rootParam,
                    rootParam,
                    rootParam
                );
            }

            // Write the file
            string confPath = buildPath(sysInfo.bootDir, "refind_linux.conf");
            write(confPath, content);

            Logger.info("Force regenerated refind_linux.conf");
            ui.printSuccess("Regenerated refind_linux.conf with explicit parameters");
            ui.printInfo("Root parameter: " ~ rootParam);

        } catch (Exception e) {
            Logger.error("Failed to force regenerate: " ~ e.msg);
            ui.printError("Could not regenerate configuration: " ~ e.msg);
        }
    }

    /**
     * Generate refind_linux.conf manually
     */
    private bool generateRefindLinuxConf(ref SystemInfo sysInfo) {
        try {
            // Try using mkrlconf first if available
            if (exists(buildPath(sysInfo.mountPoint, "usr/bin/mkrlconf"))) {
                ui.printInfo("Using mkrlconf to generate refind_linux.conf...");
                auto mkrlconfResult = ChrootManager.executeChrootDirect(sysInfo, ["mkrlconf", "--force"]);
                auto exitCode = wait(mkrlconfResult);

                if (exitCode == 0) {
                    Logger.info("Successfully generated refind_linux.conf with mkrlconf");
                    ui.printSuccess("Generated refind_linux.conf using mkrlconf");

                    // Verify and fix the generated file if needed
                    fixRefindLinuxConf(sysInfo);
                    return true;
                } else {
                    Logger.warning("mkrlconf failed, falling back to manual generation");
                }
            }

            string bootPath = sysInfo.bootDir;
            string refindConfPath = buildPath(bootPath, "refind_linux.conf");

            // Detect the actual UUID if not already set
            if (sysInfo.uuid.length == 0) {
                try {
                    // Try multiple methods to get UUID
                    auto uuidResult = execute(["blkid", "-s", "UUID", "-o", "value", sysInfo.device]);
                    if (uuidResult.status == 0 && uuidResult.output.strip().length > 0) {
                        sysInfo.uuid = uuidResult.output.strip();
                        Logger.info("Detected UUID via blkid: " ~ sysInfo.uuid);
                    } else {
                        // Try lsblk as fallback
                        auto lsblkResult = execute(["lsblk", "-no", "UUID", sysInfo.device]);
                        if (lsblkResult.status == 0 && lsblkResult.output.strip().length > 0) {
                            sysInfo.uuid = lsblkResult.output.strip().split("\n")[0];
                            Logger.info("Detected UUID via lsblk: " ~ sysInfo.uuid);
                        }
                    }
                } catch (Exception e) {
                    Logger.error("Failed to detect UUID: " ~ e.msg);
                    ui.printWarning("Could not detect UUID, will use device path");
                }
            }

            // Verify the device exists
            if (!exists(sysInfo.device)) {
                Logger.error("Device does not exist: " ~ sysInfo.device);
                ui.printError("Warning: Root device not found: " ~ sysInfo.device);
            }

            // Generate configuration content
            string rootParam;

            // Use UUID if available, otherwise fall back to device
            if (sysInfo.uuid.length > 0) {
                // Check if it's a PARTUUID
                if (sysInfo.uuid.indexOf("-") == 8) {
                    rootParam = "root=PARTUUID=" ~ sysInfo.uuid;
                    ui.printInfo("Using PARTUUID for boot: " ~ sysInfo.uuid);
                } else {
                    rootParam = "root=UUID=" ~ sysInfo.uuid;
                    ui.printInfo("Using UUID for boot: " ~ sysInfo.uuid);
                }
            } else {
                Logger.warning("No UUID available, using device path");
                rootParam = "root=" ~ sysInfo.device;
                ui.printWarning("Using device path instead of UUID: " ~ sysInfo.device);
            }

            // Add btrfs subvolume if needed
            if (sysInfo.isBtrfs) {
                // CachyOS typically uses @ as root subvolume
                string subvol = sysInfo.btrfsInfo.rootSubvolume;
                if (subvol.length == 0) {
                    subvol = "@";  // Default for CachyOS (without leading slash)
                }
                // Ensure subvolume doesn't have leading slash for kernel parameter
                if (subvol.startsWith("/")) {
                    subvol = subvol[1..$];
                }
                rootParam ~= " rootflags=subvol=" ~ subvol;
                ui.printInfo("Using btrfs subvolume: " ~ subvol);
            }

            // Add common CachyOS boot parameters
            // Important: Include initrd explicitly for some rEFInd versions
            string initrdParam = "";
            foreach (kernel; sysInfo.kernels) {
                if (kernel.initrdExists) {
                    // Use relative path from /boot
                    string initrdName = baseName(kernel.initrd);
                    initrdParam = "initrd=" ~ initrdName;
                    break;
                }
            }

            string commonParams = "rw quiet zswap.enabled=0 nowatchdog splash";
            if (initrdParam.length > 0) {
                commonParams = initrdParam ~ " " ~ commonParams;
            }

            // Ensure we have proper root device specification
            if (rootParam.length == 0) {
                Logger.error("Root parameter is empty!");
                ui.printError("Failed to determine root device parameter");
                rootParam = "root=" ~ sysInfo.device;  // Fallback to device path
            }

            // Log the parameters for debugging
            Logger.info("Boot parameters: " ~ rootParam ~ " " ~ commonParams);

            // Format with proper quoting
            string content = format(
                "\"Boot with standard options\"  %s %s\n" ~
                "\"Boot to single-user mode\"    %s %s single\n" ~
                "\"Boot with minimal options\"   %s ro\n",
                rootParam, commonParams,
                rootParam, commonParams,
                rootParam
            );

            // Backup existing configuration if it exists
            if (exists(refindConfPath)) {
                string backupPath = refindConfPath ~ ".backup";
                copy(refindConfPath, backupPath);
                Logger.info("Backed up existing configuration to: " ~ backupPath);
            }

            // Write configuration file
            write(refindConfPath, content);
            Logger.info("Generated rEFInd configuration: " ~ refindConfPath);
            Logger.info("Configuration content:\n" ~ content);
            ui.printSuccess("Generated rEFInd configuration with btrfs support");
            ui.printInfo("Configuration written to: " ~ refindConfPath);

            // Display the actual content for verification
            ui.printInfo("Boot parameters configured:");
            ui.printInfo("  " ~ rootParam ~ (sysInfo.isBtrfs ? " (with btrfs subvolume)" : ""));

            // Also fix the EFI bootloader entries if needed
            fixEfiBootEntries(sysInfo);

            return true;

        } catch (Exception e) {
            Logger.error("Exception generating rEFInd configuration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix refind_linux.conf if it has issues
     */
    private void fixRefindLinuxConf(ref SystemInfo sysInfo) {
        import std.file : readText, write;
        import std.string : replace, indexOf;

        try {
            string confPath = buildPath(sysInfo.bootDir, "refind_linux.conf");
            if (!exists(confPath)) {
                return;
            }

            string content = readText(confPath);
            bool modified = false;

            // Check if root= parameter is empty or missing
            if (content.indexOf("root= ") != -1 || content.indexOf("root=\"\"") != -1) {
                // Root parameter is empty, need to fix it
                string rootParam;
                if (sysInfo.uuid.length > 0) {
                    rootParam = "root=UUID=" ~ sysInfo.uuid;
                } else {
                    rootParam = "root=" ~ sysInfo.device;
                }

                // Add btrfs subvolume if needed
                if (sysInfo.isBtrfs && sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                    string subvol = sysInfo.btrfsInfo.rootSubvolume;
                    if (subvol.startsWith("/")) {
                        subvol = subvol[1..$];
                    }
                    rootParam ~= " rootflags=subvol=" ~ subvol;
                }

                // Replace empty root with proper one
                content = content.replace("root= ", rootParam ~ " ");
                content = content.replace("root=\"\"", rootParam);
                modified = true;

                Logger.info("Fixed empty root parameter in refind_linux.conf");
                ui.printInfo("Fixed boot configuration with proper root device");
            }

            // Ensure initrd is specified if missing
            if (content.indexOf("initrd=") == -1) {
                foreach (kernel; sysInfo.kernels) {
                    if (kernel.initrdExists) {
                        string initrdName = baseName(kernel.initrd);
                        // Add initrd parameter to each line
                        auto lines = content.split("\n");
                        string newContent;
                        foreach (line; lines) {
                            if (line.length > 0 && line.indexOf("\"") != -1) {
                                // Insert initrd before other parameters
                                auto firstQuote = line.indexOf("\"");
                                auto secondQuote = line.indexOf("\"", firstQuote + 1);
                                if (secondQuote != -1) {
                                    auto thirdQuote = line.indexOf("\"", secondQuote + 1);
                                    if (thirdQuote != -1) {
                                        string params = line[secondQuote + 1 .. thirdQuote];
                                        params = "initrd=" ~ initrdName ~ " " ~ params;
                                        line = line[0 .. secondQuote + 1] ~ params ~ line[thirdQuote .. $];
                                    }
                                }
                            }
                            newContent ~= line ~ "\n";
                        }
                        content = newContent;
                        modified = true;
                        Logger.info("Added initrd parameter to refind_linux.conf");
                        break;
                    }
                }
            }

            if (modified) {
                // Backup and write new content
                string backupPath = confPath ~ ".bak";
                copy(confPath, backupPath);
                write(confPath, content);
                Logger.info("Updated refind_linux.conf with fixes");
            }

        } catch (Exception e) {
            Logger.warning("Could not fix refind_linux.conf: " ~ e.msg);
        }
    }

    /**
     * Create manual boot stanza in refind.conf
     */
    private void createRefindManualStanza(ref SystemInfo sysInfo) {
        import std.file : readText, write, append;
        import std.string : indexOf;

        try {
            // Find where rEFInd is actually installed
            string refindLocation = detectRefindInstallation(sysInfo);
            if (refindLocation.length == 0) {
                Logger.warning("Cannot create manual stanza - rEFInd not found");
                return;
            }

            string refindConfPath = buildPath(refindLocation, "refind.conf");

            if (!exists(refindConfPath)) {
                Logger.warning("refind.conf not found at: " ~ refindConfPath);
                return;
            }

            // Read existing configuration
            string content = readText(refindConfPath);

            // Check if we already have a manual stanza for CachyOS/Arch
            if (content.indexOf("menuentry \"CachyOS\"") != -1 ||
                content.indexOf("menuentry \"Arch Linux\"") != -1) {
                Logger.info("Manual stanza already exists in refind.conf");
                return;
            }

            // Find the first kernel
            KernelInfo primaryKernel;
            bool foundKernel = false;
            foreach (kernel; sysInfo.kernels) {
                if (kernel.exists && kernel.initrdExists) {
                    primaryKernel = kernel;
                    foundKernel = true;
                    break;
                }
            }

            if (!foundKernel) {
                Logger.warning("No valid kernel found for manual stanza");
                return;
            }

            // Build root parameter
            string rootParam;
            if (sysInfo.uuid.length > 0) {
                // Check if it's a PARTUUID
                if (sysInfo.uuid.indexOf("-") == 8) {
                    rootParam = "root=PARTUUID=" ~ sysInfo.uuid;
                } else {
                    rootParam = "root=UUID=" ~ sysInfo.uuid;
                }
            } else {
                rootParam = "root=" ~ sysInfo.device;
            }

            // Add btrfs subvolume if needed
            if (sysInfo.isBtrfs && sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                string subvol = sysInfo.btrfsInfo.rootSubvolume;
                if (subvol.startsWith("/")) {
                    subvol = subvol[1..$];
                }
                rootParam ~= " rootflags=subvol=" ~ subvol;
            }

            // Create manual stanza pointing to /boot
            string stanza = "\n\n# Manual stanza added by debork\n";
            stanza ~= "menuentry \"CachyOS Linux\" {\n";
            stanza ~= "    icon     /EFI/refind/icons/os_arch.png\n";
            stanza ~= "    volume   \"" ~ (sysInfo.uuid.length > 0 ? sysInfo.uuid : "boot") ~ "\"\n";
            stanza ~= "    loader   /boot/vmlinuz-linux-cachyos\n";
            stanza ~= "    initrd   /boot/initramfs-linux-cachyos.img\n";
            stanza ~= "    options  \"" ~ rootParam ~ " rw quiet zswap.enabled=0 nowatchdog splash\"\n";
            stanza ~= "    submenuentry \"Boot to single-user mode\" {\n";
            stanza ~= "        options \"" ~ rootParam ~ " rw single\"\n";
            stanza ~= "    }\n";
            stanza ~= "    submenuentry \"Boot with minimal options\" {\n";
            stanza ~= "        options \"" ~ rootParam ~ " ro\"\n";
            stanza ~= "    }\n";
            stanza ~= "}\n";

            // Backup original
            string backupPath = refindConfPath ~ ".bak";
            copy(refindConfPath, backupPath);
            Logger.info("Backed up refind.conf to: " ~ backupPath);

            // Append stanza to configuration
            append(refindConfPath, stanza);

            Logger.info("Added manual boot stanza to refind.conf");
            ui.printInfo("Created manual boot entry in rEFInd configuration");
            ui.printInfo("Manual stanza uses: " ~ rootParam);

        } catch (Exception e) {
            Logger.warning("Could not create manual stanza: " ~ e.msg);
        }
    }

    /**
     * Fix systemd-boot configuration
     */
    private bool fixEfiBootEntries(ref SystemInfo sysInfo) {
        try {
            // Check if we have kernels in /boot
            string bootDir = sysInfo.bootDir;
            string[] kernelFiles;

            foreach (DirEntry e; dirEntries(bootDir, SpanMode.shallow)) {
                if (e.isFile && e.name.baseName.startsWith("vmlinuz-")) {
                    kernelFiles ~= e.name;
                    Logger.info("Found kernel: " ~ e.name);
                }
            }

            // For CachyOS with rEFInd, ensure kernel is accessible
            foreach (kernelFile; kernelFiles) {
                string kernelName = baseName(kernelFile);
                string efiKernelPath = buildPath(sysInfo.mountPoint, "boot", "efi", "EFI", "CachyOS", kernelName);
                string sourceKernelPath = buildPath(bootDir, kernelName);

                // Also copy initramfs
                string initramfsName = kernelName.replace("vmlinuz-", "initramfs-") ~ ".img";
                string efiInitramfsPath = buildPath(sysInfo.mountPoint, "boot", "efi", "EFI", "CachyOS", initramfsName);
                string sourceInitramfsPath = buildPath(bootDir, initramfsName);

                // Create CachyOS directory if it doesn't exist
                string efiCachyDir = buildPath(sysInfo.mountPoint, "boot", "efi", "EFI", "CachyOS");
                if (!exists(efiCachyDir)) {
                    mkdirRecurse(efiCachyDir);
                    Logger.info("Created EFI CachyOS directory");
                }

                // Copy kernel and initramfs to EFI partition if they don't exist there
                if (exists(sourceKernelPath) && !exists(efiKernelPath)) {
                    copy(sourceKernelPath, efiKernelPath);
                    Logger.info("Copied kernel to EFI partition: " ~ kernelName);
                }

                if (exists(sourceInitramfsPath) && !exists(efiInitramfsPath)) {
                    copy(sourceInitramfsPath, efiInitramfsPath);
                    Logger.info("Copied initramfs to EFI partition: " ~ initramfsName);
                }
            }

            return true;
        } catch (Exception e) {
            Logger.error("Exception fixing EFI boot entries: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix systemd-boot
     */
    private bool fixSystemdBoot(ref SystemInfo sysInfo) {
        Logger.info("Fixing systemd-boot");

        try {
            // Use bootctl if available
            if (exists(buildPath(sysInfo.mountPoint, "usr/bin/bootctl"))) {
                auto process = ChrootManager.executeChrootDirect(sysInfo, ["bootctl", "update"]);
                auto exitCode = wait(process);

                if (exitCode == 0) {
                    ui.printStatus("✓ systemd-boot updated");
                    return generateSystemdBootEntries(sysInfo);
                }
            }

            // Fallback to manual configuration
            return generateSystemdBootEntries(sysInfo);

        } catch (Exception e) {
            Logger.error("Exception fixing systemd-boot: " ~ e.msg);
            return false;
        }
    }

    /**
     * Generate systemd-boot entries
     */
    private bool generateSystemdBootEntries(ref SystemInfo sysInfo) {
        try {
            string loaderDir = buildPath(sysInfo.efiDir, "loader");
            string entriesDir = buildPath(loaderDir, "entries");

            if (!exists(entriesDir)) {
                mkdirRecurse(entriesDir);
            }

            // Generate loader.conf
            string loaderConf = buildPath(loaderDir, "loader.conf");
            string loaderContent =
                "default arch.conf\n" ~
                "timeout 4\n" ~
                "console-mode keep\n" ~
                "editor no\n";
            write(loaderConf, loaderContent);

            // Generate entries for each kernel
            foreach (kernel; sysInfo.kernels) {
                if (!kernel.exists) continue;

                string entryFile = buildPath(entriesDir, kernel.kernelVersion ~ ".conf");
                string rootParam;

                // Use UUID if available
                if (sysInfo.uuid.length > 0) {
                    rootParam = "root=UUID=" ~ sysInfo.uuid;
                } else {
                    Logger.warning("No UUID for systemd-boot entry, using device");
                    rootParam = "root=" ~ sysInfo.device;
                }

                if (sysInfo.isBtrfs && sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                    rootParam ~= " rootflags=subvol=" ~ sysInfo.btrfsInfo.rootSubvolume;
                }

                string entryContent = format(
                    "title   Arch Linux (%s)\n" ~
                    "linux   /%s\n" ~
                    "initrd  /%s\n" ~
                    "options %s rw\n",
                    kernel.kernelVersion,
                    kernel.path,
                    kernel.initrd,
                    rootParam
                );

                write(entryFile, entryContent);
                Logger.debugLog("Generated systemd-boot entry: " ~ entryFile);
            }

            ui.printStatus("✓ systemd-boot entries generated");
            return true;

        } catch (Exception e) {
            Logger.error("Failed to generate systemd-boot entries: " ~ e.msg);
            return false;
        }
    }

    /**
     * Attempt to auto-detect and fix bootloader
     */
    private bool attemptBootloaderAutofix(ref SystemInfo sysInfo) {
        Logger.info("Attempting bootloader auto-detection and fix");

        // Try each bootloader type
        if (exists(buildPath(sysInfo.mountPoint, "usr/bin/grub-mkconfig")) ||
            exists(buildPath(sysInfo.mountPoint, "boot/grub/grub.cfg"))) {

            sysInfo.bootLoader = BootLoader.GRUB;
            ui.printInfo("Auto-detected GRUB bootloader");
            return fixGrub(sysInfo);
        }

        if (exists(buildPath(sysInfo.efiDir, "EFI/refind/refind.conf")) ||
            exists(buildPath(sysInfo.mountPoint, "usr/bin/refind-install"))) {

            sysInfo.bootLoader = BootLoader.REFIND;
            ui.printInfo("Auto-detected rEFInd bootloader");
            return fixRefind(sysInfo);
        }

        if (exists(buildPath(sysInfo.efiDir, "loader/loader.conf")) ||
            exists(buildPath(sysInfo.mountPoint, "usr/bin/bootctl"))) {

            sysInfo.bootLoader = BootLoader.SYSTEMD_BOOT;
            ui.printInfo("Auto-detected systemd-boot");
            return fixSystemdBoot(sysInfo);
        }

        ui.printWarning("Could not auto-detect bootloader type");
        return false;
    }

    /**
     * Get package update command for different package managers
     */
    private string getUpdateCommand(PackageManager pm) {
        final switch (pm) {
            case PackageManager.PACMAN:
                return "pacman -Syyu --noconfirm";
            case PackageManager.APT:
                return "apt update && apt upgrade -y";
            case PackageManager.YUM:
                return "yum update -y";
            case PackageManager.DNF:
                return "dnf update -y";
            case PackageManager.ZYPPER:
                return "zypper refresh && zypper update -y";
            case PackageManager.UNKNOWN:
                throw new Exception("Unknown package manager");
        }
    }

    /**
     * Get direct package update command (no shell wrapper)
     */
    private string[] getDirectUpdateCommand(PackageManager pm) {
        final switch (pm) {
            case PackageManager.PACMAN:
                return ["pacman", "-Syyu", "--noconfirm"];
            case PackageManager.APT:
                return ["apt", "update"];
            case PackageManager.YUM:
                return ["yum", "update", "-y"];
            case PackageManager.DNF:
                return ["dnf", "update", "-y"];
            case PackageManager.ZYPPER:
                return ["zypper", "update", "-y"];
            case PackageManager.UNKNOWN:
                throw new Exception("Unknown package manager");
        }
    }

    /**
     * Get initramfs regeneration commands
     */
    private string[][] getInitramfsCommands(PackageManager pm) {
        final switch (pm) {
            case PackageManager.PACMAN:
                return [
                    ["mkinitcpio", "-P"],
                    ["mkinitcpio", "-p", "linux"]
                ];
            case PackageManager.APT:
                return [
                    ["update-initramfs", "-u", "-k", "all"],
                    ["update-initramfs", "-c", "-k", "all"]
                ];
            case PackageManager.YUM:
            case PackageManager.DNF:
                return [
                    ["dracut", "--regenerate-all", "--force"],
                    ["dracut", "--force"]
                ];
            case PackageManager.ZYPPER:
                return [
                    ["mkinitrd"],
                    ["dracut", "--regenerate-all", "--force"]
                ];
            case PackageManager.UNKNOWN:
                return [
                    ["mkinitcpio", "-P"],  // Try Arch first
                    ["update-initramfs", "-u", "-k", "all"],  // Then Debian
                    ["dracut", "--regenerate-all", "--force"]  // Then Red Hat
                ];
        }
    }

    /**
     * Install missing packages essential for boot
     */
    bool installEssentialPackages(ref SystemInfo sysInfo) {
        Logger.info("Installing essential packages");

        if (!sysInfo.isValidated) {
            Logger.error("System not validated for package installation");
            return false;
        }

        try {
            string[] packages = getEssentialPackages(sysInfo.packageManager);
            string installCommand = getInstallCommand(sysInfo.packageManager, packages);

            auto process = ChrootManager.executeChrootCommand(sysInfo, installCommand);
            auto exitCode = wait(process);

            if (exitCode == 0) {
                ui.printStatus("✓ Essential packages installed");
                return true;
            } else {
                ui.printError("Failed to install essential packages");
                return false;
            }

        } catch (Exception e) {
            Logger.error("Exception installing essential packages: " ~ e.msg);
            return false;
        }
    }

    /**
     * Get list of essential packages for each distribution
     */
    private string[] getEssentialPackages(PackageManager pm) {
        final switch (pm) {
            case PackageManager.PACMAN:
                return ["bash", "coreutils", "linux", "mkinitcpio"];
            case PackageManager.APT:
                return ["bash", "coreutils", "linux-image-generic", "initramfs-tools"];
            case PackageManager.YUM:
            case PackageManager.DNF:
                return ["bash", "coreutils", "kernel", "dracut"];
            case PackageManager.ZYPPER:
                return ["bash", "coreutils", "kernel-default", "mkinitrd"];
            case PackageManager.UNKNOWN:
                return ["bash", "coreutils"];
        }
    }

    /**
     * Get package installation command
     */
    private string getInstallCommand(PackageManager pm, string[] packages) {
        string packageList = packages.join(" ");

        final switch (pm) {
            case PackageManager.PACMAN:
                return "pacman -S --needed --noconfirm " ~ packageList;
            case PackageManager.APT:
                return "apt install -y " ~ packageList;
            case PackageManager.YUM:
                return "yum install -y " ~ packageList;
            case PackageManager.DNF:
                return "dnf install -y " ~ packageList;
            case PackageManager.ZYPPER:
                return "zypper install -y " ~ packageList;
            case PackageManager.UNKNOWN:
                throw new Exception("Unknown package manager");
        }
    }

    /**
     * Detect boot device from root device
     */
    private string detectBootDevice(string rootDevice) {
        try {
            // For NVMe: /dev/nvme0n1p5 -> /dev/nvme0n1
            // For SATA: /dev/sda5 -> /dev/sda
            string bootDevice = rootDevice.replaceAll(regex(r"p?\d+$"), "");

            if (exists(bootDevice)) {
                Logger.debugLog("Detected boot device: " ~ bootDevice);
                return bootDevice;
            }
        } catch (Exception e) {
            Logger.debugLog("Failed to detect boot device: " ~ e.msg);
        }

        return "";
    }

    /**
     * Repair filesystem if needed
     */
    bool repairFilesystem(ref SystemInfo sysInfo) {
        Logger.info("Checking filesystem integrity");

        try {
            string[] checkCommand;

            final switch (sysInfo.filesystemType) {
                case FilesystemType.EXT4:
                case FilesystemType.EXT3:
                case FilesystemType.EXT2:
                    checkCommand = ["e2fsck", "-f", "-y", sysInfo.device];
                    break;
                case FilesystemType.XFS:
                    checkCommand = ["xfs_repair", sysInfo.device];
                    break;
                case FilesystemType.F2FS:
                    checkCommand = ["fsck.f2fs", "-f", sysInfo.device];
                    break;
                case FilesystemType.REISERFS:
                    checkCommand = ["reiserfsck", "--yes", sysInfo.device];
                    break;
                case FilesystemType.BTRFS:
                    ui.printWarning("Btrfs repair should be done manually with 'btrfs check --repair'");
                    return true;
                case FilesystemType.UNKNOWN:
                    ui.printWarning("Unknown filesystem type - skipping repair");
                    return true;
            }

            // Run filesystem check
            ui.printInfo("Running filesystem check: " ~ checkCommand.join(" "));
            auto process = spawnProcess(checkCommand);
            auto exitCode = wait(process);

            if (exitCode == 0) {
                ui.printStatus("✓ Filesystem check passed");
                return true;
            } else {
                ui.printWarning("Filesystem check completed with warnings");
                return true; // Non-zero exit doesn't always mean failure for fsck
            }

        } catch (Exception e) {
            Logger.error("Exception during filesystem repair: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix common permission issues
     */
    bool fixPermissions(ref SystemInfo sysInfo) {
        Logger.info("Fixing common permission issues");

        if (!sysInfo.isValidated) {
            return false;
        }

        try {
            // Fix common permission issues
            string[] permissionFixes = [
                "chmod 755 /usr/bin/*",
                "chmod 755 /bin/* 2>/dev/null || true",
                "chmod 644 /etc/passwd /etc/group",
                "chmod 600 /etc/shadow 2>/dev/null || true",
                "chmod 755 /boot",
                "chmod -R 755 /boot/grub* 2>/dev/null || true"
            ];

            bool anyFailed = false;
            foreach (cmd; permissionFixes) {
                try {
                    auto process = ChrootManager.executeChrootCommand(sysInfo, cmd);
                    wait(process);
                } catch (Exception e) {
                    Logger.debugLog("Permission fix failed: " ~ cmd ~ " - " ~ e.msg);
                    anyFailed = true;
                }
            }

            if (!anyFailed) {
                ui.printStatus("✓ Permission fixes applied");
            } else {
                ui.printWarning("Some permission fixes failed");
            }

            return true;

        } catch (Exception e) {
            Logger.error("Exception fixing permissions: " ~ e.msg);
            return false;
        }
    }

    // Helper function
    private string bootLoaderToString(BootLoader bootloader) {
        final switch (bootloader) {
            case BootLoader.UNKNOWN:     return "Unknown";
            case BootLoader.GRUB:        return "GRUB";
            case BootLoader.REFIND:      return "rEFInd";
            case BootLoader.SYSTEMD_BOOT: return "systemd-boot";
        }
    }
}
