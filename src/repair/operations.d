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
import std.datetime : Clock;
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
            if (updatePackagesUniversal(sysInfo)) {
                result.completedSteps ~= "Package update";
                ui.printStatus("✓ Packages updated successfully");
            } else {
                result.errors ~= "Package update failed";
                result.warnings ~= "Some packages may be out of date";
            }
        }

        // Step 1.5: Fix graphics drivers if needed
        if (config.fixGraphicsDrivers) {
            ui.printInfo("Step 1.5/4: Checking graphics drivers...");
            if (fixGraphicsDrivers(sysInfo)) {
                result.completedSteps ~= "Graphics drivers fixed";
                ui.printStatus("✓ Graphics drivers configured successfully");
            } else {
                result.warnings ~= "Graphics driver configuration may need manual attention";
            }
        }

        // Step 2: Remove Plymouth from GRUB if requested
        if (config.removePlymouthFromGrub) {
            ui.printInfo("Step 2/4: Removing Plymouth from GRUB...");
            if (removePlymouthFromGrub(sysInfo)) {
                result.completedSteps ~= "Plymouth removed from GRUB";
                ui.printStatus("✓ Plymouth removed from GRUB successfully");
            } else {
                result.warnings ~= "Could not remove Plymouth from GRUB";
            }
        }

        // Step 3: Regenerate initramfs
        if (config.regenerateInitramfs) {
            ui.printInfo("Step 3/4: Regenerating initramfs...");
            if (regenerateInitramfs(sysInfo)) {
                result.completedSteps ~= "Initramfs regeneration";
                ui.printStatus("✓ Initramfs regenerated successfully");
            } else {
                result.errors ~= "Initramfs regeneration failed";
                result.warnings ~= "System may not boot properly";
            }
        }

        // Step 4: Fix bootloader
        if (config.fixBootloader) {
            ui.printInfo("Step 4/4: Fixing bootloader...");
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
     * Install GRUB bootloader (public method for menu)
     */
    bool installGrubBootloader(ref SystemInfo sysInfo) {
        Logger.info("Installing GRUB bootloader from menu");
        return installGrubForBtrfs(sysInfo);
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

            // For Btrfs systems, offer to install GRUB as it handles subvolumes better
            if (sysInfo.isBtrfs) {
                ui.printInfo("Btrfs filesystem detected - GRUB handles this better than direct kernel loading");
                string response = ui.promptInput("Install GRUB for better Btrfs support? (recommended) [Y/n]");
                if (response.toLower() != "n" && response.toLower() != "no") {
                    if (installGrubForBtrfs(sysInfo)) {
                        ui.printSuccess("GRUB installed - rEFInd will chainload it");
                        return true;
                    }
                }
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

            // Ensure Btrfs driver is installed if needed
            if (sysInfo.isBtrfs) {
                ensureBtrfsDriver(sysInfo);
            }

            // Always generate proper refind_linux.conf for btrfs systems
            ui.printInfo("Generating rEFInd configuration for btrfs system...");
            // Generate refind_linux.conf configuration
            success = generateRefindLinuxConf(sysInfo);

            // Verify the configuration was actually written correctly
            verifyRefindLinuxConf(sysInfo);

            // Configure rEFInd to scan /boot for kernels
            configureRefindScanPaths(sysInfo, refindLocation);

            // Also create or update manual boot stanza in refind.conf for reliability
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

            // Get the FAT UUID of the boot partition (this is what rEFInd uses for volume)
            // For FAT filesystems, we need the short UUID format (XXXX-XXXX), not a long UUID
            string bootVolumeId = "";

            // Get full blkid output and parse it
            auto blkidResult = executeShell("blkid " ~ bootDevice);
            if (blkidResult.status == 0) {
                string blkidOutput = blkidResult.output;

                // Look for UUID="XXXX-XXXX" pattern (FAT UUID format)
                import std.regex : matchFirst, regex;
                auto uuidMatch = matchFirst(blkidOutput, regex(`UUID="([0-9A-F]{4}-[0-9A-F]{4})"`));
                if (uuidMatch) {
                    bootVolumeId = uuidMatch[1];
                    ui.printInfo("Detected FAT UUID: " ~ bootVolumeId);
                }
            }

            // If no UUID found, try label as fallback
            if (bootVolumeId.length == 0) {
                auto labelResult = executeShell("blkid -s LABEL -o value " ~ bootDevice);
                bootVolumeId = labelResult.status == 0 ? labelResult.output.strip() : "";
                if (bootVolumeId.length > 0) {
                    ui.printInfo("Using volume label: " ~ bootVolumeId);
                }
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
                manualEntry ~= "    loader   /boot/vmlinuz-linux-cachyos\n";
                manualEntry ~= "    initrd   /boot/initramfs-linux-cachyos.img\n";
                manualEntry ~= "    options  \"root=UUID=" ~ sysInfo.uuid ~ " rootflags=subvol=@ rw quiet splash\"\n";
                manualEntry ~= "}\n";

                append(refindConfPath, manualEntry);
                ui.printSuccess("Added manual CachyOS entry to rEFInd");
            } else {
                // Entry exists but might have wrong volume ID - fix it
                ui.printInfo("Checking existing CachyOS entry...");

                // Check if volume ID is wrong
                import std.regex : replaceAll, regex;
                string correctVolumePattern = "volume   " ~ bootVolumeId;

                // Replace any wrong volume ID with the correct one
                auto volumeRegex = regex(`(menuentry "CachyOS Linux"[^}]*volume\s+)[^\n]+`);
                string newContent = replaceAll(refindContent, volumeRegex, "$1" ~ bootVolumeId);

                if (newContent != refindContent) {
                    // Backup and write corrected content
                    copy(refindConfPath, refindConfPath ~ ".bak");
                    write(refindConfPath, newContent);
                    ui.printSuccess("Fixed volume ID in existing CachyOS entry to: " ~ bootVolumeId);
                } else {
                    ui.printInfo("Existing entry has correct volume ID");
                }

                // Also add exclusions to reduce duplicates
                if (refindContent.indexOf("dont_scan_volumes") == -1) {
                    append(refindConfPath, "\n# Hide duplicate entries\n");
                    append(refindConfPath, "dont_scan_volumes " ~ bootVolumeId ~ "\n");
                }
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
        import std.process : executeShell;

        // First check all mounted EFI partitions
        string[] efiMountPoints = [];

        // Check common EFI mount points
        if (exists("/mnt/EFI/refind")) {
            efiMountPoints ~= "/mnt";
        }
        if (exists("/boot/efi/EFI")) {
            efiMountPoints ~= "/boot/efi";
        }
        if (exists(buildPath(sysInfo.mountPoint, "boot/efi/EFI"))) {
            efiMountPoints ~= buildPath(sysInfo.mountPoint, "boot/efi");
        }

        // Try to find Windows EFI partition if mounted
        auto findResult = executeShell("find /mnt* -maxdepth 3 -name refind_x64.efi 2>/dev/null | head -1");
        if (findResult.status == 0 && findResult.output.length > 0) {
            string refindPath = findResult.output.strip();
            if (exists(refindPath)) {
                string location = dirName(refindPath);
                Logger.info("Found rEFInd at: " ~ location);
                ui.printInfo("rEFInd located at: " ~ location);
                return location;
            }
        }

        // Check standard locations in priority order
        string[] possibleLocations = [
            "/mnt/EFI/refind",
            "/mnt/EFI/EFI/refind",
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
     * Fix graphics drivers configuration
     */
    bool fixGraphicsDrivers(ref SystemInfo sysInfo) {
        Logger.info("Starting comprehensive graphics driver fix");
        ui.printInfo("Analyzing graphics hardware and configuration...");

        try {
            // Detect graphics hardware
            GraphicsInfo gfxInfo = detectGraphicsHardware(sysInfo);

            if (gfxInfo.vendor == GraphicsVendor.Unknown) {
                Logger.warning("Could not detect graphics hardware");
                return false;
            }

            ui.printInfo("Detected: " ~ gfxInfo.description);

            // Remove problematic xf86-video drivers
            bool driversRemoved = removeProblematicDrivers(sysInfo, gfxInfo);

            // Check and fix X11 configuration
            bool x11Fixed = fixX11Configuration(sysInfo, gfxInfo);

            // Fix font configuration
            bool fontsFixed = fixFontConfiguration(sysInfo);

            // Fix display manager configuration
            bool displayManagerFixed = fixDisplayManagerConfiguration(sysInfo);

            // Check Plymouth configuration
            bool plymouthFixed = checkPlymouthConfiguration(sysInfo);

            // Ensure proper Mesa drivers are installed
            bool mesaFixed = ensureMesaDrivers(sysInfo, gfxInfo);

            // Check if 'here' universal package manager is available
            bool hereAvailable = checkHereAvailability(sysInfo);

            // Check and fix shell configurations
            bool shellFixed = validateShellConfigurations(sysInfo);

            // Check and fix network connectivity
            bool networkFixed = validateNetworkConfiguration(sysInfo);

            bool overallSuccess = x11Fixed && fontsFixed && mesaFixed;
            if (driversRemoved) ui.printStatus("✓ Removed problematic xf86-video drivers");
            if (displayManagerFixed) ui.printStatus("✓ Display manager configuration updated");
            if (plymouthFixed) ui.printStatus("✓ Plymouth configuration checked");
            if (shellFixed) ui.printStatus("✓ Shell configurations validated");
            if (networkFixed) ui.printStatus("✓ Network configuration validated");
            if (!hereAvailable) ui.printWarning("! 'here' universal package manager not found - using distribution-specific commands");

            return overallSuccess;

        } catch (Exception e) {
            Logger.error("Graphics driver fix failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Detect graphics hardware information
     */
    private GraphicsInfo detectGraphicsHardware(ref SystemInfo sysInfo) {
        import std.process : executeShell;
        import std.algorithm : canFind, startsWith;

        GraphicsInfo info;

        try {
            // Use lspci to detect graphics hardware in chroot
            auto result = ChrootManager.executeInChroot(sysInfo, ["lspci", "-nn"]);

            if (result.status == 0) {
                foreach (line; result.output.split('\n')) {
                    if (line.canFind("VGA") || line.canFind("Display") || line.canFind("3D")) {
                        info.description = line.strip();

                        if (line.canFind("Intel")) {
                            info.vendor = GraphicsVendor.Intel;
                            // Detect specific Intel generations
                            if (line.canFind("Meteor Lake") || line.canFind("Raptor Lake") ||
                                line.canFind("Alder Lake") || line.canFind("Tiger Lake")) {
                                info.useModesetting = true;
                            }
                        } else if (line.canFind("AMD") || line.canFind("ATI")) {
                            info.vendor = GraphicsVendor.AMD;
                            info.useModesetting = true;
                        } else if (line.canFind("NVIDIA")) {
                            info.vendor = GraphicsVendor.NVIDIA;
                        }
                        break;
                    }
                }
            }

            Logger.info("Graphics detection: " ~ info.description);
            return info;

        } catch (Exception e) {
            Logger.error("Failed to detect graphics hardware: " ~ e.msg);
            return info;
        }
    }

    /**
     * Fix X11 configuration for detected graphics hardware
     */
    private bool fixX11Configuration(ref SystemInfo sysInfo, GraphicsInfo gfxInfo) {
        import std.file : write, mkdirRecurse, exists, readText;
        import std.path : buildPath, dirName;

        string xorgConfDir = buildPath(sysInfo.mountPoint, "etc", "X11", "xorg.conf.d");

        try {
            // Ensure xorg.conf.d directory exists
            if (!exists(xorgConfDir)) {
                mkdirRecurse(xorgConfDir);
            }

            string configFile = buildPath(xorgConfDir, "20-graphics.conf");
            string configContent;

            switch (gfxInfo.vendor) {
                case GraphicsVendor.Intel:
                    if (gfxInfo.useModesetting) {
                        // Modern Intel graphics - use modesetting driver
                        configContent = `Section "Device"
    Identifier "Intel Graphics"
    Driver "modesetting"
    Option "AccelMethod" "glamor"
    Option "DRI" "3"
EndSection`;
                        ui.printInfo("Configuring modern Intel graphics with modesetting driver");
                    } else {
                        // Older Intel graphics - use intel driver if available
                        configContent = `Section "Device"
    Identifier "Intel Graphics"
    Driver "intel"
    Option "TearFree" "true"
    Option "AccelMethod" "sna"
    Option "DRI" "3"
EndSection`;
                        ui.printInfo("Configuring older Intel graphics with intel driver");
                    }
                    break;

                case GraphicsVendor.AMD:
                    // AMD graphics - use modesetting driver
                    configContent = `Section "Device"
    Identifier "AMD Graphics"
    Driver "modesetting"
    Option "AccelMethod" "glamor"
    Option "DRI" "3"
    Option "TearFree" "true"
EndSection`;
                    ui.printInfo("Configuring AMD graphics with modesetting driver");
                    break;

                case GraphicsVendor.NVIDIA:
                    // NVIDIA - check if proprietary drivers are installed
                    configContent = `Section "Device"
    Identifier "NVIDIA Graphics"
    Driver "nvidia"
    Option "NoLogo" "true"
EndSection`;
                    ui.printInfo("Configuring NVIDIA graphics (proprietary driver)");
                    break;

                default:
                    // Generic fallback
                    configContent = `Section "Device"
    Identifier "Generic Graphics"
    Driver "modesetting"
    Option "AccelMethod" "glamor"
    Option "DRI" "3"
EndSection`;
                    ui.printInfo("Configuring generic graphics with modesetting driver");
                    break;
            }

            // Remove conflicting configurations
            string[] conflictingFiles = ["20-intel.conf", "20-amd.conf", "20-nvidia.conf"];
            foreach (file; conflictingFiles) {
                string conflictPath = buildPath(xorgConfDir, file);
                if (exists(conflictPath)) {
                    Logger.info("Removing conflicting X11 config: " ~ file);
                    remove(conflictPath);
                }
            }

            // Write new configuration
            write(configFile, configContent);
            Logger.info("Created X11 configuration: " ~ configFile);

            return true;

        } catch (Exception e) {
            Logger.error("Failed to fix X11 configuration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix font configuration to prevent X11 font errors
     */
    private bool fixFontConfiguration(ref SystemInfo sysInfo) {
        import std.process : executeShell;
        import std.file : exists;
        import std.path : buildPath;

        try {
            string[] fontDirs = [
                buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "misc"),
                buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "TTF"),
                buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "OTF"),
                buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "Type1")
            ];

            bool anyFixed = false;

            foreach (fontDir; fontDirs) {
                if (exists(fontDir)) {
                    Logger.info("Generating fonts.dir for: " ~ fontDir);
                    auto result = executeShell("mkfontdir " ~ fontDir);
                    if (result.status == 0) {
                        anyFixed = true;
                    }
                }
            }

            // Update font cache in chroot
            auto result = ChrootManager.executeInChroot(sysInfo, ["fc-cache", "-fv"]);
            if (result.status == 0) {
                anyFixed = true;
                Logger.info("Font cache updated successfully");
            }

            return anyFixed;

        } catch (Exception e) {
            Logger.error("Failed to fix font configuration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Ensure proper Mesa drivers are installed
     */
    private bool ensureMesaDrivers(ref SystemInfo sysInfo, GraphicsInfo gfxInfo) {
        try {
            string[] packagesToCheck;

            switch (gfxInfo.vendor) {
                case GraphicsVendor.Intel:
                    packagesToCheck = ["mesa", "libva-intel-driver", "intel-media-driver"];
                    break;
                case GraphicsVendor.AMD:
                    packagesToCheck = ["mesa", "libva-mesa-driver", "mesa-vdpau"];
                    break;
                default:
                    packagesToCheck = ["mesa"];
                    break;
            }

            bool allPresent = true;
            foreach (pkg; packagesToCheck) {
                auto result = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", pkg]);
                if (result.status != 0) {
                    Logger.warning("Mesa driver package not installed: " ~ pkg);
                    allPresent = false;
                }
            }

            if (allPresent) {
                ui.printStatus("✓ Mesa drivers are properly installed");
            } else {
                ui.printWarning("! Some Mesa driver packages may be missing");
                ui.printInfo("  Consider installing: " ~ packagesToCheck.join(" "));
            }

            return true; // Don't fail repair for this

        } catch (Exception e) {
            Logger.error("Failed to check Mesa drivers: " ~ e.msg);
            return false;
        }
    }

    /**
     * Remove problematic xf86-video drivers that conflict with modesetting
     */
    private bool removeProblematicDrivers(ref SystemInfo sysInfo, GraphicsInfo gfxInfo) {
        try {
            string[] problematicDrivers;

            switch (gfxInfo.vendor) {
                case GraphicsVendor.Intel:
                    // Modern Intel graphics should use modesetting, not xf86-video-intel
                    if (gfxInfo.useModesetting) {
                        problematicDrivers = ["xf86-video-intel"];
                    }
                    break;
                case GraphicsVendor.AMD:
                    // Modern AMD graphics should use modesetting, not legacy drivers
                    problematicDrivers = ["xf86-video-ati", "xf86-video-radeon"];
                    break;
                default:
                    break;
            }

            bool anyRemoved = false;
            foreach (driver; problematicDrivers) {
                auto checkResult = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", driver]);
                if (checkResult.status == 0) {
                    Logger.info("Found problematic driver: " ~ driver);
                    ui.printWarning("! Removing problematic driver: " ~ driver);

                    auto removeResult = ChrootManager.executeInChroot(sysInfo,
                        ["pacman", "-Rns", "--noconfirm", driver]);

                    if (removeResult.status == 0) {
                        Logger.info("Successfully removed: " ~ driver);
                        anyRemoved = true;
                    } else {
                        Logger.warning("Failed to remove " ~ driver ~ ": " ~ removeResult.output);
                    }
                }
            }

            return anyRemoved;

        } catch (Exception e) {
            Logger.error("Failed to remove problematic drivers: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix display manager configuration (LightDM, SDDM, GDM)
     */
    private bool fixDisplayManagerConfiguration(ref SystemInfo sysInfo) {
        ui.printInfo("Detecting and configuring display manager...");

        // Detect which display manager is installed/enabled
        string activeDisplayManager = detectDisplayManager(sysInfo);

        if (activeDisplayManager.empty) {
            ui.printWarning("! No display manager detected");
            return offerDisplayManagerInstallation(sysInfo);
        }

        ui.printInfo("Detected display manager: " ~ activeDisplayManager);

        switch (activeDisplayManager) {
            case "lightdm":
                return fixLightDMConfiguration(sysInfo);
            case "sddm":
                return fixSDDMConfiguration(sysInfo);
            case "gdm":
                return fixGDMConfiguration(sysInfo);
            default:
                ui.printWarning("! Unsupported display manager: " ~ activeDisplayManager);
                return false;
        }
    }

    /**
     * Detect which display manager is active
     */
    private string detectDisplayManager(ref SystemInfo sysInfo) {
        string[] displayManagers = ["sddm", "lightdm", "gdm"];

        foreach (dm; displayManagers) {
            // Check if service is enabled
            auto result = ChrootManager.executeInChroot(sysInfo, ["systemctl", "is-enabled", dm ~ ".service"]);
            if (result.status == 0 && result.output.strip() == "enabled") {
                return dm;
            }
        }

        // Fall back to checking if packages are installed
        foreach (dm; displayManagers) {
            auto result = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", dm]);
            if (result.status == 0) {
                return dm;
            }
        }

        return "";
    }

    /**
     * Offer to install a display manager
     */
    private bool offerDisplayManagerInstallation(ref SystemInfo sysInfo) {
        ui.printInfo("No display manager found. Would you like to install one?");

        MenuOption[] dmOptions = [
            MenuOption("SDDM", "Modern Qt-based display manager (recommended for KDE/modern systems)", true),
            MenuOption("LightDM", "Lightweight display manager (good for XFCE/lightweight DEs)", true),
            MenuOption("GDM", "GNOME display manager (recommended for GNOME)", true),
            MenuOption("Skip", "Skip display manager installation", true)
        ];

        int choice = ui.showMenu(dmOptions);
        string selectedDM = "";

        switch (choice) {
            case 0: selectedDM = "sddm"; break;
            case 1: selectedDM = "lightdm lightdm-gtk-greeter"; break;
            case 2: selectedDM = "gdm"; break;
            default: return false;
        }

        ui.printInfo("Installing " ~ selectedDM ~ "...");
        string[] packages = selectedDM.split();
        bool installSuccess = true;

        foreach (pkg; packages) {
            if (!installPackageUniversal(sysInfo, pkg)) {
                installSuccess = false;
                break;
            }
        }

        auto result = CommandResult();
        result.status = installSuccess ? 0 : 1;

        if (result.status == 0) {
            // Enable the service
            string serviceName = selectedDM.split()[0] ~ ".service";
            ChrootManager.executeInChroot(sysInfo, ["systemctl", "enable", serviceName]);
            ui.printStatus("✓ " ~ selectedDM.split()[0] ~ " installed and enabled");
            return true;
        } else {
            ui.printError("Failed to install " ~ selectedDM);
            return false;
        }
    }

    /**
     * Fix GDM configuration
     */
    private bool fixGDMConfiguration(ref SystemInfo sysInfo) {
        try {
            string gdmConf = buildPath(sysInfo.mountPoint, "etc", "gdm", "custom.conf");

            if (!exists(gdmConf)) {
                Logger.warning("GDM configuration not found: " ~ gdmConf);
                return false;
            }

            string content = readText(gdmConf);
            string originalContent = content;
            bool modified = false;

            // Ensure Wayland is disabled if having X11 issues
            if (content.indexOf("WaylandEnable") == -1) {
                auto daemonSection = content.indexOf("[daemon]");
                if (daemonSection == -1) {
                    content ~= "\n[daemon]\nWaylandEnable=false\n";
                } else {
                    auto nextSection = content.indexOf("[", daemonSection + 1);
                    string insertion = "WaylandEnable=false\n";

                    if (nextSection != -1) {
                        content = content[0..nextSection] ~ insertion ~ content[nextSection..$];
                    } else {
                        content ~= insertion;
                    }
                }
                modified = true;
                Logger.info("Disabled Wayland in GDM for X11 compatibility");
            }

            if (modified) {
                write(gdmConf, content);
                Logger.info("Updated GDM configuration");
                return true;
            }

            return false;

        } catch (Exception e) {
            Logger.error("Failed to fix GDM configuration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix SDDM configuration
     */
    private bool fixSDDMConfiguration(ref SystemInfo sysInfo) {
        import std.file : write, mkdirRecurse;

        try {
            string sddmConfDir = buildPath(sysInfo.mountPoint, "etc", "sddm.conf.d");
            string configFile = buildPath(sddmConfDir, "debork-fix.conf");

            if (!exists(sddmConfDir)) {
                mkdirRecurse(sddmConfDir);
            }

            string sddmConfig = `[General]
# Debork graphics fix - ensure proper session detection
DisplayServer=x11

[Theme]
# Use default theme to avoid theme-related crashes
Current=

[X11]
# Ensure proper X11 server arguments
ServerArguments=-nolisten tcp

[Wayland]
# Wayland session configuration
SessionDir=/usr/share/wayland-sessions

[Users]
# Allow all users
MaximumUid=65000
MinimumUid=1000
`;

            write(configFile, sddmConfig);
            Logger.info("Created SDDM configuration: " ~ configFile);
            ui.printStatus("✓ SDDM configuration updated");
            return true;

        } catch (Exception e) {
            Logger.error("Failed to configure SDDM: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix LightDM configuration
     */
    private bool fixLightDMConfiguration(ref SystemInfo sysInfo) {
        import std.file : exists, readText, write;
        import std.string : indexOf, replace;

        try {
            string lightdmConf = buildPath(sysInfo.mountPoint, "etc", "lightdm", "lightdm.conf");

            if (!exists(lightdmConf)) {
                Logger.warning("LightDM configuration not found: " ~ lightdmConf);
                return false;
            }

            string content = readText(lightdmConf);
            string originalContent = content;
            bool modified = false;

            // Ensure greeter-session is properly set
            if (content.indexOf("greeter-session=") == -1 &&
                content.indexOf("greeter-session =") == -1) {

                // Add greeter session configuration
                auto seatDefault = content.indexOf("[Seat:*]");
                if (seatDefault != -1) {
                    auto nextSection = content.indexOf("[", seatDefault + 1);
                    string insertion = "\ngreeter-session=lightdm-gtk-greeter\n";

                    if (nextSection != -1) {
                        content = content[0..nextSection] ~ insertion ~ content[nextSection..$];
                    } else {
                        content ~= insertion;
                    }
                    modified = true;
                    Logger.info("Added greeter-session configuration");
                }
            }

            // Fix any session timeout issues
            if (content.indexOf("greeter-timeout=") == -1) {
                auto seatDefault = content.indexOf("[Seat:*]");
                if (seatDefault != -1) {
                    auto nextSection = content.indexOf("[", seatDefault + 1);
                    string insertion = "greeter-timeout=30\n";

                    if (nextSection != -1) {
                        content = content[0..nextSection] ~ insertion ~ content[nextSection..$];
                    } else {
                        content ~= insertion;
                    }
                    modified = true;
                    Logger.info("Added greeter timeout configuration");
                }
            }

            if (modified) {
                write(lightdmConf, content);
                Logger.info("Updated LightDM configuration");
                return true;
            }

            return false;

        } catch (Exception e) {
            Logger.error("Failed to fix LightDM greeter configuration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Check Plymouth configuration for conflicts
     */
    private bool checkPlymouthConfiguration(ref SystemInfo sysInfo) {
        try {
            // Check if Plymouth is installed
            auto plymouthCheck = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", "plymouth"]);

            if (plymouthCheck.status != 0) {
                Logger.info("Plymouth not installed - no conflicts");
                return true;
            }

            ui.printInfo("Plymouth detected - checking configuration...");

            // Check current theme
            auto themeCheck = ChrootManager.executeInChroot(sysInfo, ["plymouth-set-default-theme"]);
            if (themeCheck.status == 0) {
                Logger.info("Plymouth theme: " ~ themeCheck.output.strip());
            }

            // Check if plymouth is in initramfs hooks
            string mkinitcpioConf = buildPath(sysInfo.mountPoint, "etc", "mkinitcpio.conf");
            if (exists(mkinitcpioConf)) {
                string content = readText(mkinitcpioConf);
                if (content.indexOf("plymouth") != -1) {
                    ui.printInfo("Plymouth is properly integrated in initramfs");
                } else {
                    ui.printWarning("Plymouth may not be properly integrated in initramfs");
                    ui.printInfo("Consider adding 'plymouth' to HOOKS in /etc/mkinitcpio.conf");
                }
            }

            // Plymouth itself rarely causes X11 issues, but log for reference
            Logger.info("Plymouth configuration checked");
            return true;

        } catch (Exception e) {
            Logger.error("Failed to check Plymouth configuration: " ~ e.msg);
            return false;
        }
    }


    /**
     * Diagnose graphics and display issues
     */
    void diagnoseGraphicsIssues(ref SystemInfo sysInfo) {
        ui.printHeader();
        ui.printInfo("Diagnosing graphics and display configuration...");

        try {
            // Detect graphics hardware
            GraphicsInfo gfxInfo = detectGraphicsHardware(sysInfo);

            ui.printInfo("=== Graphics Hardware ===");
            if (gfxInfo.vendor != GraphicsVendor.Unknown) {
                ui.printStatus("✓ " ~ gfxInfo.description);
            } else {
                ui.printWarning("! Could not detect graphics hardware");
            }

            // Check X11 configuration
            ui.printInfo("\n=== X11 Configuration ===");
            diagnoseX11Config(sysInfo, gfxInfo);

            // Check problematic drivers
            ui.printInfo("\n=== Driver Conflicts ===");
            diagnoseDriverConflicts(sysInfo, gfxInfo);

            // Check fonts
            ui.printInfo("\n=== Font Configuration ===");
            diagnoseFonts(sysInfo);

            // Check LightDM
            ui.printInfo("\n=== Display Manager ===");
            diagnoseLightDM(sysInfo);

            // Check Plymouth
            ui.printInfo("\n=== Boot Splash ===");
            diagnosePlymouth(sysInfo);

            // Check Mesa
            ui.printInfo("\n=== Mesa Drivers ===");
            diagnoseMesa(sysInfo, gfxInfo);

        } catch (Exception e) {
            Logger.error("Graphics diagnostics failed: " ~ e.msg);
            ui.printError("Diagnostics failed: " ~ e.msg);
        }

        ui.printInfo("\nPress any key to continue...");
        ui.waitForKey();
    }

    /**
     * Diagnose X11 configuration issues
     */
    private void diagnoseX11Config(ref SystemInfo sysInfo, GraphicsInfo gfxInfo) {
        import std.file : exists, readText, dirEntries, SpanMode;

        string xorgConfDir = buildPath(sysInfo.mountPoint, "etc", "X11", "xorg.conf.d");

        if (!exists(xorgConfDir)) {
            ui.printWarning("! No X11 configuration directory found");
            return;
        }

        bool foundGraphicsConfig = false;
        try {
            foreach (entry; dirEntries(xorgConfDir, SpanMode.shallow)) {
                if (entry.name.endsWith(".conf")) {
                    string content = readText(entry.name);
                    if (content.indexOf("Device") != -1 && content.indexOf("Driver") != -1) {
                        foundGraphicsConfig = true;
                        string filename = baseName(entry.name);
                        ui.printInfo("  Found config: " ~ filename);

                        // Check for problematic drivers
                        if (content.indexOf(`Driver "intel"`) != -1 && gfxInfo.useModesetting) {
                            ui.printWarning("  ! Using legacy intel driver for modern hardware");
                        } else if (content.indexOf(`Driver "modesetting"`) != -1) {
                            ui.printStatus("  ✓ Using modern modesetting driver");
                        }
                    }
                }
            }

            if (!foundGraphicsConfig) {
                ui.printWarning("! No graphics driver configuration found");
            }

        } catch (Exception e) {
            ui.printError("Could not read X11 configuration: " ~ e.msg);
        }
    }

    /**
     * Diagnose driver conflicts
     */
    private void diagnoseDriverConflicts(ref SystemInfo sysInfo, GraphicsInfo gfxInfo) {
        string[] conflictingPackages;

        switch (gfxInfo.vendor) {
            case GraphicsVendor.Intel:
                if (gfxInfo.useModesetting) {
                    conflictingPackages = ["xf86-video-intel"];
                }
                break;
            case GraphicsVendor.AMD:
                conflictingPackages = ["xf86-video-ati", "xf86-video-radeon"];
                break;
            default:
                break;
        }

        bool foundConflicts = false;
        foreach (pkg; conflictingPackages) {
            auto result = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", pkg]);
            if (result.status == 0) {
                ui.printWarning("! Conflicting driver installed: " ~ pkg);
                foundConflicts = true;
            }
        }

        if (!foundConflicts) {
            ui.printStatus("✓ No conflicting drivers detected");
        }
    }

    /**
     * Diagnose font configuration
     */
    private void diagnoseFonts(ref SystemInfo sysInfo) {
        string[] fontDirs = [
            buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "misc"),
            buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "TTF"),
            buildPath(sysInfo.mountPoint, "usr", "share", "fonts", "OTF")
        ];

        bool allGood = true;
        foreach (fontDir; fontDirs) {
            if (exists(fontDir)) {
                string fontsDir = buildPath(fontDir, "fonts.dir");
                if (exists(fontsDir)) {
                    ui.printStatus("✓ " ~ baseName(fontDir) ~ " has fonts.dir");
                } else {
                    ui.printWarning("! " ~ baseName(fontDir) ~ " missing fonts.dir");
                    allGood = false;
                }
            }
        }

        if (allGood) {
            ui.printStatus("✓ Font configuration looks good");
        }
    }

    /**
     * Diagnose LightDM configuration
     */
    private void diagnoseLightDM(ref SystemInfo sysInfo) {
        string lightdmConf = buildPath(sysInfo.mountPoint, "etc", "lightdm", "lightdm.conf");

        if (!exists(lightdmConf)) {
            ui.printWarning("! LightDM configuration not found");
            return;
        }

        try {
            string content = readText(lightdmConf);

            if (content.indexOf("greeter-session") != -1) {
                ui.printStatus("✓ Greeter session configured");
            } else {
                ui.printWarning("! No greeter session configured");
            }

            // Check if greeter packages are installed
            string[] greeters = ["lightdm-gtk-greeter", "lightdm-slick-greeter"];
            bool foundGreeter = false;
            foreach (greeter; greeters) {
                auto result = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", greeter]);
                if (result.status == 0) {
                    ui.printStatus("✓ " ~ greeter ~ " installed");
                    foundGreeter = true;
                }
            }

            if (!foundGreeter) {
                ui.printWarning("! No LightDM greeter packages found");
            }

        } catch (Exception e) {
            ui.printError("Could not read LightDM config: " ~ e.msg);
        }
    }

    /**
     * Diagnose Plymouth configuration
     */
    private void diagnosePlymouth(ref SystemInfo sysInfo) {
        auto plymouthCheck = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", "plymouth"]);

        if (plymouthCheck.status != 0) {
            ui.printInfo("  Plymouth not installed");
            return;
        }

        ui.printStatus("✓ Plymouth installed");

        auto themeCheck = ChrootManager.executeInChroot(sysInfo, ["plymouth-set-default-theme"]);
        if (themeCheck.status == 0) {
            ui.printInfo("  Theme: " ~ themeCheck.output.strip());
        }
    }

    /**
     * Diagnose Mesa drivers
     */
    private void diagnoseMesa(ref SystemInfo sysInfo, GraphicsInfo gfxInfo) {
        string[] expectedPackages = ["mesa"];

        switch (gfxInfo.vendor) {
            case GraphicsVendor.Intel:
                expectedPackages ~= ["libva-intel-driver", "intel-media-driver"];
                break;
            case GraphicsVendor.AMD:
                expectedPackages ~= ["libva-mesa-driver", "mesa-vdpau"];
                break;
            default:
                break;
        }

        foreach (pkg; expectedPackages) {
            auto result = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Q", pkg]);
            if (result.status == 0) {
                ui.printStatus("✓ " ~ pkg ~ " installed");
            } else {
                ui.printWarning("! " ~ pkg ~ " not installed");
            }
        }
    }

    /**
     * Validate and fix shell configurations that can silently brick systems
     */
    bool validateShellConfigurations(ref SystemInfo sysInfo) {
        ui.printInfo("Checking shell configurations for syntax errors...");

        try {
            bool anyFixed = false;
            string[] users = getUserList(sysInfo);

            // Check system-wide shell configs
            anyFixed |= validateSystemShellConfigs(sysInfo);

            // Check user shell configs
            foreach (user; users) {
                anyFixed |= validateUserShellConfigs(sysInfo, user);
            }

            return anyFixed;

        } catch (Exception e) {
            Logger.error("Shell configuration validation failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Get list of users to check shell configs for
     */
    private string[] getUserList(ref SystemInfo sysInfo) {
        import std.algorithm : filter, map;
        import std.array : array;
        import std.string : split;

        string[] users;

        try {
            string passwdPath = buildPath(sysInfo.mountPoint, "etc", "passwd");
            if (!exists(passwdPath)) return users;

            string content = readText(passwdPath);
            foreach (line; content.split('\n')) {
                if (line.length == 0 || line.startsWith("#")) continue;

                string[] fields = line.split(':');
                if (fields.length >= 7) {
                    string username = fields[0];
                    string shell = fields[6];
                    int uid = fields[2].to!int;

                    // Only check regular users (UID >= 1000) and root
                    if ((uid >= 1000 && uid < 65534) || uid == 0) {
                        if (shell.endsWith("bash") || shell.endsWith("zsh") ||
                            shell.endsWith("fish") || shell.endsWith("sh")) {
                            users ~= username;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Logger.error("Failed to get user list: " ~ e.msg);
        }

        return users;
    }

    /**
     * Validate system-wide shell configurations
     */
    private bool validateSystemShellConfigs(ref SystemInfo sysInfo) {
        bool anyFixed = false;

        string[] systemConfigs = [
            "/etc/bash.bashrc",
            "/etc/zsh/zshrc",
            "/etc/fish/config.fish",
            "/etc/profile"
        ];

        foreach (configPath; systemConfigs) {
            string fullPath = buildPath(sysInfo.mountPoint, configPath[1..$]); // Remove leading /
            if (exists(fullPath)) {
                if (validateSingleShellConfig(sysInfo, configPath, "system")) {
                    anyFixed = true;
                }
            }
        }

        return anyFixed;
    }

    /**
     * Validate user shell configurations
     */
    private bool validateUserShellConfigs(ref SystemInfo sysInfo, string username) {
        bool anyFixed = false;

        string homeDir = "/home/" ~ username;
        if (username == "root") homeDir = "/root";

        string[] userConfigs = [
            "/.bashrc",
            "/.bash_profile",
            "/.zshrc",
            "/.config/fish/config.fish",
            "/.profile"
        ];

        foreach (configFile; userConfigs) {
            string configPath = homeDir ~ configFile;
            string fullPath = buildPath(sysInfo.mountPoint, configPath[1..$]); // Remove leading /

            if (exists(fullPath)) {
                if (validateSingleShellConfig(sysInfo, configPath, username)) {
                    anyFixed = true;
                }
            }
        }

        return anyFixed;
    }

    /**
     * Validate a single shell configuration file
     */
    private bool validateSingleShellConfig(ref SystemInfo sysInfo, string configPath, string owner) {
        import std.file : copy, readText;
        import std.path : baseName, extension;

        try {
            string fullPath = buildPath(sysInfo.mountPoint, configPath[1..$]);
            string content = readText(fullPath);

            // Detect shell type from path
            string shellType = "bash"; // default
            if (configPath.indexOf("zsh") != -1) shellType = "zsh";
            else if (configPath.indexOf("fish") != -1) shellType = "fish";

            // Basic syntax validation
            bool hasErrors = false;
            string[] errors;

            // Check for common syntax errors
            if (shellType == "bash" || shellType == "zsh") {
                hasErrors |= checkBashZshSyntax(content, configPath, errors);
            } else if (shellType == "fish") {
                hasErrors |= checkFishSyntax(content, configPath, errors);
            }

            if (hasErrors) {
                ui.printWarning("! Syntax errors found in " ~ configPath ~ " (owner: " ~ owner ~ ")");
                foreach (error; errors) {
                    ui.printInfo("  " ~ error);
                }

                // Create backup
                string backupPath = fullPath ~ ".debork-backup-" ~
                                   Clock.currTime().toISOExtString()[0..19].replace(":", "-");
                copy(fullPath, backupPath);
                ui.printInfo("  Created backup: " ~ backupPath);

                // Offer to fix or disable
                return offerShellConfigFix(sysInfo, fullPath, configPath, content, shellType);
            }

            return false;

        } catch (Exception e) {
            Logger.error("Failed to validate " ~ configPath ~ ": " ~ e.msg);
            return false;
        }
    }

    /**
     * Check bash/zsh syntax for common errors
     */
    private bool checkBashZshSyntax(string content, string configPath, ref string[] errors) {
        import std.string : split, strip, indexOf;

        bool hasErrors = false;
        string[] lines = content.split('\n');

        for (int i = 0; i < lines.length; i++) {
            string line = lines[i].strip();
            if (line.length == 0 || line.startsWith("#")) continue;

            // Check for unmatched quotes
            int singleQuotes = 0, doubleQuotes = 0;
            bool inSingle = false, inDouble = false;

            for (int j = 0; j < line.length; j++) {
                char c = line[j];
                if (c == '\'' && !inDouble) {
                    inSingle = !inSingle;
                    singleQuotes++;
                }
                else if (c == '"' && !inSingle) {
                    inDouble = !inDouble;
                    doubleQuotes++;
                }
            }

            if (singleQuotes % 2 != 0) {
                errors ~= "Line " ~ (i+1).to!string ~ ": Unmatched single quote";
                hasErrors = true;
            }
            if (doubleQuotes % 2 != 0) {
                errors ~= "Line " ~ (i+1).to!string ~ ": Unmatched double quote";
                hasErrors = true;
            }

            // Check for unmatched brackets/braces
            if (line.indexOf("[") != -1 && line.indexOf("]") == -1) {
                errors ~= "Line " ~ (i+1).to!string ~ ": Unmatched square bracket";
                hasErrors = true;
            }

            // Check for dangerous commands without proper checks
            if (line.indexOf("rm -rf") != -1 && line.indexOf("$") != -1) {
                errors ~= "Line " ~ (i+1).to!string ~ ": Potentially dangerous rm command with variables";
                hasErrors = true;
            }
        }

        return hasErrors;
    }

    /**
     * Check fish syntax for common errors
     */
    private bool checkFishSyntax(string content, string configPath, ref string[] errors) {
        import std.string : split, strip, indexOf;

        bool hasErrors = false;
        string[] lines = content.split('\n');

        for (int i = 0; i < lines.length; i++) {
            string line = lines[i].strip();
            if (line.length == 0 || line.startsWith("#")) continue;

            // Fish-specific syntax checks
            if (line.startsWith("function") && !line.endsWith(";")) {
                if (i + 1 < lines.length && !lines[i + 1].strip().startsWith("end")) {
                    errors ~= "Line " ~ (i+1).to!string ~ ": Function missing 'end'";
                    hasErrors = true;
                }
            }

            if (line.startsWith("if") && !line.endsWith(";")) {
                // Look for matching 'end'
                bool foundEnd = false;
                for (int j = i + 1; j < lines.length; j++) {
                    if (lines[j].strip() == "end") {
                        foundEnd = true;
                        break;
                    }
                }
                if (!foundEnd) {
                    errors ~= "Line " ~ (i+1).to!string ~ ": If statement missing 'end'";
                    hasErrors = true;
                }
            }
        }

        return hasErrors;
    }

    /**
     * Offer to fix shell configuration issues
     */
    private bool offerShellConfigFix(ref SystemInfo sysInfo, string fullPath, string configPath,
                                   string content, string shellType) {
        MenuOption[] fixOptions = [
            MenuOption("Comment out problematic lines", "Add # to disable problematic lines", true),
            MenuOption("Create minimal safe config", "Replace with basic safe configuration", true),
            MenuOption("Rename to .disabled", "Disable the config file entirely", true),
            MenuOption("Skip", "Leave as-is (may cause login issues)", true)
        ];

        ui.printInfo("How would you like to handle this configuration?");
        int choice = ui.showMenu(fixOptions);

        try {
            switch (choice) {
                case 0: // Comment out problematic lines
                    return commentOutProblematicLines(fullPath, content);

                case 1: // Create minimal safe config
                    return createMinimalSafeConfig(fullPath, shellType);

                case 2: // Rename to disabled
                    import std.file : rename;
                    rename(fullPath, fullPath ~ ".disabled");
                    ui.printStatus("✓ Disabled configuration file");
                    return true;

                default: // Skip
                    return false;
            }
        } catch (Exception e) {
            Logger.error("Failed to fix shell config: " ~ e.msg);
            return false;
        }
    }

    /**
     * Comment out lines that cause syntax errors
     */
    private bool commentOutProblematicLines(string fullPath, string content) {
        import std.string : split, indexOf;
        import std.array : join;
        import std.file : write;

        string[] lines = content.split('\n');
        bool modified = false;

        for (int i = 0; i < lines.length; i++) {
            string line = lines[i];

            // Comment out lines with obvious syntax issues
            if (line.indexOf("rm -rf") != -1 && line.indexOf("$") != -1) {
                lines[i] = "# DEBORK: Commented out potentially dangerous command: " ~ line;
                modified = true;
            }
            // Add more problematic pattern checks here
        }

        if (modified) {
            write(fullPath, lines.join('\n'));
            ui.printStatus("✓ Commented out problematic lines");
            return true;
        }

        return false;
    }

    /**
     * Create a minimal safe shell configuration
     */
    private bool createMinimalSafeConfig(string fullPath, string shellType) {
        import std.file : write;

        string safeConfig = "";

        switch (shellType) {
            case "bash":
                safeConfig = `# Safe minimal bash configuration created by debork
# Original file backed up with .debork-backup suffix

# Basic settings
export EDITOR=nano
export PAGER=less

# Safe aliases
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Basic prompt
PS1='\u@\h:\w\$ '
`;
                break;

            case "zsh":
                safeConfig = `# Safe minimal zsh configuration created by debork
# Original file backed up with .debork-backup suffix

# Basic settings
export EDITOR=nano
export PAGER=less

# Safe aliases
alias ls='ls --color=auto'
alias ll='ls -alF'

# Basic prompt
PROMPT='%n@%m:%~%# '
`;
                break;

            case "fish":
                safeConfig = `# Safe minimal fish configuration created by debork
# Original file backed up with .debork-backup suffix

# Basic settings
set -x EDITOR nano
set -x PAGER less

# Safe aliases
alias ls='ls --color=auto'
alias ll='ls -alF'
`;
                break;

            default:
                safeConfig = `# Safe minimal shell configuration created by debork
# Original file backed up with .debork-backup suffix

export EDITOR=nano
export PAGER=less
`;
                break;
        }

        write(fullPath, safeConfig);
        ui.printStatus("✓ Created minimal safe configuration");
        return true;
    }

    /**
     * Remove Plymouth from GRUB configuration
     */
    bool removePlymouthFromGrub(ref SystemInfo sysInfo) {
        ui.printInfo("Removing Plymouth splash from GRUB configuration...");

        try {
            string grubDefault = buildPath(sysInfo.mountPoint, "etc", "default", "grub");

            if (!exists(grubDefault)) {
                ui.printWarning("! GRUB default configuration not found");
                return false;
            }

            string content = readText(grubDefault);
            string originalContent = content;
            bool modified = false;

            // Remove splash parameter from GRUB_CMDLINE_LINUX_DEFAULT
            if (content.indexOf("splash") != -1) {
                import std.regex;

                // Remove 'splash' from GRUB_CMDLINE_LINUX_DEFAULT
                auto splashRegex = regex(r'GRUB_CMDLINE_LINUX_DEFAULT="([^"]*)\bsplash\b([^"]*)"');
                content = content.replaceAll(splashRegex, `GRUB_CMDLINE_LINUX_DEFAULT="$1$2"`);

                // Clean up double spaces
                content = content.replaceAll(regex(r'="([^"]*)\s+([^"]*)"'), `="$1 $2"`);
                content = content.replaceAll(regex(r'="([^"]*)\s+"'), `="$1"`);
                content = content.replaceAll(regex(r'="\s+([^"]*)"'), `="$1"`);

                modified = true;
                Logger.info("Removed splash parameter from GRUB configuration");
            }

            // Remove quiet parameter if user wants
            if (content.indexOf("quiet") != -1) {
                ui.printInfo("Also remove 'quiet' parameter? (shows boot messages)");
                MenuOption[] options = [
                    MenuOption("Yes", "Remove quiet parameter to show boot messages", true),
                    MenuOption("No", "Keep quiet parameter", true)
                ];

                int choice = ui.showMenu(options);
                if (choice == 0) {
                    auto quietRegex = regex(r'GRUB_CMDLINE_LINUX_DEFAULT="([^"]*)\bquiet\b([^"]*)"');
                    content = content.replaceAll(quietRegex, `GRUB_CMDLINE_LINUX_DEFAULT="$1$2"`);

                    // Clean up double spaces again
                    content = content.replaceAll(regex(r'="([^"]*)\s+([^"]*)"'), `="$1 $2"`);
                    content = content.replaceAll(regex(r'="([^"]*)\s+"'), `="$1"`);
                    content = content.replaceAll(regex(r'="\s+([^"]*)"'), `="$1"`);

                    modified = true;
                    Logger.info("Removed quiet parameter from GRUB configuration");
                }
            }

            if (modified) {
                write(grubDefault, content);
                ui.printStatus("✓ Updated GRUB configuration");

                // Regenerate GRUB configuration
                auto result = ChrootManager.executeInChroot(sysInfo, ["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]);
                if (result.status == 0) {
                    ui.printStatus("✓ GRUB configuration regenerated");
                    return true;
                } else {
                    ui.printWarning("! GRUB configuration updated but regeneration failed");
                    ui.printInfo("  You may need to run: grub-mkconfig -o /boot/grub/grub.cfg");
                    return true; // Still count as success since we modified the config
                }
            } else {
                ui.printInfo("No Plymouth parameters found in GRUB configuration");
                return true;
            }

        } catch (Exception e) {
            Logger.error("Failed to remove Plymouth from GRUB: " ~ e.msg);
            return false;
        }
    }

    /**
     * Diagnose critical system issues (diagnostic only - safe)
     */
    bool diagnoseCriticalSystemIssues(ref SystemInfo sysInfo) {
        ui.printInfo("Diagnosing critical system issues...");

        bool anyIssuesFound = false;

        try {
            // Diagnose package database
            anyIssuesFound |= diagnosePackageDatabase(sysInfo);

            // Diagnose critical system services
            anyIssuesFound |= diagnoseCriticalServices(sysInfo);

            // Diagnose filesystem issues
            anyIssuesFound |= diagnoseFilesystemIssues(sysInfo);

            // Diagnose broken symlinks in critical paths
            anyIssuesFound |= diagnoseCriticalSymlinks(sysInfo);

            // Diagnose /tmp and /var permissions
            anyIssuesFound |= diagnoseCriticalDirectoryPermissions(sysInfo);

            if (anyIssuesFound) {
                ui.printWarning("! Issues found - manual intervention may be required");
            } else {
                ui.printStatus("✓ No critical system issues detected");
            }

            return anyIssuesFound;

        } catch (Exception e) {
            Logger.error("Critical system diagnosis failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Diagnose package database issues (diagnostic only)
     */
    private bool diagnosePackageDatabase(ref SystemInfo sysInfo) {
        ui.printInfo("Checking package database integrity...");

        try {
            bool issuesFound = false;

            // Check pacman database
            if (sysInfo.packageManager == PackageManager.PACMAN) {
                auto result = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Dk"]);
                if (result.status != 0) {
                    ui.printWarning("! Pacman database corruption detected");
                    ui.printInfo("  Manual fix: Run 'pacman-db-upgrade' and 'here update'");
                    issuesFound = true;
                } else {
                    ui.printStatus("✓ Pacman database is healthy");
                }
            }

            return issuesFound;

        } catch (Exception e) {
            Logger.error("Package database diagnosis failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Diagnose critical system services
     */
    private bool diagnoseCriticalServices(ref SystemInfo sysInfo) {
        ui.printInfo("Checking critical system services...");

        try {
            bool issuesFound = false;

            string[] criticalServices = [
                "systemd-logind.service",
                "dbus.service",
                "systemd-resolved.service"
            ];

            foreach (service; criticalServices) {
                auto statusResult = ChrootManager.executeInChroot(sysInfo,
                    ["systemctl", "is-enabled", service]);

                if (statusResult.output.strip() == "masked") {
                    ui.printWarning("! Critical service is masked: " ~ service);
                    ui.printInfo("  Manual fix: systemctl unmask " ~ service);
                    issuesFound = true;
                } else if (statusResult.output.strip() == "disabled") {
                    ui.printWarning("! Critical service is disabled: " ~ service);
                    ui.printInfo("  Consider: systemctl enable " ~ service);
                    issuesFound = true;
                } else {
                    ui.printStatus("✓ " ~ service ~ " is properly configured");
                }
            }

            return issuesFound;

        } catch (Exception e) {
            Logger.error("Critical services diagnosis failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Diagnose filesystem issues
     */
    private bool diagnoseFilesystemIssues(ref SystemInfo sysInfo) {
        ui.printInfo("Checking filesystem integrity...");

        try {
            bool issuesFound = false;

            // Check for read-only filesystem
            auto mountResult = ChrootManager.executeInChroot(sysInfo, ["mount"]);
            if (mountResult.output.indexOf("ro,") != -1) {
                ui.printWarning("! Root filesystem is mounted read-only");
                ui.printInfo("  This may indicate filesystem errors");
                ui.printInfo("  Manual fix: fsck " ~ sysInfo.device ~ " (when unmounted)");
                issuesFound = true;
            } else {
                ui.printStatus("✓ Root filesystem is mounted read-write");
            }

            // Check /tmp directory
            string tmpDir = buildPath(sysInfo.mountPoint, "tmp");
            if (!exists(tmpDir)) {
                ui.printWarning("! /tmp directory missing");
                ui.printInfo("  Manual fix: mkdir /tmp && chmod 1777 /tmp");
                issuesFound = true;
            } else {
                ui.printStatus("✓ /tmp directory exists");
            }

            return issuesFound;

        } catch (Exception e) {
            Logger.error("Filesystem diagnosis failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Diagnose broken symlinks in critical system paths
     */
    private bool diagnoseCriticalSymlinks(ref SystemInfo sysInfo) {
        ui.printInfo("Checking for broken symlinks...");

        try {
            bool issuesFound = false;

            string[] criticalPaths = [
                "/etc/resolv.conf",
                "/etc/localtime",
                "/lib64",
                "/bin",
                "/sbin"
            ];

            foreach (path; criticalPaths) {
                string fullPath = buildPath(sysInfo.mountPoint, path[1..$]);
                if (exists(fullPath) && isSymlink(fullPath)) {
                    try {
                        // Try to read the symlink target
                        string target = readLink(fullPath);
                        string absoluteTarget = buildPath(sysInfo.mountPoint, target[1..$]);

                        if (!exists(absoluteTarget)) {
                            ui.printWarning("! Broken symlink detected: " ~ path ~ " -> " ~ target);
                            ui.printInfo("  Manual fix: Remove and recreate symlink");
                            issuesFound = true;
                        } else {
                            ui.printStatus("✓ " ~ path ~ " symlink is valid");
                        }
                    } catch (Exception e) {
                        // Symlink is broken
                        ui.printWarning("! Broken symlink: " ~ path);
                        ui.printInfo("  Manual fix: Remove and recreate symlink");
                        issuesFound = true;
                    }
                } else if (exists(fullPath)) {
                    ui.printStatus("✓ " ~ path ~ " exists and is not a symlink");
                }
            }

            return issuesFound;

        } catch (Exception e) {
            Logger.error("Symlink diagnosis failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Diagnose critical directory permissions
     */
    private bool diagnoseCriticalDirectoryPermissions(ref SystemInfo sysInfo) {
        ui.printInfo("Checking critical directory permissions...");

        try {
            bool issuesFound = false;

            struct DirPerms {
                string path;
                string expectedPerms;
            }

            DirPerms[] criticalDirs = [
                DirPerms("/tmp", "1777"),
                DirPerms("/var/tmp", "1777"),
                DirPerms("/var/log", "755"),
                DirPerms("/etc", "755"),
                DirPerms("/boot", "755")
            ];

            foreach (dir; criticalDirs) {
                string fullPath = buildPath(sysInfo.mountPoint, dir.path[1..$]);
                if (exists(fullPath)) {
                    auto result = ChrootManager.executeInChroot(sysInfo,
                        ["stat", "-c", "%a", dir.path]);
                    if (result.status == 0) {
                        string actualPerms = result.output.strip();
                        if (actualPerms != dir.expectedPerms) {
                            ui.printWarning("! " ~ dir.path ~ " has permissions " ~ actualPerms ~
                                          " (expected " ~ dir.expectedPerms ~ ")");
                            ui.printInfo("  Manual fix: chmod " ~ dir.expectedPerms ~ " " ~ dir.path);
                            issuesFound = true;
                        } else {
                            ui.printStatus("✓ " ~ dir.path ~ " has correct permissions");
                        }
                    }
                } else {
                    ui.printWarning("! " ~ dir.path ~ " does not exist");
                    issuesFound = true;
                }
            }

            return issuesFound;

        } catch (Exception e) {
            Logger.error("Directory permissions diagnosis failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Validate and fix network configuration
     */
    bool validateNetworkConfiguration(ref SystemInfo sysInfo) {
        ui.printInfo("Checking network configuration...");

        try {
            bool hasConnection = testNetworkConnectivity(sysInfo);
            bool hasValidConfig = validateNetworkManagerConfig(sysInfo);

            if (hasConnection && hasValidConfig) {
                ui.printStatus("✓ Network is working correctly");
                return false; // No fixes needed
            }

            if (!hasValidConfig) {
                ui.printWarning("! Network configuration issues detected");
                return fixNetworkConfiguration(sysInfo);
            }

            if (!hasConnection) {
                ui.printWarning("! No network connectivity");
                return offerNetworkConfiguration(sysInfo);
            }

            return false;

        } catch (Exception e) {
            Logger.error("Network validation failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Test network connectivity
     */
    private bool testNetworkConnectivity(ref SystemInfo sysInfo) {
        ui.printInfo("Testing network connectivity...");

        // Test DNS resolution and connectivity
        string[] testCommands = [
            ["ping", "-c", "1", "-W", "3", "8.8.8.8"],          // Google DNS
            ["ping", "-c", "1", "-W", "3", "1.1.1.1"],          // Cloudflare DNS
            ["nslookup", "google.com"]                           // DNS resolution
        ];

        int successCount = 0;
        foreach (cmd; testCommands) {
            auto result = ChrootManager.executeInChroot(sysInfo, cmd);
            if (result.status == 0) {
                successCount++;
            }
        }

        bool hasConnectivity = successCount >= 2;
        if (hasConnectivity) {
            ui.printStatus("✓ Network connectivity is working");
        } else {
            ui.printWarning("! No network connectivity detected");
        }

        return hasConnectivity;
    }

    /**
     * Validate NetworkManager configuration
     */
    private bool validateNetworkManagerConfig(ref SystemInfo sysInfo) {
        try {
            // Check if NetworkManager is installed and enabled
            auto nmCheck = ChrootManager.executeInChroot(sysInfo, ["systemctl", "is-enabled", "NetworkManager.service"]);
            if (nmCheck.status != 0) {
                ui.printWarning("! NetworkManager is not enabled");
                return false;
            }

            // Check for basic NetworkManager configuration
            string nmConfDir = buildPath(sysInfo.mountPoint, "etc", "NetworkManager");
            if (!exists(nmConfDir)) {
                ui.printWarning("! NetworkManager configuration directory missing");
                return false;
            }

            // Check for network connections
            auto connectionCheck = ChrootManager.executeInChroot(sysInfo, ["nmcli", "connection", "show"]);
            if (connectionCheck.status != 0) {
                ui.printWarning("! No network connections configured");
                return false;
            }

            return true;

        } catch (Exception e) {
            Logger.error("NetworkManager validation failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fix basic network configuration issues
     */
    private bool fixNetworkConfiguration(ref SystemInfo sysInfo) {
        ui.printInfo("Attempting to fix network configuration...");
        bool anyFixed = false;

        try {
            // Enable NetworkManager if not enabled
            auto nmCheck = ChrootManager.executeInChroot(sysInfo, ["systemctl", "is-enabled", "NetworkManager.service"]);
            if (nmCheck.status != 0) {
                ui.printInfo("Enabling NetworkManager service...");
                auto enableResult = ChrootManager.executeInChroot(sysInfo, ["systemctl", "enable", "NetworkManager.service"]);
                if (enableResult.status == 0) {
                    ui.printStatus("✓ NetworkManager enabled");
                    anyFixed = true;
                }
            }

            // Check if networkmanager package is installed
            auto packageCheck = ChrootManager.executeInChroot(sysInfo, ["which", "nmcli"]);
            if (packageCheck.status != 0) {
                ui.printInfo("NetworkManager not installed. Installing...");
                if (installPackageUniversal(sysInfo, "networkmanager")) {
                    ui.printStatus("✓ NetworkManager installed");
                    // Enable it too
                    ChrootManager.executeInChroot(sysInfo, ["systemctl", "enable", "NetworkManager.service"]);
                    anyFixed = true;
                }
            }

            // Disable conflicting network services
            string[] conflictingServices = ["dhcpcd.service", "netctl.service"];
            foreach (service; conflictingServices) {
                auto disableResult = ChrootManager.executeInChroot(sysInfo, ["systemctl", "disable", service]);
                if (disableResult.status == 0) {
                    ui.printInfo("Disabled conflicting service: " ~ service);
                    anyFixed = true;
                }
            }

            return anyFixed;

        } catch (Exception e) {
            Logger.error("Failed to fix network configuration: " ~ e.msg);
            return false;
        }
    }

    /**
     * Offer network configuration options to user
     */
    private bool offerNetworkConfiguration(ref SystemInfo sysInfo) {
        ui.printInfo("Network connectivity issues detected. How would you like to proceed?");

        MenuOption[] networkOptions = [
            MenuOption("Launch nmtui", "Use NetworkManager Text UI to configure network", true),
            MenuOption("Try automatic network setup", "Attempt automatic DHCP configuration", true),
            MenuOption("Install NetworkManager", "Install and configure NetworkManager", true),
            MenuOption("Skip network setup", "Continue without network (limited functionality)", true)
        ];

        int choice = ui.showMenu(networkOptions);

        switch (choice) {
            case 0: // Launch nmtui
                return launchNetworkManagerTUI(sysInfo);

            case 1: // Automatic setup
                return attemptAutomaticNetworkSetup(sysInfo);

            case 2: // Install NetworkManager
                return installAndConfigureNetworkManager(sysInfo);

            default: // Skip
                ui.printWarning("! Skipping network setup - some repair operations may fail");
                return false;
        }
    }

    /**
     * Launch NetworkManager Text UI for network configuration
     */
    bool launchNetworkManagerTUI(ref SystemInfo sysInfo) {
        ui.printInfo("Launching NetworkManager Text UI...");
        ui.printInfo("Configure your network connection and press ESC to exit when done.");
        ui.printInfo("Press any key to continue...");
        ui.waitForKey();

        try {
            // Clear screen and launch nmtui in chroot
            ui.clearScreen();
            auto result = ChrootManager.executeInChroot(sysInfo, ["nmtui"]);

            ui.clearScreen();
            ui.printHeader();

            if (result.status == 0) {
                ui.printStatus("✓ Network configuration completed");

                // Test connectivity after configuration
                if (testNetworkConnectivity(sysInfo)) {
                    ui.printStatus("✓ Network connectivity verified");
                    return true;
                } else {
                    ui.printWarning("! Network configured but connectivity test failed");
                    return false;
                }
            } else {
                ui.printError("Network configuration failed or was cancelled");
                return false;
            }

        } catch (Exception e) {
            Logger.error("Failed to launch nmtui: " ~ e.msg);
            ui.printError("Could not launch network configuration tool");
            return false;
        }
    }

    /**
     * Attempt automatic network setup
     */
    bool attemptAutomaticNetworkSetup(ref SystemInfo sysInfo) {
        ui.printInfo("Attempting automatic network setup...");

        try {
            // Start NetworkManager if not running
            ChrootManager.executeInChroot(sysInfo, ["systemctl", "start", "NetworkManager.service"]);

            // Wait a moment for NetworkManager to initialize
            import core.thread;
            Thread.sleep(3000.msecs);

            // Try to connect to available networks
            auto scanResult = ChrootManager.executeInChroot(sysInfo, ["nmcli", "device", "wifi", "rescan"]);
            Thread.sleep(2000.msecs);

            auto connectResult = ChrootManager.executeInChroot(sysInfo, ["nmcli", "device", "connect", "eth0"]);
            if (connectResult.status != 0) {
                // Try with different interface names
                string[] interfaces = ["enp0s3", "enp0s8", "ens33", "wlan0"];
                foreach (iface; interfaces) {
                    auto result = ChrootManager.executeInChroot(sysInfo, ["nmcli", "device", "connect", iface]);
                    if (result.status == 0) break;
                }
            }

            // Test connectivity
            Thread.sleep(2000.msecs);
            if (testNetworkConnectivity(sysInfo)) {
                ui.printStatus("✓ Automatic network setup successful");
                return true;
            } else {
                ui.printWarning("! Automatic setup failed - try manual configuration");
                return false;
            }

        } catch (Exception e) {
            Logger.error("Automatic network setup failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Install and configure NetworkManager
     */
    bool installAndConfigureNetworkManager(ref SystemInfo sysInfo) {
        ui.printInfo("Installing and configuring NetworkManager...");

        try {
            // Install NetworkManager and related packages
            string[] packages = ["networkmanager", "network-manager-applet"];
            bool installSuccess = true;

            foreach (pkg; packages) {
                if (!installPackageUniversal(sysInfo, pkg)) {
                    installSuccess = false;
                    break;
                }
            }

            auto installResult = CommandResult();
            installResult.status = installSuccess ? 0 : 1;

            if (installResult.status != 0) {
                ui.printError("Failed to install NetworkManager packages");
                return false;
            }

            // Enable and start NetworkManager
            ChrootManager.executeInChroot(sysInfo, ["systemctl", "enable", "NetworkManager.service"]);
            ChrootManager.executeInChroot(sysInfo, ["systemctl", "start", "NetworkManager.service"]);

            // Disable conflicting services
            string[] conflictingServices = ["dhcpcd.service", "netctl.service"];
            foreach (service; conflictingServices) {
                ChrootManager.executeInChroot(sysInfo, ["systemctl", "disable", service]);
                ChrootManager.executeInChroot(sysInfo, ["systemctl", "stop", service]);
            }

            ui.printStatus("✓ NetworkManager installed and configured");

            // Offer to configure network now
            ui.printInfo("Would you like to configure network connections now?");
            MenuOption[] configOptions = [
                MenuOption("Yes", "Configure network now with nmtui", true),
                MenuOption("No", "Configure later after reboot", true)
            ];

            int choice = ui.showMenu(configOptions);
            if (choice == 0) {
                return launchNetworkManagerTUI(sysInfo);
            }

            return true;

        } catch (Exception e) {
            Logger.error("Failed to install NetworkManager: " ~ e.msg);
            return false;
        }
    }

    /**
     * Check if 'here' universal package manager is available
     */
    private bool checkHereAvailability(ref SystemInfo sysInfo) {
        try {
            auto result = ChrootManager.executeInChroot(sysInfo, ["which", "here"]);
            return result.status == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Install package using universal method (here if available, fallback to distro-specific)
     */
    private bool installPackageUniversal(ref SystemInfo sysInfo, string packageName) {
        try {
            // First try 'here' universal package manager
            auto hereResult = ChrootManager.executeInChroot(sysInfo, ["here", "install", packageName]);
            if (hereResult.status == 0) {
                ui.printStatus("✓ Installed " ~ packageName ~ " via here");
                return true;
            }

            // Fallback to distribution-specific commands
            return installPackageFallback(sysInfo, packageName);

        } catch (Exception e) {
            Logger.error("Package installation failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fallback package installation using distribution-specific commands
     */
    private bool installPackageFallback(ref SystemInfo sysInfo, string packageName) {
        try {
            // Try pacman (Arch Linux)
            auto pacmanResult = ChrootManager.executeInChroot(sysInfo, ["pacman", "-S", "--noconfirm", packageName]);
            if (pacmanResult.status == 0) {
                ui.printStatus("✓ Installed " ~ packageName ~ " via pacman");
                return true;
            }

            // Try apt (Debian/Ubuntu)
            auto aptResult = ChrootManager.executeInChroot(sysInfo, ["apt", "install", "-y", packageName]);
            if (aptResult.status == 0) {
                ui.printStatus("✓ Installed " ~ packageName ~ " via apt");
                return true;
            }

            // Try dnf (Fedora)
            auto dnfResult = ChrootManager.executeInChroot(sysInfo, ["dnf", "install", "-y", packageName]);
            if (dnfResult.status == 0) {
                ui.printStatus("✓ Installed " ~ packageName ~ " via dnf");
                return true;
            }

            // Try zypper (openSUSE)
            auto zypperResult = ChrootManager.executeInChroot(sysInfo, ["zypper", "install", "-y", packageName]);
            if (zypperResult.status == 0) {
                ui.printStatus("✓ Installed " ~ packageName ~ " via zypper");
                return true;
            }

            ui.printError("Failed to install " ~ packageName ~ " - no suitable package manager found");
            return false;

        } catch (Exception e) {
            Logger.error("Fallback package installation failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Update packages using universal method
     */
    bool updatePackagesUniversal(ref SystemInfo sysInfo) {
        ui.printInfo("Updating system packages...");

        try {
            // First try 'here' universal package manager
            auto hereResult = ChrootManager.executeInChroot(sysInfo, ["here", "update"]);
            if (hereResult.status == 0) {
                ui.printStatus("✓ System updated via here");
                return true;
            }

            // Fallback to distribution-specific commands
            return updatePackagesFallback(sysInfo);

        } catch (Exception e) {
            Logger.error("Package update failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Fallback package update using distribution-specific commands
     */
    private bool updatePackagesFallback(ref SystemInfo sysInfo) {
        try {
            // Try pacman (Arch Linux)
            auto pacmanResult = ChrootManager.executeInChroot(sysInfo, ["pacman", "-Syu", "--noconfirm"]);
            if (pacmanResult.status == 0) {
                ui.printStatus("✓ System updated via pacman");
                return true;
            }

            // Try apt (Debian/Ubuntu)
            ChrootManager.executeInChroot(sysInfo, ["apt", "update"]);
            auto aptResult = ChrootManager.executeInChroot(sysInfo, ["apt", "upgrade", "-y"]);
            if (aptResult.status == 0) {
                ui.printStatus("✓ System updated via apt");
                return true;
            }

            // Try dnf (Fedora)
            auto dnfResult = ChrootManager.executeInChroot(sysInfo, ["dnf", "update", "-y"]);
            if (dnfResult.status == 0) {
                ui.printStatus("✓ System updated via dnf");
                return true;
            }

            // Try zypper (openSUSE)
            auto zypperResult = ChrootManager.executeInChroot(sysInfo, ["zypper", "update", "-y"]);
            if (zypperResult.status == 0) {
                ui.printStatus("✓ System updated via zypper");
                return true;
            }

            ui.printError("Failed to update packages - no suitable package manager found");
            return false;

        } catch (Exception e) {
            Logger.error("Fallback package update failed: " ~ e.msg);
            return false;
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
                content.indexOf("menuentry \"CachyOS Linux\"") != -1 ||
                content.indexOf("menuentry \"Arch Linux\"") != -1) {
                Logger.info("Manual stanza already exists in refind.conf");

                // Always update existing entry if it has incorrect paths for Btrfs
                if (sysInfo.isBtrfs && sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                    updateExistingRefindEntry(refindConfPath, sysInfo);
                }
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

            // For Btrfs, use the UUID directly without quotes for volume
            if (sysInfo.isBtrfs && sysInfo.uuid.length > 0) {
                stanza ~= "    volume   " ~ sysInfo.uuid ~ "\n";
                // For Btrfs with subvolumes, include the subvolume path
                if (sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                    string subvolPath = sysInfo.btrfsInfo.rootSubvolume;
                    if (!subvolPath.startsWith("/")) {
                        subvolPath = "/" ~ subvolPath;
                    }
                    stanza ~= "    loader   " ~ subvolPath ~ "/boot/vmlinuz-linux-cachyos\n";
                    stanza ~= "    initrd   " ~ subvolPath ~ "/boot/initramfs-linux-cachyos.img\n";
                } else {
                    stanza ~= "    loader   /boot/vmlinuz-linux-cachyos\n";
                    stanza ~= "    initrd   /boot/initramfs-linux-cachyos.img\n";
                }
            } else {
                stanza ~= "    volume   \"" ~ (sysInfo.uuid.length > 0 ? sysInfo.uuid : "boot") ~ "\"\n";
                stanza ~= "    loader   /boot/vmlinuz-linux-cachyos\n";
                stanza ~= "    initrd   /boot/initramfs-linux-cachyos.img\n";
            }

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
     * Install GRUB for CachyOS/Arch systems
     */
    private bool installGrubForBtrfs(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        Logger.info("Installing GRUB for Btrfs system");
        ui.printInfo("Installing GRUB bootloader for better Btrfs support...");

        try {
            // Check if GRUB is installed in the system
            if (!exists(buildPath(sysInfo.mountPoint, "usr/bin/grub-install"))) {
                ui.printInfo("Installing GRUB package...");
                auto process = ChrootManager.executeChrootDirect(sysInfo, ["pacman", "-S", "--noconfirm", "grub", "efibootmgr"]);
                auto exitCode = wait(process);

                if (exitCode != 0) {
                    ui.printError("Failed to install GRUB package");
                    return false;
                }
            }

            // Find Windows EFI partition (where rEFInd is)
            string windowsEfiPath = "";
            if (exists("/mnt/EFI/refind")) {
                windowsEfiPath = "/mnt";
            } else if (exists("/mnt/debork/boot/efi")) {
                windowsEfiPath = buildPath(sysInfo.mountPoint, "boot/efi");
            }

            if (windowsEfiPath.length == 0) {
                ui.printError("Could not find EFI partition");
                return false;
            }

            // Mount Windows EFI to /boot/efi in chroot if needed
            string chrootEfiPath = buildPath(sysInfo.mountPoint, "boot/efi");
            if (!exists(chrootEfiPath)) {
                mkdirRecurse(chrootEfiPath);
            }

            // Check if already mounted
            auto mountCheck = executeShell("mountpoint -q " ~ chrootEfiPath);
            if (mountCheck.status != 0) {
                // Find the Windows EFI partition device
                auto efiDevice = executeShell("df " ~ windowsEfiPath ~ " | tail -1 | awk '{print $1}'");
                if (efiDevice.status == 0) {
                    string device = efiDevice.output.strip();
                    auto mountResult = executeShell("mount " ~ device ~ " " ~ chrootEfiPath);
                    if (mountResult.status != 0) {
                        ui.printWarning("Could not mount EFI partition to chroot");
                    }
                }
            }

            // Mount efivars if not already mounted
            string efivarPath = buildPath(sysInfo.mountPoint, "sys/firmware/efi/efivars");
            if (exists("/sys/firmware/efi/efivars") && exists(efivarPath)) {
                auto efivarCheck = executeShell("mountpoint -q " ~ efivarPath);
                if (efivarCheck.status != 0) {
                    auto mountEfivars = executeShell("mount --bind /sys/firmware/efi/efivars " ~ efivarPath);
                    if (mountEfivars.status == 0) {
                        Logger.info("Mounted efivars for GRUB installation");
                    }
                }
            }

            // Install GRUB to EFI with removable flag for better compatibility
            ui.printInfo("Installing GRUB to EFI partition...");
            auto process = ChrootManager.executeChrootDirect(sysInfo, [
                "grub-install",
                "--target=x86_64-efi",
                "--efi-directory=/boot/efi",
                "--bootloader-id=CachyOS",
                "--removable",
                "--recheck"
            ]);
            auto exitCode = wait(process);

            if (exitCode != 0) {
                // Try without removable flag if it failed
                ui.printInfo("Retrying GRUB installation without removable flag...");
                process = ChrootManager.executeChrootDirect(sysInfo, [
                    "grub-install",
                    "--target=x86_64-efi",
                    "--efi-directory=/boot/efi",
                    "--bootloader-id=CachyOS",
                    "--no-nvram",
                    "--recheck"
                ]);
                exitCode = wait(process);

                if (exitCode != 0) {
                    ui.printError("GRUB installation failed");
                    return false;
                }
            }

            // Generate GRUB configuration
            ui.printInfo("Generating GRUB configuration...");
            process = ChrootManager.executeChrootDirect(sysInfo, ["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]);
            exitCode = wait(process);

            if (exitCode != 0) {
                ui.printWarning("GRUB configuration generation had issues");
            }

            ui.printSuccess("GRUB installed successfully");
            ui.printInfo("rEFInd should now detect 'CachyOS' GRUB entry");

            // Create a manual rEFInd entry for GRUB if needed
            createRefindGrubEntry(sysInfo);

            return true;

        } catch (Exception e) {
            Logger.error("Failed to install GRUB: " ~ e.msg);
            ui.printError("GRUB installation failed: " ~ e.msg);
            return false;
        }
    }

    /**
     * Create rEFInd entry for GRUB
     */
    private void createRefindGrubEntry(ref SystemInfo sysInfo) {
        try {
            // Find rEFInd configuration
            string refindConfPath = "";
            if (exists("/mnt/EFI/refind/refind.conf")) {
                refindConfPath = "/mnt/EFI/refind/refind.conf";
            } else if (exists(buildPath(sysInfo.mountPoint, "boot/efi/EFI/refind/refind.conf"))) {
                refindConfPath = buildPath(sysInfo.mountPoint, "boot/efi/EFI/refind/refind.conf");
            }

            if (refindConfPath.length == 0) {
                Logger.warning("rEFInd configuration not found");
                return;
            }

            // Check if GRUB entry already exists
            string content = readText(refindConfPath);
            if (content.indexOf("menuentry \"CachyOS GRUB\"") != -1) {
                Logger.info("GRUB entry already exists in rEFInd");
                return;
            }

            // Add GRUB entry
            string grubEntry = "\n\n# GRUB entry for CachyOS\n";
            grubEntry ~= "menuentry \"CachyOS GRUB\" {\n";
            grubEntry ~= "    icon     /EFI/refind/icons/os_arch.png\n";
            grubEntry ~= "    loader   /EFI/CachyOS/grubx64.efi\n";
            grubEntry ~= "    options  \"\"\n";
            grubEntry ~= "}\n";

            append(refindConfPath, grubEntry);
            ui.printInfo("Added GRUB entry to rEFInd configuration");

        } catch (Exception e) {
            Logger.warning("Could not create rEFInd GRUB entry: " ~ e.msg);
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

    /**
     * Ensure Btrfs driver is installed for rEFInd
     */
    private void ensureBtrfsDriver(ref SystemInfo sysInfo) {
        import std.process : executeShell;

        try {
            // Find where rEFInd is installed
            string refindLocation = detectRefindInstallation(sysInfo);
            if (refindLocation.length == 0) {
                Logger.warning("Cannot install Btrfs driver - rEFInd not found");
                return;
            }

            string driversDir = buildPath(refindLocation, "drivers_x64");
            string btrfsDriverPath = buildPath(driversDir, "btrfs_x64.efi");

            // Check if driver already exists
            if (exists(btrfsDriverPath)) {
                Logger.info("Btrfs driver already installed");
                return;
            }

            // Create drivers directory if it doesn't exist
            if (!exists(driversDir)) {
                mkdirRecurse(driversDir);
                Logger.info("Created rEFInd drivers directory");
            }

            // Look for Btrfs driver in the system
            string[] possibleLocations = [
                "/usr/share/refind/drivers_x64/btrfs_x64.efi",
                buildPath(sysInfo.mountPoint, "usr/share/refind/drivers_x64/btrfs_x64.efi"),
                "/usr/lib/refind/drivers_x64/btrfs_x64.efi",
                buildPath(sysInfo.mountPoint, "usr/lib/refind/drivers_x64/btrfs_x64.efi")
            ];

            string sourceDriver = "";
            foreach (location; possibleLocations) {
                if (exists(location)) {
                    sourceDriver = location;
                    break;
                }
            }

            if (sourceDriver.length > 0) {
                copy(sourceDriver, btrfsDriverPath);
                Logger.info("Installed Btrfs driver for rEFInd");
                ui.printInfo("Installed Btrfs filesystem driver for rEFInd");
            } else {
                Logger.warning("Btrfs driver not found in system");
                ui.printWarning("Could not find Btrfs driver - manual installation may be needed");
            }

        } catch (Exception e) {
            Logger.warning("Could not install Btrfs driver: " ~ e.msg);
        }
    }

    /**
     * Update existing rEFInd entry with correct Btrfs paths
     */
    private void updateExistingRefindEntry(string refindConfPath, ref SystemInfo sysInfo) {
        import std.file : readText, write;
        import std.regex : regex, replaceAll, matchFirst;

        try {
            string content = readText(refindConfPath);
            string originalContent = content;

            // For Btrfs with subvolumes, we need to prepend the subvolume path
            if (sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                string subvolPath = sysInfo.btrfsInfo.rootSubvolume;
                if (!subvolPath.startsWith("/")) {
                    subvolPath = "/" ~ subvolPath;
                }

                // Find any CachyOS menuentry block and update it
                auto menuRegex = regex(`(menuentry\s+"CachyOS[^"]*"\s*\{[^}]*\})`, "gms");
                auto match = matchFirst(content, menuRegex);

                if (!match.empty) {
                    string menuBlock = match[1];
                    string updatedBlock = menuBlock;

                    // Update loader path if it doesn't have subvolume prefix already
                    if (updatedBlock.indexOf(subvolPath ~ "/boot/vmlinuz") == -1) {
                        auto loaderRegex = regex(`(loader\s+)(/boot/vmlinuz[-\w]+)`, "gm");
                        updatedBlock = replaceAll(updatedBlock, loaderRegex, "$1" ~ subvolPath ~ "$2");
                    }

                    // Update initrd path if it doesn't have subvolume prefix already
                    if (updatedBlock.indexOf(subvolPath ~ "/boot/initramfs") == -1) {
                        auto initrdRegex = regex(`(initrd\s+)(/boot/initramfs[-\w]+\.img)`, "gm");
                        updatedBlock = replaceAll(updatedBlock, initrdRegex, "$1" ~ subvolPath ~ "$2");
                    }

                    // Ensure volume uses UUID without quotes for Btrfs
                    auto volumeRegex = regex(`(volume\s+)"?([0-9a-fA-F-]+)"?`, "gm");
                    updatedBlock = replaceAll(updatedBlock, volumeRegex, "$1$2");

                    // Replace the original block with the updated one
                    if (menuBlock != updatedBlock) {
                        content = content.replace(menuBlock, updatedBlock);
                    }
                }

                // If content changed, write it back
                if (content != originalContent) {
                    // Backup original
                    string backupPath = refindConfPath ~ ".bak-" ~ to!string(Clock.currTime.toUnixTime());
                    copy(refindConfPath, backupPath);

                    // Write updated content
                    write(refindConfPath, content);
                    Logger.info("Updated existing rEFInd entry with Btrfs subvolume paths");
                    ui.printInfo("Updated rEFInd configuration for Btrfs filesystem");
                }
            }

        } catch (Exception e) {
            Logger.warning("Could not update existing rEFInd entry: " ~ e.msg);
        }
    }
}
