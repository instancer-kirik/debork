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
            // Method 1: Use refind-install if available
            if (exists(buildPath(sysInfo.mountPoint, "usr/bin/refind-install"))) {
                auto process = ChrootManager.executeChrootDirect(sysInfo, ["refind-install"]);
                auto exitCode = wait(process);

                if (exitCode == 0) {
                    ui.printStatus("✓ rEFInd configuration updated");
                    return true;
                }
            }

            // Method 2: Manual refind_linux.conf generation
            return generateRefindLinuxConf(sysInfo);

        } catch (Exception e) {
            Logger.error("Exception fixing rEFInd: " ~ e.msg);
            return false;
        }
    }

    /**
     * Generate refind_linux.conf manually
     */
    private bool generateRefindLinuxConf(ref SystemInfo sysInfo) {
        try {
            string bootPath = sysInfo.bootDir;
            string refindConfPath = buildPath(bootPath, "refind_linux.conf");

            // Find the best kernel to use
            KernelInfo bestKernel;
            foreach (kernel; sysInfo.kernels) {
                if (kernel.exists) {
                    bestKernel = kernel;
                    break;
                }
            }

            if (bestKernel.path.length == 0) {
                ui.printError("No usable kernel found for rEFInd configuration");
                return false;
            }

            // Generate configuration content
            string rootParam = "root=UUID=" ~ sysInfo.uuid;
            if (sysInfo.isBtrfs && sysInfo.btrfsInfo.rootSubvolume.length > 0) {
                rootParam ~= " rootflags=subvol=" ~ sysInfo.btrfsInfo.rootSubvolume;
            }

            string content = format(
                "\"Boot with standard options\" \"%s initrd=%s %s rw\"\n" ~
                "\"Boot to terminal\"            \"%s initrd=%s %s rw systemd.unit=multi-user.target\"\n" ~
                "\"Boot with nomodeset\"         \"%s initrd=%s %s rw nomodeset\"\n",
                bestKernel.path, bestKernel.initrd, rootParam,
                bestKernel.path, bestKernel.initrd, rootParam,
                bestKernel.path, bestKernel.initrd, rootParam
            );

            // Write configuration file
            write(refindConfPath, content);
            Logger.info("Generated rEFInd configuration: " ~ refindConfPath);
            ui.printStatus("✓ Generated rEFInd configuration");

            return true;

        } catch (Exception e) {
            Logger.error("Failed to generate rEFInd configuration: " ~ e.msg);
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
                string rootParam = "root=UUID=" ~ sysInfo.uuid;

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
