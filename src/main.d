module main;

import std.stdio;
import std.getopt;
import std.conv;
import std.algorithm;
import std.string;
import std.file;
import std.path;
import std.process;

import debork.core.types;
import debork.core.logger;
import debork.ui.tui;
import debork.filesystem.mount;
import debork.filesystem.btrfs;
import debork.system.chroot;
import debork.system.detection;
import debork.repair.operations;

class DeborkApp {
    private TUI ui;
    private SystemInfo sysInfo;
    private bool debugMode = false;
    private bool verboseMode = false;

    this(bool debugFlag = false, bool verbose = false) {
        debugMode = debugFlag;
        verboseMode = verbose;
        ui = new TUI(debugFlag);
        Logger.initialize(debugFlag);
    }

    /**
     * Main application entry point
     */
    int run() {
        try {
            // Check if running as root
            if (!isRoot()) {
                ui.printError("debork must be run as root for system repair operations");
                ui.printInfo("Please run: sudo debork");
                return 1;
            }

            // Show welcome screen
            ui.printHeader();
            ui.printInfo("Welcome to debork Boot Rescue Tool!");
            writeln();

            // Select partition to repair
            PartitionInfo selectedPartition = selectPartition();
            if (selectedPartition.device.length == 0) {
                ui.printInfo("No device selected. Exiting...");
                return 0;
            }

            ui.printInfo("Selected device: " ~ selectedPartition.device);
            ui.printInfo("Attempting to mount and analyze system...");
            writeln();

            // Mount the system
            if (!mountSystem(selectedPartition)) {
                ui.printError("Failed to mount system. Cannot continue.");
                ui.printError("Please check:");
                ui.printList([
                    "The partition is accessible and not corrupted",
                    "You have sufficient permissions (running as root)",
                    "The filesystem type is supported"
                ]);
                ui.waitForKey();
                return 1;
            }

            // Run main menu loop
            int result = runMainMenu();

            // Cleanup
            cleanup();

            return result;

        } catch (Exception e) {
            ui.printError("Fatal error: " ~ e.msg);
            Logger.error("Fatal exception in main: " ~ e.msg);
            cleanup();
            return 1;
        }
    }

    /**
     * Select partition to repair
     */
    private PartitionInfo selectPartition() {
        ui.printInfo("Scanning for Linux partitions...");
        auto partitions = SystemDetection.scanPartitions();

        if (partitions.length == 0) {
            ui.printWarning("No Linux partitions detected automatically");
            PartitionInfo manual;
            manual.device = ui.promptInput("Enter device path to repair (e.g., /dev/nvme0n1p5)");
            return manual;
        }

        // Create menu options
        MenuOption[] options;
        foreach (partition; partitions) {
            string description = format("%s %s",
                                       partition.fstype.length > 0 ? partition.fstype : "unknown",
                                       partition.size.length > 0 ? partition.size : "");

            if (partition.label.length > 0) {
                description ~= " (" ~ partition.label ~ ")";
            }

            options ~= MenuOption(partition.device, description, true);
        }

        // Add manual entry option
        options ~= MenuOption("Enter device path manually", "Type custom device path", true);

        ui.printHeader();
        ui.printInfo("Select partition to repair:");
        writeln();

        int choice = ui.showMenu(options);
        if (choice == -1) {
            ui.printInfo("Selection cancelled");
            return PartitionInfo.init;
        }

        if (choice >= partitions.length) {
            // Manual entry
            PartitionInfo manual;
            manual.device = ui.promptInput("Enter device path to repair (e.g., /dev/nvme0n1p5)");
            return manual;
        }

        PartitionInfo selectedPartition = partitions[choice];
        ui.printInfo("Selected: " ~ selectedPartition.device ~ " (" ~ selectedPartition.fstype ~ ")");
        if (selectedPartition.uuid.length > 0) {
            ui.printInfo("UUID: " ~ selectedPartition.uuid);
        }
        return selectedPartition;
    }

    /**
     * Mount the selected system
     */
    private bool mountSystem(PartitionInfo partition) {
        ui.printInfo("Mounting system from " ~ partition.device);

        // Pre-populate UUID if we already have it from partition scan
        if (partition.uuid.length > 0) {
            sysInfo.uuid = partition.uuid;
            ui.printInfo("Using detected UUID: " ~ partition.uuid);
        }

        // Check if device exists
        if (!exists(partition.device)) {
            ui.printError("Device does not exist: " ~ partition.device);
            return false;
        }

        ui.printInfo("Device exists, checking mount status...");

        // Force unmount if already mounted
        if (MountManager.isDeviceMounted(partition.device)) {
            ui.printWarning("Device is already mounted. Attempting to unmount...");
            if (!MountManager.forceUnmountDevice(partition.device)) {
                ui.printError("Failed to unmount device. It may be in use.");
                return false;
            }
            ui.printInfo("Device unmounted successfully");
        }

        ui.printInfo("Mounting filesystem...");

        // Mount the system
        if (!MountManager.mountSystem(sysInfo, partition.device)) {
            ui.printError("Failed to mount system");
            ui.printError("Mount operation failed. Check system logs for details.");
            return false;
        }

        ui.printSuccess("Filesystem mounted successfully");

        // Detect system information
        ui.printInfo("Analyzing system...");
        try {
            sysInfo.kernels = SystemDetection.detectKernels(sysInfo);
            ui.printInfo("Found " ~ to!string(sysInfo.kernels.length) ~ " kernel(s)");

            sysInfo.bootLoader = SystemDetection.detectBootLoader(sysInfo);
            ui.printInfo("Detected bootloader: " ~ bootLoaderToString(sysInfo.bootLoader));
        } catch (Exception e) {
            ui.printError("Error during system analysis: " ~ e.msg);
            ui.printInfo("Continuing with partial information...");
        }

        // Validate chroot environment
        ui.printInfo("Validating system...");
        if (!ChrootManager.validateChrootEnvironment(sysInfo)) {
            ui.printWarning("System validation failed");
            ui.printInfo("You can still try using the Emergency Shell or Diagnostics");
        } else {
            ui.printSuccess("System validation passed");
        }

        ui.printStatus("System mounted and analyzed successfully");
        ui.printInfo("Press any key to continue to repair menu...");
        ui.waitForKey();
        return true;
    }

    /**
     * Main menu loop
     */
    private int runMainMenu() {
        MenuOption[] mainMenu = [
            MenuOption("Fix My System (Complete Repair)",
                      "Update packages, regenerate initramfs, fix bootloader", true),
            MenuOption("Emergency Shell (Manual Fixes)",
                      "Interactive chroot shell for manual repairs", true),
            MenuOption("Regenerate Initramfs Only",
                      "Rebuild initramfs for all kernels", true),
            MenuOption("Fix Bootloader Only",
                      "Repair bootloader configuration", true),
            MenuOption("Clean & Fix rEFInd",
                      "Clean duplicate entries and fix rEFInd configuration", true),
            MenuOption("Fix Dual-EFI Boot",
                      "Fix boot with /boot on separate EFI partition", true),
            MenuOption("Show System Information",
                      "Display detected system details", true),
            MenuOption("Diagnose System Issues",
                      "Analyze and diagnose system problems", true),
            MenuOption("Advanced Options",
                      "Additional repair and maintenance tools", true),
            MenuOption("Exit",
                      "Unmount system and exit debork", true)
        ];

        auto repairOps = new RepairOperations(ui);
        bool shouldExit = false;

        while (!shouldExit) {
            ui.printHeader();
            ui.printInfo("System: " ~ sysInfo.mountPoint);
            ui.printInfo("Filesystem: " ~ sysInfo.fstype);
            writeln();

            int choice = ui.showMenu(mainMenu);

            ui.printInfo("You selected option: " ~ to!string(choice + 1));

            switch (choice) {
                case 0: // Complete Repair
                    performCompleteRepair(repairOps);
                    break;

                case 1: // Emergency Shell
                    startEmergencyShell();
                    break;

                case 2: // Regenerate Initramfs
                    regenerateInitramfs(repairOps);
                    break;

                case 3: // Fix Bootloader
                    fixBootloader(repairOps);
                    break;

                case 4: // Clean & Fix rEFInd
                    cleanAndFixRefind(repairOps);
                    break;

                case 5: // Fix Dual-EFI Boot
                    fixDualEfiBoot(repairOps);
                    break;

                case 6: // Show System Info
                    showSystemInformation();
                    break;

                case 7: // Diagnose System
                    diagnoseSystem();
                    break;

                case 8: // Advanced Options
                    showAdvancedMenu(repairOps);
                    break;

                case 9: // Exit
                    shouldExit = true;
                    break;
                case -1: // Quit
                    shouldExit = true;
                    break;

                default:
                    break;
            }
        }

        return 0;
    }

    /**
     * Perform complete system repair
     */
    private void performCompleteRepair(RepairOperations repairOps) {
        ui.printHeader();
        ui.printInfo("Complete System Repair");
        writeln();

        string[] steps = [
            "Update all packages with package manager",
            "Regenerate initramfs for all kernels",
            "Fix bootloader configuration",
            "Complete system repair in one operation"
        ];

        ui.printList(steps, TermColor.GREEN);
        writeln();

        if (!ui.promptConfirm("Continue with complete repair?", false)) {
            return;
        }

        RepairConfig config;
        config.updatePackages = true;
        config.regenerateInitramfs = true;
        config.fixBootloader = true;
        config.verboseOutput = verboseMode;

        auto result = repairOps.performCompleteRepair(sysInfo, config);
        ui.displayResult(result);

        if (result.success) {
            ui.printInfo("System repair completed! You should now be able to boot normally.");
            ui.printInfo("Recommendation: Reboot your system to test the fixes.");
        }

        ui.waitForKey();
    }

    /**
     * Start emergency shell
     */
    private void startEmergencyShell() {
        ui.printHeader();
        ui.printInfo("Starting emergency shell in chroot environment...");
        writeln();

        string[] warnings = [
            "You are entering a chroot environment as root",
            "Use package manager commands carefully",
            "Network connectivity should work for downloads",
            "Type 'exit' to return to debork menu"
        ];

        ui.printInfoBox("IMPORTANT NOTES", warnings);
        writeln();

        string[] sysInfo_lines = ChrootManager.getChrootInfo(sysInfo);
        ui.printList(sysInfo_lines);
        writeln();

        if (!ui.promptConfirm("Start emergency shell?", true)) {
            return;
        }

        if (ChrootManager.startInteractiveShell(sysInfo)) {
            ui.printInfo("Returned from emergency shell");
        } else {
            ui.printError("Emergency shell failed to start");
        }

        ui.waitForKey();
    }

    /**
     * Regenerate initramfs only
     */
    private void regenerateInitramfs(RepairOperations repairOps) {
        ui.printHeader();
        ui.printInfo("Regenerating initramfs for all kernels...");

        if (repairOps.regenerateInitramfs(sysInfo)) {
            ui.printStatus("✓ Initramfs regeneration completed");
        } else {
            ui.printError("Initramfs regeneration failed");
        }

        ui.waitForKey();
    }

    /**
     * Fix bootloader only
     */
    private void fixBootloader(RepairOperations repairOps) {
        ui.printHeader();
        ui.printInfo("Fixing bootloader configuration...");

        if (repairOps.fixBootloader(sysInfo)) {
            ui.printStatus("✓ Bootloader repair completed");
        } else {
            ui.printError("Bootloader repair failed");
        }

        ui.waitForKey();
    }

    /**
     * Clean and fix rEFInd specifically
     */
    private void cleanAndFixRefind(RepairOperations repairOps) {
        ui.printHeader();
        ui.printInfo("Cleaning and fixing rEFInd bootloader...");

        // Check if rEFInd is the detected bootloader
        if (sysInfo.bootLoader != BootLoader.REFIND) {
            ui.printWarning("rEFInd not detected as the bootloader");
            ui.printInfo("Current bootloader: " ~ bootLoaderToString(sysInfo.bootLoader));

            string response = ui.promptInput("Force rEFInd repair anyway? (y/n)");
            if (response.toLower() != "y" && response.toLower() != "yes") {
                ui.waitForKey();
                return;
            }

            sysInfo.bootLoader = BootLoader.REFIND;
        }

        ui.printInfo("Cleaning duplicate rEFInd entries...");
        ui.printInfo("Regenerating rEFInd configuration...");
        ui.printInfo("Verifying boot parameters...");

        if (repairOps.fixBootloader(sysInfo)) {
            ui.printStatus("✓ rEFInd cleanup and repair completed");
            ui.printInfo("");
            ui.printInfo("rEFInd should now have:");
            ui.printInfo("  • Cleaned up duplicate entries");
            ui.printInfo("  • Proper root device parameters");
            ui.printInfo("  • Correct btrfs subvolume settings");
            ui.printInfo("  • Valid refind_linux.conf in /boot");
        } else {
            ui.printError("rEFInd repair failed");
        }

        ui.waitForKey();
    }

    /**
     * Fix dual-EFI boot setup
     */
    private void fixDualEfiBoot(RepairOperations repairOps) {
        ui.printHeader();
        ui.printInfo("Fixing dual-EFI boot configuration...");
        ui.printInfo("This handles the case where /boot is on a separate EFI partition");

        // Force the dual-EFI fix
        if (repairOps.fixDualEfiRefind(sysInfo)) {
            ui.printStatus("✓ Dual-EFI boot configuration fixed");
            ui.printInfo("");
            ui.printInfo("The system should now boot with:");
            ui.printInfo("  • Kernel loaded from first EFI partition");
            ui.printInfo("  • rEFInd configured with correct volume");
            ui.printInfo("  • Proper root device parameters");
        } else {
            ui.printError("Failed to fix dual-EFI boot configuration");
        }

        ui.waitForKey();
    }

    /**
     * Install essential packages
     */
    private void installEssentialPackages(RepairOperations repairOps) {
        ui.printHeader();
        ui.printInfo("Installing essential packages...");

        if (repairOps.installEssentialPackages(sysInfo)) {
            ui.printStatus("✓ Essential packages installed");
        } else {
            ui.printError("Failed to install essential packages");
        }

        ui.waitForKey();
    }

    /**
     * Show system information
     */
    private void showSystemInformation() {
        ui.printSystemInfo(sysInfo);
        writeln();

        string[] summary = SystemDetection.getSystemSummary(sysInfo);
        ui.printList(summary);

        ui.waitForKey();
    }

    /**
     * Diagnose system issues
     */
    private void diagnoseSystem() {
        ui.printHeader();
        string[] diagnosis = ChrootManager.diagnoseChrootIssues(sysInfo);
        ui.printList(diagnosis);
        ui.waitForKey();
    }

    /**
     * Show advanced options menu
     */
    private void showAdvancedMenu(RepairOperations repairOps) {
        MenuOption[] advancedMenu = [
            MenuOption("Repair Filesystem", "Check and repair filesystem errors", true),
            MenuOption("Fix File Permissions", "Repair common permission issues", true),
            MenuOption("Remount with Different Options", "Change mount options", true),
            MenuOption("View Mount Information", "Show detailed mount info", true),
            MenuOption("Test Chroot Environment", "Verify chroot functionality", true),
            MenuOption("Back to Main Menu", "Return to main menu", true)
        ];

        while (true) {
            ui.printHeader();
            ui.printInfo("Advanced Options");
            int choice = ui.showMenu(advancedMenu);

            switch (choice) {
                case 0: // Repair Filesystem
                    if (repairOps.repairFilesystem(sysInfo)) {
                        ui.printStatus("✓ Filesystem repair completed");
                    } else {
                        ui.printError("Filesystem repair failed");
                    }
                    ui.waitForKey();
                    break;

                case 1: // Fix Permissions
                    if (repairOps.fixPermissions(sysInfo)) {
                        ui.printStatus("✓ Permission fixes applied");
                    } else {
                        ui.printError("Permission fixes failed");
                    }
                    ui.waitForKey();
                    break;

                case 2: // Remount Options
                    string options = ui.promptInput("Enter mount options (e.g., rw,noatime)");
                    if (options.length > 0) {
                        if (MountManager.remountWithOptions(sysInfo, options)) {
                            ui.printStatus("✓ Remounted with new options");
                        } else {
                            ui.printError("Remount failed");
                        }
                    }
                    ui.waitForKey();
                    break;

                case 3: // Mount Info
                    string[] mountInfo = MountManager.getMountInfo(sysInfo);
                    ui.printList(mountInfo);
                    ui.waitForKey();
                    break;

                case 4: // Test Chroot
                    if (ChrootManager.testChroot(sysInfo)) {
                        ui.printStatus("✓ Chroot test passed");
                    } else {
                        ui.printError("Chroot test failed");
                    }
                    ui.waitForKey();
                    break;

                case 5: // Back
                case -1:
                    return;

                default:
                    break;
            }
        }
    }

    /**
     * Cleanup and unmount
     */
    private void cleanup() {
        try {
            if (sysInfo.isMounted) {
                ui.printInfo("Unmounting system...");
                if (MountManager.unmountSystem(sysInfo)) {
                    ui.printInfo("System unmounted successfully");
                } else {
                    ui.printWarning("Some unmount operations failed");
                }
            }
        } catch (Exception e) {
            Logger.error("Exception during cleanup: " ~ e.msg);
        }
    }

    /**
     * Check if running as root
     */
    private bool isRoot() {
        try {
            auto result = execute(["id", "-u"]);
            return result.status == 0 && result.output.strip() == "0";
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Helper function for bootloader enum to string
     */
    private string bootLoaderToString(BootLoader bootloader) {
        final switch (bootloader) {
            case BootLoader.UNKNOWN:     return "Unknown";
            case BootLoader.GRUB:        return "GRUB";
            case BootLoader.REFIND:      return "rEFInd";
            case BootLoader.SYSTEMD_BOOT: return "systemd-boot";
        }
    }
}

/**
 * Application entry point
 */
int main(string[] args) {
    bool showHelp = false;
    bool debugMode = false;
    bool verboseMode = false;
    bool versionInfo = false;

    try {
        auto helpInformation = getopt(
            args,
            "help|h", "Show this help message", &showHelp,
            "debug|d", "Enable debug mode with verbose logging", &debugMode,
            "verbose|v", "Enable verbose output", &verboseMode,
            "version", "Show version information", &versionInfo
        );

        if (showHelp) {
            writeln("debork - Cross-Platform Linux Boot Rescue Tool");
            writeln();
            writeln("Usage: debork [options]");
            writeln();
            writeln("A comprehensive TUI-based system for fixing broken Linux installations");
            writeln("from rescue environments. Supports multiple bootloaders and filesystems.");
            writeln();
            defaultGetoptPrinter("Options:", helpInformation.options);
            writeln();
            writeln("Features:");
            writeln("  • Automatic partition detection and mounting");
            writeln("  • Robust btrfs subvolume handling");
            writeln("  • Multi-bootloader support (GRUB, rEFInd, systemd-boot)");
            writeln("  • Package manager integration");
            writeln("  • Emergency shell with chroot environment");
            writeln("  • Comprehensive system diagnostics");
            writeln();
            writeln("Examples:");
            writeln("  sudo debork              # Interactive mode");
            writeln("  sudo debork --debug      # Debug mode with detailed logging");
            writeln("  sudo debork --verbose    # Verbose output");
            writeln();
            writeln("Requirements:");
            writeln("  • Must be run as root");
            writeln("  • Requires mount, umount, chroot, blkid utilities");
            writeln("  • Compatible with most Linux distributions");
            writeln();
            return 0;
        }

        if (versionInfo) {
            writeln("debork 2.0.0 - Cross-Platform Linux Boot Rescue Tool");
            writeln("Built with D programming language");
            writeln("License: MIT");
            writeln();
            return 0;
        }

    } catch (Exception e) {
        stderr.writeln("Error parsing command line arguments: " ~ e.msg);
        return 1;
    }

    // Create and run the application
    try {
        auto app = new DeborkApp(debugMode, verboseMode);
        return app.run();
    } catch (Exception e) {
        stderr.writeln("Fatal error: " ~ e.msg);
        return 1;
    }
}
