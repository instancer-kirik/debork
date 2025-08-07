module debork.system.chroot;

import std.process;
import std.file;
import std.path;
import std.string;
import std.algorithm;
import std.conv;
import std.format;
import debork.core.types;
import debork.core.logger;

class ChrootManager {

    /**
     * Validate that the chroot environment is functional
     */
    static bool validateChrootEnvironment(ref SystemInfo sysInfo) {
        Logger.info("Validating chroot environment");

        if (!sysInfo.isMounted) {
            Logger.error("System not mounted, cannot validate chroot");
            return false;
        }

        // Check essential directories
        if (!validateEssentialDirectories(sysInfo)) {
            return false;
        }

        // Detect available shells
        try {
            sysInfo.availableShells = detectAvailableShells(sysInfo);
            if (sysInfo.availableShells.length == 0) {
                Logger.error("No usable shells found in chroot environment");
                return false;
            }
        } catch (Exception e) {
            Logger.error("Shell detection failed: " ~ e.msg);
            return false;
        }

        // Detect package manager
        sysInfo.packageManager = detectPackageManager(sysInfo);
        if (sysInfo.packageManager == PackageManager.UNKNOWN) {
            Logger.warning("No recognized package manager found");
        }

        sysInfo.isValidated = true;
        Logger.info("Chroot environment validation passed");
        return true;
    }

    /**
     * Detect all available shells in the chroot environment
     */
    static string[] detectAvailableShells(ref SystemInfo sysInfo) {
        string[] shells;
        string[] shellPaths = [
            "/bin/bash",     "/usr/bin/bash",
            "/bin/sh",       "/usr/bin/sh",
            "/bin/dash",     "/usr/bin/dash",
            "/bin/ash",      "/usr/bin/ash",
            "/bin/zsh",      "/usr/bin/zsh",
            "/bin/fish",     "/usr/bin/fish",
            "/bin/ksh",      "/usr/bin/ksh"
        ];

        foreach (shellPath; shellPaths) {
            string fullPath = buildPath(sysInfo.mountPoint, shellPath[1..$]); // Remove leading slash
            if (exists(fullPath) && isFile(fullPath)) {
                // Verify the shell is executable
                try {
                    auto attrs = getAttributes(fullPath);
                    if (attrs & octal!755) { // Check if executable
                        shells ~= shellPath;
                        Logger.debugLog("Found available shell: " ~ shellPath);
                    }
                } catch (Exception e) {
                    Logger.debugLog("Failed to check shell " ~ shellPath ~ ": " ~ e.msg);
                }
            }
        }

        return shells;
    }

    /**
     * Get the best available shell for chroot operations
     */
    static string getBestShell(ref SystemInfo sysInfo) {
        if (sysInfo.availableShells.length == 0) {
            throw new Exception("No usable shells available in chroot environment");
        }

        // Preference order for shells
        string[] preferredOrder = [
            "/bin/bash", "/usr/bin/bash",  // Bash is most compatible
            "/bin/sh", "/usr/bin/sh",      // POSIX shell fallback
            "/bin/dash", "/usr/bin/dash",  // Debian default
            "/bin/ash", "/usr/bin/ash",    // Busybox shell
            "/bin/zsh", "/usr/bin/zsh",    // Z shell
            "/bin/fish", "/usr/bin/fish"   // Fish shell
        ];

        foreach (preferred; preferredOrder) {
            if (sysInfo.availableShells.canFind(preferred)) {
                Logger.debugLog("Selected shell: " ~ preferred);
                return preferred;
            }
        }

        // If no preferred shell found, use the first available
        Logger.debugLog("Using first available shell: " ~ sysInfo.availableShells[0]);
        return sysInfo.availableShells[0];
    }

    /**
     * Execute a command in the chroot environment using shell
     */
    static auto executeChrootCommand(ref SystemInfo sysInfo, string command) {
        string shell = getBestShell(sysInfo);
        string[] args = ["chroot", sysInfo.mountPoint, shell, "-c", command];

        Logger.debugLog("Executing chroot command: " ~ args.join(" "));
        return spawnProcess(args);
    }

    /**
     * Execute a command directly in chroot (no shell wrapper)
     */
    static auto executeChrootDirect(ref SystemInfo sysInfo, string[] command) {
        string[] args = ["chroot", sysInfo.mountPoint] ~ command;

        Logger.debugLog("Executing direct chroot: " ~ args.join(" "));
        return spawnProcess(args);
    }

    /**
     * Start an interactive shell in the chroot environment
     */
    static bool startInteractiveShell(ref SystemInfo sysInfo) {
        if (!sysInfo.isValidated) {
            if (!validateChrootEnvironment(sysInfo)) {
                Logger.error("Cannot start shell: chroot validation failed");
                return false;
            }
        }

        try {
            string shell = getBestShell(sysInfo);
            Logger.info("Starting interactive shell: " ~ shell);

            auto process = spawnProcess(["chroot", sysInfo.mountPoint, shell, "-l"]);
            auto exitCode = wait(process);

            Logger.info("Interactive shell exited with code: " ~ to!string(exitCode));
            return exitCode == 0;

        } catch (Exception e) {
            Logger.error("Failed to start interactive shell: " ~ e.msg);
            return false;
        }
    }

    /**
     * Test chroot functionality
     */
    static bool testChroot(ref SystemInfo sysInfo) {
        Logger.info("Testing chroot functionality");

        try {
            // Simple test: run 'echo' in chroot
            auto process = executeChrootCommand(sysInfo, "echo 'chroot test successful'");
            auto exitCode = wait(process);

            if (exitCode == 0) {
                Logger.info("Chroot test passed");
                return true;
            } else {
                Logger.error("Chroot test failed with exit code: " ~ to!string(exitCode));
                return false;
            }

        } catch (Exception e) {
            Logger.error("Chroot test exception: " ~ e.msg);
            return false;
        }
    }

    /**
     * Get detailed chroot environment information
     */
    static string[] getChrootInfo(ref SystemInfo sysInfo) {
        string[] info;

        info ~= "=== Chroot Environment Information ===";
        info ~= "Mount point: " ~ sysInfo.mountPoint;
        info ~= "Device: " ~ sysInfo.device;
        info ~= "Filesystem: " ~ sysInfo.fstype;
        info ~= "Validated: " ~ (sysInfo.isValidated ? "Yes" : "No");

        if (sysInfo.isBtrfs) {
            info ~= "Btrfs root subvolume: " ~ sysInfo.btrfsInfo.rootSubvolume;
        }

        info ~= "";
        info ~= "Available shells:";
        if (sysInfo.availableShells.length > 0) {
            foreach (shell; sysInfo.availableShells) {
                info ~= "  ✓ " ~ shell;
            }
        } else {
            info ~= "  ✗ No shells found";
        }

        info ~= "";
        info ~= "Package manager: " ~ packageManagerToString(sysInfo.packageManager);
        info ~= "Network config: " ~ (sysInfo.hasNetworking ? "Available" : "Not available");

        return info;
    }

    /**
     * Diagnose chroot issues and provide solutions
     */
    static string[] diagnoseChrootIssues(ref SystemInfo sysInfo) {
        string[] diagnosis;

        diagnosis ~= "=== Chroot Diagnosis ===";

        // Check if system is mounted
        if (!sysInfo.isMounted) {
            diagnosis ~= "✗ System not mounted";
            diagnosis ~= "  Solution: Mount your system partition first";
            return diagnosis;
        }

        // Check essential directories
        diagnosis ~= "Essential directories:";
        string[] essentialDirs = ["bin", "usr/bin", "sbin", "usr/sbin", "etc", "lib", "usr/lib"];
        bool missingDirs = false;

        foreach (dir; essentialDirs) {
            string fullPath = buildPath(sysInfo.mountPoint, dir);
            string status = exists(fullPath) ? "✓" : "✗";
            diagnosis ~= format("  %s /%s", status, dir);
            if (!exists(fullPath)) {
                missingDirs = true;
            }
        }

        if (missingDirs) {
            diagnosis ~= "";
            diagnosis ~= "Solutions for missing directories:";
            diagnosis ~= "• Wrong partition mounted (not Linux root)";
            diagnosis ~= "• Btrfs subvolume issue (try different subvolume)";
            diagnosis ~= "• Severely damaged system";
        }

        // Check shells
        diagnosis ~= "";
        diagnosis ~= "Available shells:";
        string[] detectedShells = detectAvailableShells(sysInfo);
        if (detectedShells.length > 0) {
            foreach (shell; detectedShells) {
                diagnosis ~= "  ✓ " ~ shell;
            }
        } else {
            diagnosis ~= "  ✗ No shells found";
            diagnosis ~= "";
            diagnosis ~= "Solutions for missing shells:";
            diagnosis ~= "• Boot from live USB and install: pacman -S bash";
            diagnosis ~= "• Check if /bin is a symlink to /usr/bin";
            diagnosis ~= "• System may be severely damaged";
        }

        // Check package manager
        diagnosis ~= "";
        PackageManager pm = detectPackageManager(sysInfo);
        diagnosis ~= "Package manager: " ~ packageManagerToString(pm);

        if (pm == PackageManager.UNKNOWN) {
            diagnosis ~= "  ✗ No recognized package manager found";
            diagnosis ~= "";
            diagnosis ~= "Solutions:";
            diagnosis ~= "• Verify this is a Linux root partition";
            diagnosis ~= "• Check for package manager in unusual locations";
            diagnosis ~= "• System may not be a supported distribution";
        }

        return diagnosis;
    }

    /**
     * Check if system has basic tools needed for repair
     */
    static bool hasEssentialTools(ref SystemInfo sysInfo) {
        string[] essentialTools = ["ls", "cat", "chmod", "chown"];

        foreach (tool; essentialTools) {
            string[] searchPaths = ["bin/" ~ tool, "usr/bin/" ~ tool];
            bool found = false;

            foreach (path; searchPaths) {
                string fullPath = buildPath(sysInfo.mountPoint, path);
                if (exists(fullPath)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                Logger.warning("Essential tool missing: " ~ tool);
                return false;
            }
        }

        return true;
    }

    /**
     * Get chroot environment status summary
     */
    static string getChrootStatus(ref SystemInfo sysInfo) {
        if (!sysInfo.isMounted) {
            return "Not mounted";
        }

        if (!sysInfo.isValidated) {
            return "Mounted but not validated";
        }

        if (sysInfo.availableShells.length == 0) {
            return "No shells available";
        }

        if (sysInfo.packageManager == PackageManager.UNKNOWN) {
            return "Ready (no package manager)";
        }

        return "Ready for operations";
    }

    /**
     * Export environment variables for chroot
     */
    static string[] getChrootEnvironment() {
        import std.process : environment;
        return [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            "TERM=" ~ environment.get("TERM", "xterm"),
            "LANG=C.UTF-8"
        ];
    }

    // Private helper functions

    private static bool validateEssentialDirectories(ref SystemInfo sysInfo) {
        string[] essentialDirs = ["bin", "usr/bin", "sbin", "usr/sbin", "etc", "lib", "usr/lib"];
        bool allPresent = true;

        foreach (dir; essentialDirs) {
            string fullPath = buildPath(sysInfo.mountPoint, dir);
            if (!exists(fullPath)) {
                Logger.error("Missing essential directory: /" ~ dir);
                allPresent = false;
            }
        }

        if (!allPresent) {
            Logger.error("System validation failed: missing essential directories");
            Logger.info("This suggests:");
            Logger.info("• Wrong partition mounted (not a Linux root filesystem)");
            Logger.info("• Btrfs subvolume mounting issue");
            Logger.info("• Severely damaged system installation");
        }

        return allPresent;
    }

    private static PackageManager detectPackageManager(ref SystemInfo sysInfo) {
        struct PMInfo {
            PackageManager type;
            string path;
            string name;
        }

        PMInfo[] packageManagers = [
            PMInfo(PackageManager.PACMAN, "usr/bin/pacman", "pacman"),
            PMInfo(PackageManager.PACMAN, "bin/pacman", "pacman"),
            PMInfo(PackageManager.APT, "usr/bin/apt", "apt"),
            PMInfo(PackageManager.APT, "bin/apt", "apt"),
            PMInfo(PackageManager.YUM, "usr/bin/yum", "yum"),
            PMInfo(PackageManager.YUM, "bin/yum", "yum"),
            PMInfo(PackageManager.DNF, "usr/bin/dnf", "dnf"),
            PMInfo(PackageManager.DNF, "bin/dnf", "dnf"),
            PMInfo(PackageManager.ZYPPER, "usr/bin/zypper", "zypper"),
            PMInfo(PackageManager.ZYPPER, "bin/zypper", "zypper")
        ];

        foreach (pm; packageManagers) {
            string fullPath = buildPath(sysInfo.mountPoint, pm.path);
            if (exists(fullPath) && isFile(fullPath)) {
                Logger.logDetection("package manager", pm.name ~ " at /" ~ pm.path);
                return pm.type;
            }
        }

        Logger.warning("No recognized package manager found");
        return PackageManager.UNKNOWN;
    }

    private static string packageManagerToString(PackageManager pm) {
        final switch (pm) {
            case PackageManager.UNKNOWN: return "Unknown";
            case PackageManager.PACMAN:  return "pacman (Arch Linux)";
            case PackageManager.APT:     return "apt (Debian/Ubuntu)";
            case PackageManager.YUM:     return "yum (Red Hat/CentOS)";
            case PackageManager.DNF:     return "dnf (Fedora)";
            case PackageManager.ZYPPER:  return "zypper (openSUSE)";
        }
    }
}
