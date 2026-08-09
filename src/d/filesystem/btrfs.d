module debork.filesystem.btrfs;

import std.process;
import std.file;
import std.path;
import std.string;
import std.algorithm;
import std.conv;
import std.regex;
import std.format;
import std.array;
import debork.core.types;
import debork.core.logger;

class BtrfsManager {

    /**
     * Mount a btrfs filesystem with proper subvolume detection
     */
    static bool mountWithSubvolume(ref SystemInfo sysInfo, string device) {
        Logger.info("Mounting btrfs filesystem: " ~ device);

        try {
            // Step 1: Detect all subvolumes
            BtrfsSubvolume[] subvols = detectSubvolumes(device);
            sysInfo.btrfsInfo.subvolumes = subvols;

            if (subvols.length == 0) {
                Logger.warning("No subvolumes detected, mounting default");
                Logger.info("No subvolumes detected, mounting with default options");
                return mountDefault(sysInfo, device);
            }

            // Step 2: Find the root subvolume
            string rootSubvol = detectRootSubvolume(subvols);

            if (rootSubvol.length > 0) {
                Logger.info("Detected root subvolume: " ~ rootSubvol);
                sysInfo.btrfsInfo.rootSubvolume = rootSubvol;
                return mountWithSpecificSubvolume(sysInfo, device, rootSubvol);
            } else {
                Logger.warning("No root subvolume detected, trying common patterns");
                // Try CachyOS specific patterns first
                if (tryMountCachyOS(sysInfo, device)) {
                    return true;
                }
                return tryCommonSubvolumePatterns(sysInfo, device);
            }

        } catch (Exception e) {
            Logger.error("Exception in btrfs mounting: " ~ e.msg);
            return false;
        }
    }

    /**
     * Try to mount CachyOS specific layout
     */
    private static bool tryMountCachyOS(ref SystemInfo sysInfo, string device) {
        Logger.info("Attempting CachyOS-specific mount configuration");

        // CachyOS typically uses @ for root and @home for home
        string[] cachyPatterns = ["@", "@root"];

        foreach (pattern; cachyPatterns) {
            Logger.info("Trying CachyOS pattern: " ~ pattern);
            if (mountWithSpecificSubvolume(sysInfo, device, pattern)) {
                Logger.info("Successfully mounted with CachyOS pattern: " ~ pattern);

                // Try to mount @home subvolume if it exists
                string homeMount = sysInfo.mountPoint ~ "/home";
                if (exists(homeMount)) {
                    auto homeResult = execute(["mount", "-o", "subvol=@home", device, homeMount]);
                    if (homeResult.status == 0) {
                        Logger.info("Mounted @home subvolume");
                    }
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Detect all subvolumes in a btrfs filesystem
     */
    static BtrfsSubvolume[] detectSubvolumes(string device) {
        BtrfsSubvolume[] subvols;
        string tempMount = "/tmp/debork_btrfs_detect";

        try {
            // Create temporary mount point
            if (!exists(tempMount)) {
                mkdirRecurse(tempMount);
            }

            // Mount temporarily to detect subvolumes
            Logger.debugLog("Temporarily mounting " ~ device ~ " to detect subvolumes");
            auto mountResult = execute(["mount", "-o", "ro", device, tempMount]);
            if (mountResult.status != 0) {
                Logger.error("Failed to temporarily mount for subvolume detection: " ~ mountResult.output);
                return subvols;
            }

            // List subvolumes
            auto listResult = execute(["btrfs", "subvolume", "list", tempMount]);
            if (listResult.status == 0) {
                subvols = parseSubvolumeList(listResult.output);
                Logger.info(format("Found %d btrfs subvolumes", subvols.length));

                // Log all detected subvolumes in debug mode
                foreach (subvol; subvols) {
                    Logger.debugLog(format("Subvolume ID=%d path='%s' topLevel=%s",
                                       subvol.id, subvol.path, subvol.topLevel));
                }
            } else {
                Logger.error("Failed to list subvolumes: " ~ listResult.output);
            }

            // Clean up temporary mount
            auto umountResult = execute(["umount", tempMount]);
            if (umountResult.status != 0) {
                Logger.warning("Failed to unmount temporary mount: " ~ umountResult.output);
            }

        } catch (Exception e) {
            Logger.error("Exception during subvolume detection: " ~ e.msg);

            // Try to clean up if possible
            try {
                execute(["umount", tempMount]);
            } catch (Exception cleanupE) {
                // Ignore cleanup errors
            }
        }

        return subvols;
    }

    /**
     * Parse btrfs subvolume list output
     */
    private static BtrfsSubvolume[] parseSubvolumeList(string output) {
        BtrfsSubvolume[] subvols;
        auto lines = output.split("\n");

        foreach (line; lines) {
            line = line.strip();
            if (line.length == 0) continue;

            // Parse format: "ID 256 gen 12345 top level 5 path @"
            auto match = matchFirst(line, regex(`ID (\d+) gen (\d+) top level (\d+) path (.+)`));
            if (match) {
                BtrfsSubvolume subvol;
                subvol.id = to!int(match[1]);
                subvol.generation = to!int(match[2]);
                subvol.topLevel = match[3];
                subvol.path = match[4].strip();

                // Mark common root subvolumes
                subvol.isRoot = isLikelyRootSubvolume(subvol.path);

                subvols ~= subvol;
            }
        }

        return subvols;
    }

    /**
     * Detect which subvolume is the root filesystem
     */
    private static string detectRootSubvolume(BtrfsSubvolume[] subvols) {
        // Priority order for root subvolume detection
        string[] rootPatterns = [
            "@",            // Most common for Arch/CachyOS
            "root",         // Some distributions
            "rootfs",       // Alternative naming
            "@rootfs",      // Another variant
            "/"             // Literal root
        ];

        // First pass: Look for exact matches
        foreach (pattern; rootPatterns) {
            foreach (subvol; subvols) {
                if (subvol.path == pattern) {
                    Logger.debugLog("Found exact root subvolume match: " ~ pattern);
                    return pattern;
                }
            }
        }

        // Second pass: Look for subvolumes marked as likely root
        foreach (subvol; subvols) {
            if (subvol.isRoot) {
                Logger.debugLog("Found likely root subvolume: " ~ subvol.path);
                return subvol.path;
            }
        }

        // Third pass: Look for top-level subvolumes (common pattern)
        foreach (subvol; subvols) {
            if (subvol.topLevel == "5" && subvol.path.length > 0 &&
                !subvol.path.startsWith("@") && subvol.path != "var/lib/portables") {
                Logger.debugLog("Found potential root subvolume (top-level): " ~ subvol.path);
                return subvol.path;
            }
        }

        return ""; // No root subvolume found
    }

    /**
     * Check if a subvolume path is likely to be a root filesystem
     */
    private static bool isLikelyRootSubvolume(string path) {
        // Common root subvolume patterns
        string[] rootPatterns = ["@", "root", "rootfs", "@rootfs"];

        foreach (pattern; rootPatterns) {
            if (path == pattern) {
                return true;
            }
        }

        // Avoid home, var, tmp, cache, etc.
        string[] nonRootPatterns = [
            "@home", "@var", "@tmp", "@cache", "@log", "@srv", "@root",
            "home", "var", "tmp", "cache", "log", "srv", "swap",
            "var/lib", "var/cache", "var/log"
        ];

        foreach (pattern; nonRootPatterns) {
            if (path.startsWith(pattern)) {
                return false;
            }
        }

        return false;
    }

    /**
     * Mount btrfs with a specific subvolume
     */
    private static bool mountWithSpecificSubvolume(ref SystemInfo sysInfo, string device, string subvol) {
        Logger.info("Mounting btrfs with subvolume: " ~ subvol);

        string[] mountArgs = ["mount", "-o", "subvol=" ~ subvol, device, sysInfo.mountPoint];

        auto result = execute(mountArgs);
        if (result.status != 0) {
            Logger.error("Failed to mount with subvolume " ~ subvol ~ ": " ~ result.output);
            return false;
        }

        sysInfo.btrfsInfo.rootSubvolume = subvol;
        Logger.logMount(device, sysInfo.mountPoint, true, "subvol=" ~ subvol);

        // Verify the mount worked and contains a Linux system
        if (!validateLinuxSystem(sysInfo)) {
            Logger.warning("Mounted subvolume doesn't contain a valid Linux system");
            // Don't fail here, let validation handle it
        }

        // Mount additional subvolumes
        mountAdditionalSubvolumes(sysInfo, device);

        return true;
    }

    /**
     * Try common subvolume naming patterns
     */
    private static bool tryCommonSubvolumePatterns(ref SystemInfo sysInfo, string device) {
        string[] commonPatterns = ["@", "root", "rootfs", "@rootfs"];

        foreach (pattern; commonPatterns) {
            Logger.info("Trying common subvolume pattern: " ~ pattern);

            try {
                if (mountWithSpecificSubvolume(sysInfo, device, pattern)) {
                    if (validateLinuxSystem(sysInfo)) {
                        Logger.info("Successfully mounted with pattern: " ~ pattern);
                        return true;
                    } else {
                        // Unmount and try next pattern
                        execute(["umount", sysInfo.mountPoint]);
                    }
                }
            } catch (Exception e) {
                Logger.debugLog("Pattern " ~ pattern ~ " failed: " ~ e.msg);
                execute(["umount", sysInfo.mountPoint]); // Cleanup
            }
        }

        Logger.warning("All common subvolume patterns failed");
        return mountDefault(sysInfo, device);
    }

    /**
     * Mount btrfs with default subvolume
     */
    private static bool mountDefault(ref SystemInfo sysInfo, string device) {
        Logger.info("Mounting btrfs with default subvolume");

        auto result = execute(["mount", device, sysInfo.mountPoint]);
        if (result.status != 0) {
            Logger.error("Failed to mount btrfs default: " ~ result.output);
            return false;
        }

        Logger.logMount(device, sysInfo.mountPoint, true, "default subvolume");
        return true;
    }

    /**
     * Mount additional btrfs subvolumes if they exist
     */
    private static void mountAdditionalSubvolumes(ref SystemInfo sysInfo, string device) {
        string[] commonSubvols = ["@home", "@root", "@srv", "@cache", "@tmp", "@log", "@var"];

        foreach (subvol; commonSubvols) {
            string mountPoint = buildPath(sysInfo.mountPoint, subvol[1..$]); // Remove @
            if (exists(mountPoint)) {
                Logger.debugLog("Mounting additional subvolume: " ~ subvol);
                auto result = execute(["mount", "-o", "subvol=" ~ subvol, device, mountPoint]);
                if (result.status == 0) {
                    sysInfo.btrfsInfo.mountedSubvolumes ~= subvol;
                    Logger.debugLog("Successfully mounted " ~ subvol);
                } else {
                    Logger.debugLog("Failed to mount " ~ subvol ~ ": " ~ result.output);
                }
            }
        }
    }

    /**
     * Validate that the mounted filesystem contains a Linux system
     */
    private static bool validateLinuxSystem(ref SystemInfo sysInfo) {
        // Check for essential directories
        string[] essentialDirs = ["usr/bin", "etc", "lib"];

        foreach (dir; essentialDirs) {
            string fullPath = buildPath(sysInfo.mountPoint, dir);
            if (!exists(fullPath)) {
                Logger.debugLog("Missing essential directory for Linux system: " ~ dir);
                return false;
            }
        }

        // Check for at least one common Linux file
        string[] linuxFiles = ["etc/passwd", "usr/bin/ls", "bin/sh", "usr/bin/bash"];

        foreach (file; linuxFiles) {
            string fullPath = buildPath(sysInfo.mountPoint, file);
            if (exists(fullPath)) {
                Logger.debugLog("Found Linux system indicator: " ~ file);
                return true;
            }
        }

        Logger.debugLog("No clear Linux system indicators found");
        return false;
    }

    /**
     * Get detailed information about btrfs filesystem
     */
    static BtrfsInfo getBtrfsInfo(string device) {
        BtrfsInfo info;

        try {
            info.subvolumes = detectSubvolumes(device);
            info.rootSubvolume = detectRootSubvolume(info.subvolumes);
        } catch (Exception e) {
            Logger.error("Failed to get btrfs info: " ~ e.msg);
        }

        return info;
    }

    /**
     * List all subvolumes in a readable format
     */
    static string[] listSubvolumes(ref SystemInfo sysInfo) {
        string[] result;

        foreach (subvol; sysInfo.btrfsInfo.subvolumes) {
            string rootIndicator = subvol.isRoot ? " (ROOT)" : "";
            string mountedIndicator = sysInfo.btrfsInfo.mountedSubvolumes.canFind(subvol.path) ? " [MOUNTED]" : "";

            result ~= format("ID %d: %s%s%s", subvol.id, subvol.path, rootIndicator, mountedIndicator);
        }

        return result;
    }

    /**
     * Check if btrfs tools are available
     */
    static bool isBtrfsSupported() {
        try {
            auto result = execute(["btrfs", "--version"]);
            return result.status == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get btrfs filesystem info without mounting
     */
    static string getBtrfsFilesystemInfo(string device) {
        try {
            auto result = execute(["btrfs", "filesystem", "show", device]);
            if (result.status == 0) {
                return result.output;
            }
        } catch (Exception e) {
            Logger.debugLog("Failed to get btrfs filesystem info: " ~ e.msg);
        }

        return "";
    }

    /**
     * Unmount all btrfs subvolumes
     */
    static bool unmountAll(ref SystemInfo sysInfo) {
        bool success = true;

        // Unmount additional subvolumes first
        foreach_reverse (subvol; sysInfo.btrfsInfo.mountedSubvolumes) {
            string mountPoint = buildPath(sysInfo.mountPoint, subvol[1..$]);
            auto result = execute(["umount", mountPoint]);
            if (result.status != 0) {
                Logger.warning("Failed to unmount " ~ subvol ~ ": " ~ result.output);
                success = false;
            }
        }

        // Clear the mounted list
        sysInfo.btrfsInfo.mountedSubvolumes = [];

        return success;
    }

    /**
     * Repair btrfs filesystem if needed
     */
    static bool repairFilesystem(string device) {
        Logger.info("Checking btrfs filesystem: " ~ device);

        try {
            // Check filesystem
            auto checkResult = execute(["btrfs", "check", "--readonly", device]);
            if (checkResult.status == 0) {
                Logger.info("Btrfs filesystem check passed");
                return true;
            } else {
                Logger.warning("Btrfs filesystem has issues: " ~ checkResult.output);

                // Ask user before attempting repair
                Logger.info("Btrfs filesystem repair is risky and should be done manually");
                Logger.info("Recommended: Boot from live USB and run 'btrfs check --repair " ~ device ~ "'");
                return false;
            }
        } catch (Exception e) {
            Logger.error("Exception during btrfs check: " ~ e.msg);
            return false;
        }
    }
}
