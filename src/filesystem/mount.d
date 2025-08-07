module debork.filesystem.mount;

import std.process;
import std.file;
import std.path;
import std.string;
import std.algorithm;
import std.conv;
import std.format;
import debork.core.types;
import debork.core.logger;
import debork.filesystem.btrfs;

class MountManager {

    /**
     * Mount a system from the given device
     */
    static bool mountSystem(ref SystemInfo sysInfo, string device) {
        Logger.info("Mounting system from " ~ device);

        try {
            // Create mount point
            if (!exists(sysInfo.mountPoint)) {
                mkdirRecurse(sysInfo.mountPoint);
            }

            // Detect filesystem type
            if (!detectFilesystemType(sysInfo, device)) {
                Logger.error("Failed to detect filesystem type for device: " ~ device);
                return false;
            }
            Logger.info("Detected filesystem: " ~ sysInfo.fstype ~ (sysInfo.isBtrfs ? " (btrfs)" : ""));

            // Store device information
            sysInfo.device = device;
            detectUUID(sysInfo, device);

            // Mount based on filesystem type
            bool mountSuccess = false;
            if (sysInfo.isBtrfs) {
                Logger.info("Attempting btrfs mount with subvolume detection");
                mountSuccess = BtrfsManager.mountWithSubvolume(sysInfo, device);
            } else {
                Logger.info("Attempting regular filesystem mount");
                mountSuccess = mountRegularFilesystem(sysInfo, device);
            }

            if (!mountSuccess) {
                Logger.error("Mount operation failed for device: " ~ device);
                return false;
            }
            Logger.info("Mount operation successful");

            // Set up boot directories
            setupBootDirectories(sysInfo);

            // Mount essential directories for chroot
            Logger.info("Bind mounting essential directories for chroot");
            if (!bindMountEssentialDirectories(sysInfo)) {
                Logger.warning("Some essential directories failed to mount");
            } else {
                Logger.info("Essential directories mounted successfully");
            }

            // Mount EFI partition if found
            Logger.info("Checking for EFI partition");
            if (!mountEfiPartition(sysInfo)) {
                Logger.info("No EFI partition found or failed to mount");
            } else {
                Logger.info("EFI partition mounted successfully");
            }

            // Copy network configuration
            copyNetworkConfiguration(sysInfo);

            sysInfo.isMounted = true;
            Logger.info("System mounted successfully at " ~ sysInfo.mountPoint);
            return true;

        } catch (Exception e) {
            Logger.error("Exception mounting system: " ~ e.msg);
            return false;
        }
    }

    /**
     * Detect filesystem type and set system info
     */
    private static bool detectFilesystemType(ref SystemInfo sysInfo, string device) {
        try {
            auto fstypeResult = execute(["blkid", "-s", "TYPE", "-o", "value", device]);
            if (fstypeResult.status == 0) {
                sysInfo.fstype = fstypeResult.output.strip();
                sysInfo.isBtrfs = (sysInfo.fstype == "btrfs");

                // Map string to enum
                switch (sysInfo.fstype) {
                    case "ext4":
                        sysInfo.filesystemType = FilesystemType.EXT4;
                        break;
                    case "ext3":
                        sysInfo.filesystemType = FilesystemType.EXT3;
                        break;
                    case "ext2":
                        sysInfo.filesystemType = FilesystemType.EXT2;
                        break;
                    case "btrfs":
                        sysInfo.filesystemType = FilesystemType.BTRFS;
                        break;
                    case "xfs":
                        sysInfo.filesystemType = FilesystemType.XFS;
                        break;
                    case "f2fs":
                        sysInfo.filesystemType = FilesystemType.F2FS;
                        break;
                    case "reiserfs":
                        sysInfo.filesystemType = FilesystemType.REISERFS;
                        break;
                    default:
                        sysInfo.filesystemType = FilesystemType.UNKNOWN;
                        break;
                }

                Logger.logDetection("filesystem type", sysInfo.fstype);
                return true;
            } else {
                Logger.error("Failed to detect filesystem type: " ~ fstypeResult.output);
                return false;
            }
        } catch (Exception e) {
            Logger.error("Exception detecting filesystem type: " ~ e.msg);
            return false;
        }
    }

    /**
     * Detect and store UUID
     */
    private static void detectUUID(ref SystemInfo sysInfo, string device) {
        try {
            auto uuidResult = execute(["blkid", "-s", "UUID", "-o", "value", device]);
            if (uuidResult.status == 0) {
                sysInfo.uuid = uuidResult.output.strip();
                Logger.logDetection("UUID", sysInfo.uuid);
            }
        } catch (Exception e) {
            Logger.debugLog("Failed to get UUID: " ~ e.msg);
        }
    }

    /**
     * Mount regular (non-btrfs) filesystem
     */
    private static bool mountRegularFilesystem(ref SystemInfo sysInfo, string device) {
        auto result = execute(["mount", device, sysInfo.mountPoint]);
        if (result.status != 0) {
            Logger.error("Failed to mount " ~ device ~ ": " ~ result.output);
            return false;
        }

        Logger.logMount(device, sysInfo.mountPoint, true);
        return true;
    }

    /**
     * Set up boot directory paths
     */
    private static void setupBootDirectories(ref SystemInfo sysInfo) {
        sysInfo.bootDir = buildPath(sysInfo.mountPoint, "boot");
        sysInfo.efiDir = sysInfo.bootDir; // Default, may be updated later

        Logger.debugLog("Boot directory: " ~ sysInfo.bootDir);
    }

    /**
     * Bind mount essential directories for chroot
     */
    static bool bindMountEssentialDirectories(ref SystemInfo sysInfo) {
        string[] essentialDirs = ["/dev", "/proc", "/sys", "/run"];
        bool allSuccess = true;

        foreach (dir; essentialDirs) {
            string targetDir = buildPath(sysInfo.mountPoint, dir[1..$]); // Remove leading slash

            // Create target directory if it doesn't exist
            if (!exists(targetDir)) {
                try {
                    mkdirRecurse(targetDir);
                } catch (Exception e) {
                    Logger.warning("Failed to create directory " ~ targetDir ~ ": " ~ e.msg);
                    allSuccess = false;
                    continue;
                }
            }

            // Bind mount
            auto result = execute(["mount", "--bind", dir, targetDir]);
            if (result.status == 0) {
                Logger.debugLog("Bind mounted " ~ dir ~ " to " ~ targetDir);
            } else {
                Logger.warning("Failed to bind mount " ~ dir ~ ": " ~ result.output);
                allSuccess = false;
            }
        }

        return allSuccess;
    }

    /**
     * Detect and mount EFI system partition
     */
    private static bool mountEfiPartition(ref SystemInfo sysInfo) {
        // Common EFI directory locations
        string[] efiPaths = [
            buildPath(sysInfo.mountPoint, "boot/efi"),
            buildPath(sysInfo.mountPoint, "efi"),
            buildPath(sysInfo.mountPoint, "boot/EFI")
        ];

        foreach (efiPath; efiPaths) {
            if (exists(efiPath)) {
                sysInfo.efiDir = efiPath;
                Logger.debugLog("Found EFI directory: " ~ efiPath);

                // Try to find and mount EFI system partition
                string efiDevice = detectEfiDevice();
                if (efiDevice.length > 0) {
                    auto result = execute(["mount", efiDevice, efiPath]);
                    if (result.status == 0) {
                        Logger.info("Mounted EFI partition " ~ efiDevice ~ " at " ~ efiPath);
                        return true;
                    } else {
                        Logger.warning("Failed to mount EFI partition: " ~ result.output);
                    }
                }
                return true; // Directory exists even if mount failed
            }
        }

        Logger.debugLog("No EFI directory found");
        return false;
    }

    /**
     * Detect EFI system partition device
     */
    private static string detectEfiDevice() {
        try {
            // Look for currently mounted EFI partition
            auto result = execute(["findmnt", "-n", "-o", "SOURCE", "-t", "vfat", "/boot/efi"]);
            if (result.status == 0) {
                return result.output.strip();
            }

            // Look for EFI partitions by type
            result = execute(["lsblk", "-n", "-o", "NAME,FSTYPE", "-t", "part"]);
            if (result.status == 0) {
                auto lines = result.output.split("\n");
                foreach (line; lines) {
                    if (line.canFind("vfat")) {
                        auto parts = line.split();
                        if (parts.length >= 1) {
                            string device = "/dev/" ~ parts[0].strip();
                            // Additional validation could go here
                            return device;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Logger.debugLog("Exception detecting EFI device: " ~ e.msg);
        }

        return "";
    }

    /**
     * Copy network configuration for chroot internet access
     */
    private static void copyNetworkConfiguration(ref SystemInfo sysInfo) {
        string[] networkFiles = [
            "/etc/resolv.conf",
            "/etc/hosts"
        ];

        foreach (file; networkFiles) {
            if (exists(file)) {
                string targetFile = buildPath(sysInfo.mountPoint, file[1..$]);
                try {
                    copy(file, targetFile);
                    Logger.debugLog("Copied " ~ file ~ " to chroot");
                    sysInfo.hasNetworking = true;
                } catch (Exception e) {
                    Logger.warning("Failed to copy " ~ file ~ ": " ~ e.msg);
                }
            }
        }
    }

    /**
     * Unmount system and all associated mounts
     */
    static bool unmountSystem(ref SystemInfo sysInfo) {
        Logger.info("Unmounting system");
        bool allSuccess = true;

        if (!sysInfo.isMounted) {
            Logger.debugLog("System not mounted, skipping unmount");
            return true;
        }

        try {
            // Unmount btrfs subvolumes first if applicable
            if (sysInfo.isBtrfs) {
                if (!BtrfsManager.unmountAll(sysInfo)) {
                    allSuccess = false;
                }
            }

            // Unmount essential directories (in reverse order)
            string[] mountPoints = [
                buildPath(sysInfo.mountPoint, "boot/efi"),
                buildPath(sysInfo.mountPoint, "run"),
                buildPath(sysInfo.mountPoint, "sys"),
                buildPath(sysInfo.mountPoint, "proc"),
                buildPath(sysInfo.mountPoint, "dev")
            ];

            foreach (mountPoint; mountPoints) {
                auto result = execute(["umount", mountPoint]);
                if (result.status != 0) {
                    Logger.debugLog("Failed to unmount " ~ mountPoint ~ " (may not be mounted)");
                }
            }

            // Finally unmount the main filesystem
            auto result = execute(["umount", sysInfo.mountPoint]);
            if (result.status == 0) {
                Logger.info("Successfully unmounted system");
                sysInfo.isMounted = false;
            } else {
                Logger.error("Failed to unmount main filesystem: " ~ result.output);

                // Try lazy unmount as fallback
                result = execute(["umount", "-l", sysInfo.mountPoint]);
                if (result.status == 0) {
                    Logger.info("Successfully lazy unmounted system");
                    sysInfo.isMounted = false;
                } else {
                    Logger.error("Even lazy unmount failed: " ~ result.output);
                    allSuccess = false;
                }
            }

        } catch (Exception e) {
            Logger.error("Exception during unmount: " ~ e.msg);
            allSuccess = false;
        }

        return allSuccess;
    }

    /**
     * Check if a device is currently mounted
     */
    static bool isDeviceMounted(string device) {
        try {
            auto result = execute(["findmnt", "-n", "-S", device]);
            return result.status == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get mount point of a device if mounted
     */
    static string getDeviceMountPoint(string device) {
        try {
            auto result = execute(["findmnt", "-n", "-o", "TARGET", "-S", device]);
            if (result.status == 0) {
                return result.output.strip();
            }
        } catch (Exception e) {
            Logger.debugLog("Exception getting mount point for " ~ device ~ ": " ~ e.msg);
        }
        return "";
    }

    /**
     * Force unmount a device from all mount points
     */
    static bool forceUnmountDevice(string device) {
        try {
            // Get all mount points for this device
            auto result = execute(["findmnt", "-n", "-o", "TARGET", "-S", device]);
            if (result.status == 0) {
                auto mountPoints = result.output.split("\n");
                foreach (mountPoint; mountPoints) {
                    mountPoint = mountPoint.strip();
                    if (mountPoint.length > 0) {
                        Logger.info("Force unmounting " ~ mountPoint);
                        execute(["umount", "-l", mountPoint]); // Lazy unmount
                    }
                }
                return true;
            }
        } catch (Exception e) {
            Logger.error("Exception force unmounting " ~ device ~ ": " ~ e.msg);
        }
        return false;
    }

    /**
     * Validate that all essential mounts are in place
     */
    static bool validateMounts(ref SystemInfo sysInfo) {
        if (!sysInfo.isMounted) {
            return false;
        }

        // Check main mount
        if (!exists(sysInfo.mountPoint)) {
            Logger.error("Mount point doesn't exist: " ~ sysInfo.mountPoint);
            return false;
        }

        // Check essential directories are accessible
        string[] essentialDirs = ["dev", "proc", "sys"];
        foreach (dir; essentialDirs) {
            string fullPath = buildPath(sysInfo.mountPoint, dir);
            if (!exists(fullPath)) {
                Logger.warning("Essential directory not accessible: " ~ dir);
                return false;
            }
        }

        Logger.debugLog("Mount validation passed");
        return true;
    }

    /**
     * Remount with different options if needed
     */
    static bool remountWithOptions(ref SystemInfo sysInfo, string options) {
        if (!sysInfo.isMounted) {
            Logger.error("Cannot remount: system not mounted");
            return false;
        }

        try {
            auto result = execute(["mount", "-o", "remount," ~ options, sysInfo.mountPoint]);
            if (result.status == 0) {
                Logger.info("Successfully remounted with options: " ~ options);
                return true;
            } else {
                Logger.error("Failed to remount with options: " ~ result.output);
                return false;
            }
        } catch (Exception e) {
            Logger.error("Exception during remount: " ~ e.msg);
            return false;
        }
    }

    /**
     * Get detailed mount information
     */
    static string[] getMountInfo(ref SystemInfo sysInfo) {
        string[] info;

        try {
            auto result = execute(["findmnt", "-D", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", sysInfo.mountPoint]);
            if (result.status == 0) {
                info = result.output.split("\n");
            }
        } catch (Exception e) {
            Logger.debugLog("Failed to get mount info: " ~ e.msg);
        }

        return info;
    }
}
