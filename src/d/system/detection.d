module debork.system.detection;

import std.process;
import std.file;
import std.path;
import std.string;
import std.algorithm;
import std.conv;
import std.format;
import std.regex;
import std.json;
import std.array;
import debork.core.types;
import debork.core.logger;

class SystemDetection {

    /**
     * Scan for all available partitions that could contain Linux systems
     */
    static PartitionInfo[] scanPartitions() {
        Logger.info("Scanning for Linux partitions");
        PartitionInfo[] partitions;

        try {
            // Method 1: Use lsblk to get comprehensive partition info
            partitions = scanWithLsblk();

            if (partitions.length > 0) {
                Logger.info(format("Found %d potential Linux partitions with lsblk", partitions.length));
                return partitions;
            }

            // Method 2: Fallback to manual scanning
            Logger.warning("lsblk failed, trying manual partition detection");
            partitions = scanCommonDevices();

        } catch (Exception e) {
            Logger.error("Exception during partition scanning: " ~ e.msg);
        }

        return partitions;
    }

    /**
     * Scan partitions using lsblk for comprehensive info
     */
    private static PartitionInfo[] scanWithLsblk() {
        PartitionInfo[] partitions;

        try {
            // Get partition info in JSON format for easier parsing
            auto result = execute(["lsblk", "-J", "-o", "NAME,UUID,LABEL,FSTYPE,MOUNTPOINT,SIZE,TYPE"]);
            if (result.status != 0) {
                Logger.error("lsblk failed: " ~ result.output);
                return partitions;
            }

            // Parse JSON output
            try {
                JSONValue jsonData = parseJSON(result.output);
                if ("blockdevices" in jsonData) {
                    partitions = parseBlockDevices(jsonData["blockdevices"]);
                }
            } catch (Exception e) {
                Logger.warning("Failed to parse lsblk JSON, falling back to text parsing");
                partitions = parseLsblkText(result.output);
            }

        } catch (Exception e) {
            Logger.error("Exception in lsblk scanning: " ~ e.msg);
        }

        return partitions;
    }

    /**
     * Parse lsblk JSON output
     */
    private static PartitionInfo[] parseBlockDevices(JSONValue blockdevices) {
        PartitionInfo[] partitions;

        foreach (device; blockdevices.array) {
            // Process main device
            if ("children" in device) {
                foreach (child; device["children"].array) {
                    auto partition = parsePartitionFromJSON(child);
                    if (partition.isLinuxRoot) {
                        partitions ~= partition;
                    }
                }
            } else {
                auto partition = parsePartitionFromJSON(device);
                if (partition.isLinuxRoot) {
                    partitions ~= partition;
                }
            }
        }

        return partitions;
    }

    /**
     * Parse individual partition from JSON
     */
    private static PartitionInfo parsePartitionFromJSON(JSONValue partJson) {
        PartitionInfo partition;

        if ("name" in partJson && partJson["name"].type == JSONType.string) {
            partition.device = "/dev/" ~ partJson["name"].str;
        }

        if ("uuid" in partJson && partJson["uuid"].type == JSONType.string) {
            partition.uuid = partJson["uuid"].str;
        }

        if ("label" in partJson && partJson["label"].type == JSONType.string) {
            partition.label = partJson["label"].str;
        }

        if ("fstype" in partJson && partJson["fstype"].type == JSONType.string) {
            partition.fstype = partJson["fstype"].str;
        }

        if ("mountpoint" in partJson && partJson["mountpoint"].type == JSONType.string) {
            partition.mountpoint = partJson["mountpoint"].str;
            partition.isMounted = (partition.mountpoint.length > 0);
        }

        if ("size" in partJson && partJson["size"].type == JSONType.string) {
            partition.size = partJson["size"].str;
        }

        // Determine if this is likely a Linux root partition
        partition.isLinuxRoot = isLikelyLinuxPartition(partition);

        return partition;
    }

    /**
     * Fallback text parsing for lsblk output
     */
    private static PartitionInfo[] parseLsblkText(string output) {
        PartitionInfo[] partitions;
        auto lines = output.split("\n");

        foreach (line; lines) {
            if (line.canFind("/dev/") && isLinuxFilesystemType(line)) {
                PartitionInfo partition;

                // Simple parsing - extract device name
                auto parts = line.split();
                if (parts.length > 0) {
                    string devName = parts[0];
                    // Remove tree characters from lsblk output
                    devName = devName.replaceAll(regex(`[├└│─]`), "");
                    devName = devName.strip();

                    if (!devName.startsWith("/dev/")) {
                        devName = "/dev/" ~ devName;
                    }

                    partition.device = devName;
                    partition.isLinuxRoot = true; // Assume if we got here
                    partitions ~= partition;
                }
            }
        }

        return partitions;
    }

    /**
     * Check if line contains Linux filesystem types
     */
    private static bool isLinuxFilesystemType(string line) {
        string[] linuxFilesystems = ["ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "reiserfs"];

        foreach (fs; linuxFilesystems) {
            if (line.canFind(fs)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine if partition is likely to contain a Linux system
     */
    private static bool isLikelyLinuxPartition(PartitionInfo partition) {
        // Skip if no filesystem type
        if (partition.fstype.length == 0) {
            return false;
        }

        // Check filesystem type
        string[] linuxFilesystems = ["ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "reiserfs"];
        if (!linuxFilesystems.canFind(partition.fstype)) {
            return false;
        }

        // Skip small partitions (likely boot partitions)
        if (partition.size.length > 0) {
            if (partition.size.canFind("M") && !partition.size.canFind("G")) {
                // Smaller than 1GB, probably not root
                return false;
            }
        }

        // Skip if mounted as non-root
        if (partition.isMounted && partition.mountpoint != "/" &&
            !partition.mountpoint.startsWith("/mnt/") &&
            !partition.mountpoint.startsWith("/media/")) {
            return false;
        }

        // Check label hints
        if (partition.label.length > 0) {
            string[] rootLabels = ["root", "linux", "system", "arch", "ubuntu", "debian", "fedora", "opensuse"];
            string[] bootLabels = ["boot", "efi", "esp"];

            string lowerLabel = partition.label.toLower();
            foreach (rootLabel; rootLabels) {
                if (lowerLabel.canFind(rootLabel)) {
                    return true;
                }
            }

            foreach (bootLabel; bootLabels) {
                if (lowerLabel.canFind(bootLabel)) {
                    return false; // Definitely not root
                }
            }
        }

        return true; // Default to likely if we got this far
    }

    /**
     * Scan common device patterns as fallback
     */
    private static PartitionInfo[] scanCommonDevices() {
        PartitionInfo[] partitions;

        string[] commonDevices = [
            "/dev/sda1", "/dev/sda2", "/dev/sda3", "/dev/sda4", "/dev/sda5",
            "/dev/sdb1", "/dev/sdb2", "/dev/sdb3", "/dev/sdb4", "/dev/sdb5",
            "/dev/nvme0n1p1", "/dev/nvme0n1p2", "/dev/nvme0n1p3", "/dev/nvme0n1p4", "/dev/nvme0n1p5", "/dev/nvme0n1p6",
            "/dev/nvme1n1p1", "/dev/nvme1n1p2", "/dev/nvme1n1p3",
            "/dev/vda1", "/dev/vda2", "/dev/vda3",
            "/dev/mmcblk0p1", "/dev/mmcblk0p2", "/dev/mmcblk0p3"
        ];

        foreach (device; commonDevices) {
            if (exists(device)) {
                PartitionInfo partition;
                partition.device = device;

                // Try to get basic info
                try {
                    auto fstypeResult = execute(["blkid", "-s", "TYPE", "-o", "value", device]);
                    if (fstypeResult.status == 0) {
                        partition.fstype = fstypeResult.output.strip();
                        partition.isLinuxRoot = isLinuxFilesystemType(partition.fstype);

                        if (partition.isLinuxRoot) {
                            // Get additional info
                            auto uuidResult = execute(["blkid", "-s", "UUID", "-o", "value", device]);
                            if (uuidResult.status == 0) {
                                partition.uuid = uuidResult.output.strip();
                            }

                            auto labelResult = execute(["blkid", "-s", "LABEL", "-o", "value", device]);
                            if (labelResult.status == 0) {
                                partition.label = labelResult.output.strip();
                            }

                            partitions ~= partition;
                        }
                    }
                } catch (Exception e) {
                    Logger.debugLog("Failed to get info for " ~ device ~ ": " ~ e.msg);
                }
            }
        }

        return partitions;
    }

    /**
     * Detect kernels in the mounted system
     */
    static KernelInfo[] detectKernels(ref SystemInfo sysInfo) {
        Logger.info("Detecting kernels");
        KernelInfo[] kernels;

        if (!sysInfo.isMounted) {
            Logger.error("System not mounted, cannot detect kernels");
            return kernels;
        }

        string bootPath = sysInfo.bootDir;
        if (!exists(bootPath)) {
            Logger.error("Boot directory not found: " ~ bootPath);
            return kernels;
        }

        try {
            // Look for kernel files
            auto kernelFiles = dirEntries(bootPath, SpanMode.shallow)
                .filter!(f => f.name.baseName.startsWith("vmlinuz"))
                .array;

            foreach (kernelFile; kernelFiles) {
                KernelInfo kernel;
                kernel.path = kernelFile.name.baseName;
                kernel.exists = exists(kernelFile.name);

                if (kernel.exists) {
                    kernel.size = getSize(kernelFile.name);
                }

                // Extract kernel version
                kernel.kernelVersion = extractKernelVersion(kernel.path);

                // Find corresponding initramfs
                kernel.initrd = findInitramfs(bootPath, kernel.kernelVersion);
                if (kernel.initrd.length > 0) {
                    string initrdPath = buildPath(bootPath, kernel.initrd);
                    kernel.initrdExists = exists(initrdPath);
                }

                kernels ~= kernel;
                Logger.debugLog(format("Found kernel: %s (version: %s, initrd: %s)",
                                   kernel.path, kernel.kernelVersion, kernel.initrd));
            }

            // Sort kernels by version (newest first)
            kernels.sort!((a, b) => a.kernelVersion > b.kernelVersion);

        } catch (Exception e) {
            Logger.error("Exception detecting kernels: " ~ e.msg);
        }

        Logger.info(format("Detected %d kernels", kernels.length));
        return kernels;
    }

    /**
     * Extract kernel version from filename
     */
    private static string extractKernelVersion(string kernelPath) {
        // Common patterns: vmlinuz-5.15.0-arch1-1, vmlinuz-linux, vmlinuz-linux-lts
        auto match = matchFirst(kernelPath, regex(`vmlinuz-(.+)`));
        if (match) {
            return match[1];
        }

        // Fallback: use filename without vmlinuz prefix
        if (kernelPath.startsWith("vmlinuz-")) {
            return kernelPath[8..$];
        }

        return "unknown";
    }

    /**
     * Find corresponding initramfs for a kernel version
     */
    private static string findInitramfs(string bootPath, string kernelVersion) {
        // Common initramfs naming patterns
        string[] patterns = [
            "initramfs-" ~ kernelVersion ~ ".img",
            "initramfs-" ~ kernelVersion,
            "initrd.img-" ~ kernelVersion,
            "initrd-" ~ kernelVersion,
            "initramfs-linux.img",
            "initrd.img"
        ];

        foreach (pattern; patterns) {
            string initrdPath = buildPath(bootPath, pattern);
            if (exists(initrdPath)) {
                return pattern;
            }
        }

        return "";
    }

    /**
     * Detect bootloader type
     */
    static BootLoader detectBootLoader(ref SystemInfo sysInfo) {
        Logger.info("Detecting bootloader");

        if (!sysInfo.isMounted) {
            Logger.error("System not mounted, cannot detect bootloader");
            return BootLoader.UNKNOWN;
        }

        // Check for GRUB
        if (detectGrub(sysInfo)) {
            sysInfo.bootLoader = BootLoader.GRUB;
            Logger.logDetection("bootloader", "GRUB");
            return BootLoader.GRUB;
        }

        // Check for rEFInd
        if (detectRefind(sysInfo)) {
            sysInfo.bootLoader = BootLoader.REFIND;
            Logger.logDetection("bootloader", "rEFInd");
            return BootLoader.REFIND;
        }

        // Check for systemd-boot
        if (detectSystemdBoot(sysInfo)) {
            sysInfo.bootLoader = BootLoader.SYSTEMD_BOOT;
            Logger.logDetection("bootloader", "systemd-boot");
            return BootLoader.SYSTEMD_BOOT;
        }

        Logger.warning("No recognized bootloader detected");
        sysInfo.bootLoader = BootLoader.UNKNOWN;
        return BootLoader.UNKNOWN;
    }

    /**
     * Detect GRUB bootloader
     */
    private static bool detectGrub(ref SystemInfo sysInfo) {
        string[] grubPaths = [
            buildPath(sysInfo.mountPoint, "boot/grub/grub.cfg"),
            buildPath(sysInfo.mountPoint, "boot/grub2/grub.cfg"),
            buildPath(sysInfo.mountPoint, "usr/bin/grub-mkconfig"),
            buildPath(sysInfo.mountPoint, "usr/bin/grub2-mkconfig")
        ];

        foreach (path; grubPaths) {
            if (exists(path)) {
                Logger.debugLog("Found GRUB indicator: " ~ path);
                return true;
            }
        }

        return false;
    }

    /**
     * Detect rEFInd bootloader
     */
    private static bool detectRefind(ref SystemInfo sysInfo) {
        string[] refindPaths = [
            buildPath(sysInfo.efiDir, "EFI/refind/refind.conf"),
            buildPath(sysInfo.efiDir, "EFI/BOOT/refind.conf"),
            buildPath(sysInfo.mountPoint, "usr/bin/refind-install")
        ];

        foreach (path; refindPaths) {
            if (exists(path)) {
                Logger.debugLog("Found rEFInd indicator: " ~ path);
                return true;
            }
        }

        return false;
    }

    /**
     * Detect systemd-boot
     */
    private static bool detectSystemdBoot(ref SystemInfo sysInfo) {
        string[] systemdBootPaths = [
            buildPath(sysInfo.efiDir, "EFI/systemd/systemd-bootx64.efi"),
            buildPath(sysInfo.efiDir, "EFI/BOOT/BOOTX64.EFI"),
            buildPath(sysInfo.efiDir, "loader/loader.conf"),
            buildPath(sysInfo.mountPoint, "usr/bin/bootctl")
        ];

        foreach (path; systemdBootPaths) {
            if (exists(path)) {
                Logger.debugLog("Found systemd-boot indicator: " ~ path);
                return true;
            }
        }

        return false;
    }

    /**
     * Detect Linux distribution
     */
    static string detectDistribution(ref SystemInfo sysInfo) {
        if (!sysInfo.isMounted) {
            return "Unknown";
        }

        string[] releaseFiles = [
            "etc/os-release",
            "etc/lsb-release",
            "etc/arch-release",
            "etc/debian_version",
            "etc/redhat-release",
            "etc/SuSE-release"
        ];

        foreach (file; releaseFiles) {
            string fullPath = buildPath(sysInfo.mountPoint, file);
            if (exists(fullPath)) {
                try {
                    string content = readText(fullPath);
                    return parseDistributionInfo(content, file);
                } catch (Exception e) {
                    Logger.debugLog("Failed to read " ~ file ~ ": " ~ e.msg);
                }
            }
        }

        return "Unknown Linux";
    }

    /**
     * Parse distribution information from release files
     */
    private static string parseDistributionInfo(string content, string filename) {
        if (filename.endsWith("os-release")) {
            // Parse os-release format
            auto lines = content.split("\n");
            foreach (line; lines) {
                if (line.startsWith("PRETTY_NAME=")) {
                    auto match = matchFirst(line, regex(`PRETTY_NAME="?([^"]+)"?`));
                    if (match) {
                        return match[1];
                    }
                } else if (line.startsWith("NAME=")) {
                    auto match = matchFirst(line, regex(`NAME="?([^"]+)"?`));
                    if (match) {
                        return match[1];
                    }
                }
            }
        } else if (filename.endsWith("arch-release")) {
            return "Arch Linux";
        } else if (filename.endsWith("debian_version")) {
            return "Debian " ~ content.strip();
        } else if (filename.endsWith("redhat-release")) {
            return content.strip();
        } else if (filename.endsWith("SuSE-release")) {
            auto lines = content.split("\n");
            if (lines.length > 0) {
                return lines[0].strip();
            }
        }

        return "Unknown Linux";
    }

    /**
     * Detect system architecture
     */
    static string detectArchitecture(ref SystemInfo sysInfo) {
        if (!sysInfo.isMounted) {
            return "Unknown";
        }

        try {
            // Try to determine from kernel files
            foreach (kernel; sysInfo.kernels) {
                if (kernel.kernelVersion.canFind("x86_64")) {
                    return "x86_64";
                } else if (kernel.kernelVersion.canFind("i686") || kernel.kernelVersion.canFind("i386")) {
                    return "i386";
                } else if (kernel.kernelVersion.canFind("aarch64")) {
                    return "aarch64";
                } else if (kernel.kernelVersion.canFind("arm")) {
                    return "arm";
                }
            }

            // Try to check system binaries
            string[] archIndicators = [
                "lib64",        // Usually indicates x86_64
                "lib/x86_64-linux-gnu",
                "lib/i386-linux-gnu"
            ];

            foreach (indicator; archIndicators) {
                string fullPath = buildPath(sysInfo.mountPoint, indicator);
                if (exists(fullPath)) {
                    if (indicator.canFind("x86_64")) {
                        return "x86_64";
                    } else if (indicator.canFind("i386")) {
                        return "i386";
                    }
                }
            }

        } catch (Exception e) {
            Logger.debugLog("Failed to detect architecture: " ~ e.msg);
        }

        return "Unknown";
    }

    /**
     * Get comprehensive system information
     */
    static string[] getSystemSummary(ref SystemInfo sysInfo) {
        string[] summary;

        summary ~= "=== System Detection Summary ===";
        summary ~= format("Device: %s", sysInfo.device);
        summary ~= format("Filesystem: %s", sysInfo.fstype);
        summary ~= format("Distribution: %s", detectDistribution(sysInfo));
        summary ~= format("Architecture: %s", detectArchitecture(sysInfo));
        summary ~= format("Bootloader: %s", bootLoaderToString(sysInfo.bootLoader));
        summary ~= format("Kernels found: %d", sysInfo.kernels.length);

        if (sysInfo.isBtrfs) {
            summary ~= format("Btrfs subvolumes: %d", sysInfo.btrfsInfo.subvolumes.length);
            summary ~= format("Root subvolume: %s", sysInfo.btrfsInfo.rootSubvolume);
        }

        return summary;
    }

    /**
     * Validate that detected system information makes sense
     */
    static bool validateSystemDetection(ref SystemInfo sysInfo) {
        bool valid = true;

        // Check basic requirements
        if (sysInfo.device.length == 0) {
            Logger.error("No device specified");
            valid = false;
        }

        if (sysInfo.fstype.length == 0) {
            Logger.error("Filesystem type not detected");
            valid = false;
        }

        if (sysInfo.kernels.length == 0) {
            Logger.warning("No kernels detected - this may cause boot issues");
        }

        if (sysInfo.bootLoader == BootLoader.UNKNOWN) {
            Logger.warning("Bootloader not detected - manual configuration may be needed");
        }

        return valid;
    }

    // Helper function for bootloader enum to string
    private static string bootLoaderToString(BootLoader bootloader) {
        final switch (bootloader) {
            case BootLoader.UNKNOWN:     return "Unknown";
            case BootLoader.GRUB:        return "GRUB";
            case BootLoader.REFIND:      return "rEFInd";
            case BootLoader.SYSTEMD_BOOT: return "systemd-boot";
        }
    }
}
