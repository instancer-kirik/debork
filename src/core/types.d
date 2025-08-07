module debork.core.types;

// Terminal control codes for colored output
enum TermColor : string {
    RESET = "\033[0m",
    RED = "\033[31m",
    GREEN = "\033[32m",
    YELLOW = "\033[33m",
    BLUE = "\033[34m",
    MAGENTA = "\033[35m",
    CYAN = "\033[36m",
    WHITE = "\033[37m",
    BOLD = "\033[1m"
}

// Supported bootloader types
enum BootLoader {
    UNKNOWN,
    GRUB,
    REFIND,
    SYSTEMD_BOOT
}

// Supported package managers
enum PackageManager {
    UNKNOWN,
    PACMAN,     // Arch Linux
    APT,        // Debian/Ubuntu
    YUM,        // Red Hat/CentOS
    DNF,        // Fedora
    ZYPPER      // openSUSE
}

// Filesystem types we can handle
enum FilesystemType {
    UNKNOWN,
    EXT4,
    EXT3,
    EXT2,
    BTRFS,
    XFS,
    F2FS,
    REISERFS
}

// Log levels
enum LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
}

// Kernel information structure
struct KernelInfo {
    string path;            // Full path to kernel file
    string kernelVersion;   // Kernel version string
    string initrd;          // Initramfs/initrd path
    bool exists;            // Whether kernel file exists
    bool initrdExists;      // Whether initrd exists
    ulong size;             // Kernel file size
}

// Partition information
struct PartitionInfo {
    string device;          // Device path (e.g., /dev/sda1)
    string uuid;            // Filesystem UUID
    string label;           // Filesystem label
    string fstype;          // Filesystem type string
    string mountpoint;      // Current mount point (if any)
    string size;            // Human-readable size
    bool isLinuxRoot;       // Likely Linux root partition
    bool isMounted;         // Currently mounted
}

// Btrfs subvolume information
struct BtrfsSubvolume {
    int id;                 // Subvolume ID
    string path;            // Subvolume path
    string topLevel;        // Top level subvolume ID
    int generation;         // Generation number
    bool isRoot;            // Is this the root subvolume
}

// Btrfs-specific information
struct BtrfsInfo {
    BtrfsSubvolume[] subvolumes;
    string rootSubvolume;
    string[] mountedSubvolumes;
}

// System information structure
struct SystemInfo {
    // Device information
    string device;                      // Root device path
    string uuid;                        // Root filesystem UUID
    string mountPoint = "/mnt/debork";  // Where we mount the system

    // Filesystem information
    string fstype;                      // Filesystem type
    FilesystemType filesystemType;      // Parsed filesystem type
    bool isBtrfs;                       // Is this a btrfs filesystem
    BtrfsInfo btrfsInfo;                // Btrfs-specific info

    // Boot information
    BootLoader bootLoader = BootLoader.UNKNOWN;
    string bootDir;                     // Boot directory path
    string efiDir;                      // EFI directory path
    KernelInfo[] kernels;               // Available kernels

    // System capabilities
    PackageManager packageManager = PackageManager.UNKNOWN;
    string[] availableShells;           // Available shells in system
    bool hasNetworking;                 // Network configuration available

    // Status
    bool isMounted;                     // System currently mounted
    bool isValidated;                   // Passed validation checks
}

// Configuration for repair operations
struct RepairConfig {
    bool updatePackages = true;
    bool regenerateInitramfs = true;
    bool fixBootloader = true;
    bool skipConfirmation = false;
    bool verboseOutput = false;
}

// Result of repair operations
struct RepairResult {
    bool success;
    string[] errors;
    string[] warnings;
    string[] completedSteps;
    int exitCode;
}

// Menu option structure for TUI
struct MenuOption {
    string text;
    string description;
    bool enabled = true;
}

// Constants
struct Constants {
    static immutable string DEFAULT_MOUNT_POINT = "/mnt/debork";
    static immutable string LOG_FILE = "/tmp/debork.log";
    static immutable string TEMP_MOUNT = "/tmp/debork_temp";
    static immutable int MAX_KERNELS = 20;
    static immutable int TIMEOUT_SECONDS = 30;
}
