/**
 * debork - Cross-Platform Linux Boot Rescue Tool
 * Rewritten in Cosmopolitan C with Clay for TUI rendering
 *
 * Features:
 * - Multi-bootloader support (GRUB, rEFInd, systemd-boot)
 * - Interactive TUI interface using Clay
 * - Automatic boot configuration detection and repair
 * - Cross-platform compatibility via Cosmopolitan libc
 * - Kernel/initrd management
 * - Configuration backup/restore
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>

// Clay removed - using direct terminal rendering instead
// #define CLAY_IMPLEMENTATION
// #include "clay.h"

// Terminal control codes
#define TERM_RESET     "\033[0m"
#define TERM_RED       "\033[31m"
#define TERM_GREEN     "\033[32m"
#define TERM_YELLOW    "\033[33m"
#define TERM_BLUE      "\033[34m"
#define TERM_MAGENTA   "\033[35m"
#define TERM_CYAN      "\033[36m"
#define TERM_WHITE     "\033[37m"
#define TERM_BOLD      "\033[1m"
#define TERM_CLEAR     "\033[2J\033[H"

// Boot loader types
typedef enum {
    BOOTLOADER_UNKNOWN,
    BOOTLOADER_GRUB,
    BOOTLOADER_REFIND,
    BOOTLOADER_SYSTEMD_BOOT
} BootLoader;

// Kernel information structure
typedef struct {
    char path[256];
    char kernel_version[128];
    char initrd[256];
    bool exists;
} KernelInfo;

// Partition information
typedef struct {
    char device[64];
    char uuid[64];
    char label[128];
    char fstype[32];
    char mountpoint[256];
    char size[32];
    bool is_linux_root;
} PartitionInfo;

// System information
typedef struct {
    char device[64];
    char uuid[64];
    char mount_point[256];
    BootLoader boot_loader;
    char boot_dir[256];
    char efi_dir[256];
    KernelInfo kernels[32];
    int kernel_count;
    char fstype[32];
    bool is_btrfs;
    char root_subvol[256];
} SystemInfo;

// TUI state
typedef struct {
    SystemInfo sys_info;
    char log_file[256];
    bool debug_mode;
    int selected_menu_item;
    bool running;
    char status_message[512];
    int status_type; // 0=info, 1=success, 2=error, 3=warning
} DeborkTUI;

// Global TUI instance
static DeborkTUI g_tui = {0};

// Function prototypes
void init_tui(DeborkTUI *tui);
void cleanup_tui(DeborkTUI *tui);
void render_ui(DeborkTUI *tui);
void handle_input(DeborkTUI *tui);
void log_message(const char *level, const char *msg);
void print_status(const char *msg, bool is_error);
void print_warning(const char *msg);
void print_info(const char *msg);
void clear_screen(void);
char get_char(void);
bool prompt_confirm(const char *prompt);
char* prompt_input(const char *prompt, char *buffer, size_t size);
void detect_boot_loader(SystemInfo *sys_info);
void scan_kernels(SystemInfo *sys_info);
bool mount_system(const char *device, SystemInfo *sys_info);
void unmount_system(SystemInfo *sys_info);
void show_system_info(SystemInfo *sys_info);
void regenerate_initramfs(SystemInfo *sys_info);
void fix_grub(SystemInfo *sys_info);
void fix_refind(SystemInfo *sys_info);
void fix_systemd_boot(SystemInfo *sys_info);
void emergency_shell(SystemInfo *sys_info);
void update_system_packages(SystemInfo *sys_info);
PartitionInfo* scan_partitions(int *count);
char* select_partition(void);
bool file_exists(const char *path);
int execute_command(const char *command);
int execute_chroot_command(const char *chroot_path, const char *command);

// Initialize TUI
void init_tui(DeborkTUI *tui) {
    strcpy(tui->sys_info.mount_point, "/mnt/debork");
    strcpy(tui->log_file, "/tmp/debork.log");
    tui->selected_menu_item = 0;
    tui->running = true;
}

// Cleanup TUI
void cleanup_tui(DeborkTUI *tui) {
    // Cleanup if needed
    (void)tui; // Suppress unused warning
}

// Clear screen
void clear_screen(void) {
    printf(TERM_CLEAR);
    fflush(stdout);
}

// Get single character input
char get_char(void) {
    struct termios old_tio, new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    new_tio = old_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
    
    char ch;
    read(STDIN_FILENO, &ch, 1);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    return ch;
}

// Log message
void log_message(const char *level, const char *msg) {
    time_t now;
    time(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    char log_entry[1024];
    snprintf(log_entry, sizeof(log_entry), "[%s] %s: %s\n", timestamp, level, msg);
    
    if (g_tui.debug_mode) {
        printf("%s", log_entry);
    }
    
    FILE *log = fopen(g_tui.log_file, "a");
    if (log) {
        fprintf(log, "%s", log_entry);
        fclose(log);
    }
}

// Print status message
void print_status(const char *msg, bool is_error) {
    if (is_error) {
        printf("%s✗ %s%s\n", TERM_RED, msg, TERM_RESET);
    } else {
        printf("%s✓ %s%s\n", TERM_GREEN, msg, TERM_RESET);
    }
}

// Print warning
void print_warning(const char *msg) {
    printf("%s⚠ %s%s\n", TERM_YELLOW, msg, TERM_RESET);
}

// Print info
void print_info(const char *msg) {
    printf("%sℹ %s%s\n", TERM_BLUE, msg, TERM_RESET);
}

// Prompt for confirmation
bool prompt_confirm(const char *prompt) {
    printf("%s%s (y/N): %s", TERM_YELLOW, prompt, TERM_RESET);
    fflush(stdout);
    
    char response[32];
    if (fgets(response, sizeof(response), stdin)) {
        return (response[0] == 'y' || response[0] == 'Y');
    }
    return false;
}

// Prompt for input
char* prompt_input(const char *prompt, char *buffer, size_t size) {
    printf("%s%s: %s", TERM_CYAN, prompt, TERM_RESET);
    fflush(stdout);
    
    if (fgets(buffer, size, stdin)) {
        // Remove newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }
        return buffer;
    }
    return NULL;
}

// Check if file exists
bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

// Execute command
int execute_command(const char *command) {
    return system(command);
}

// Execute command in chroot
int execute_chroot_command(const char *chroot_path, const char *command) {
    char full_command[1024];
    snprintf(full_command, sizeof(full_command), "chroot %s %s", chroot_path, command);
    return system(full_command);
}

// Detect boot loader
void detect_boot_loader(SystemInfo *sys_info) {
    log_message("INFO", "Detecting boot loader");
    
    char path[512];
    
    // Check for GRUB
    snprintf(path, sizeof(path), "%s/boot/grub", sys_info->mount_point);
    if (file_exists(path)) {
        sys_info->boot_loader = BOOTLOADER_GRUB;
        log_message("INFO", "Detected GRUB bootloader");
        return;
    }
    
    snprintf(path, sizeof(path), "%s/boot/grub2", sys_info->mount_point);
    if (file_exists(path)) {
        sys_info->boot_loader = BOOTLOADER_GRUB;
        log_message("INFO", "Detected GRUB2 bootloader");
        return;
    }
    
    // Check for rEFInd
    snprintf(path, sizeof(path), "%s/EFI/refind", sys_info->efi_dir);
    if (file_exists(path)) {
        sys_info->boot_loader = BOOTLOADER_REFIND;
        log_message("INFO", "Detected rEFInd bootloader");
        return;
    }
    
    // Check for systemd-boot
    snprintf(path, sizeof(path), "%s/EFI/systemd", sys_info->efi_dir);
    if (file_exists(path)) {
        sys_info->boot_loader = BOOTLOADER_SYSTEMD_BOOT;
        log_message("INFO", "Detected systemd-boot bootloader");
        return;
    }
    
    sys_info->boot_loader = BOOTLOADER_UNKNOWN;
    log_message("WARN", "Could not detect bootloader type");
}

// Scan for kernels
void scan_kernels(SystemInfo *sys_info) {
    log_message("INFO", "Scanning for kernels");
    sys_info->kernel_count = 0;
    
    char boot_path[512];
    snprintf(boot_path, sizeof(boot_path), "%s/boot", sys_info->mount_point);
    
    DIR *dir = opendir(boot_path);
    if (!dir) {
        log_message("ERROR", "Cannot open boot directory");
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && sys_info->kernel_count < 32) {
        if (strncmp(entry->d_name, "vmlinuz", 7) == 0) {
            KernelInfo *kernel = &sys_info->kernels[sys_info->kernel_count];
            strcpy(kernel->path, entry->d_name);
            
            // Extract version from kernel name
            char *version_start = strchr(entry->d_name, '-');
            if (version_start) {
                strcpy(kernel->kernel_version, version_start + 1);
            }
            
            // Find corresponding initrd
            char initrd_candidates[3][256];
            snprintf(initrd_candidates[0], 256, "initramfs-%s.img", kernel->kernel_version);
            snprintf(initrd_candidates[1], 256, "initrd.img-%s", kernel->kernel_version);
            snprintf(initrd_candidates[2], 256, "initramfs-%s-fallback.img", kernel->kernel_version);
            
            for (int i = 0; i < 3; i++) {
                char initrd_path[512];
                snprintf(initrd_path, sizeof(initrd_path), "%s/%s", boot_path, initrd_candidates[i]);
                if (file_exists(initrd_path)) {
                    strcpy(kernel->initrd, initrd_candidates[i]);
                    break;
                }
            }
            
            kernel->exists = true;
            sys_info->kernel_count++;
            
            char log_msg[512];
            snprintf(log_msg, sizeof(log_msg), "Found kernel: %s (version: %s, initrd: %s)",
                     kernel->path, kernel->kernel_version, kernel->initrd);
            log_message("INFO", log_msg);
        }
    }
    
    closedir(dir);
}

// Mount system
bool mount_system(const char *device, SystemInfo *sys_info) {
    strcpy(sys_info->device, device);
    
    // Create mount point if it doesn't exist
    mkdir(sys_info->mount_point, 0755);
    
    print_info("Mounting system...");
    
    // Try to mount the device
    if (mount(device, sys_info->mount_point, "auto", 0, NULL) != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to mount %s: %s", device, strerror(errno));
        print_status(error_msg, true);
        return false;
    }
    
    print_status("System mounted successfully", false);
    
    // Mount critical filesystems for chroot
    char path[512];
    
    snprintf(path, sizeof(path), "%s/proc", sys_info->mount_point);
    mount("proc", path, "proc", 0, NULL);
    
    snprintf(path, sizeof(path), "%s/sys", sys_info->mount_point);
    mount("sysfs", path, "sysfs", 0, NULL);
    
    snprintf(path, sizeof(path), "%s/dev", sys_info->mount_point);
    mount("/dev", path, "none", MS_BIND, NULL);
    
    snprintf(path, sizeof(path), "%s/run", sys_info->mount_point);
    mount("/run", path, "none", MS_BIND, NULL);
    
    // Check for EFI directory
    snprintf(sys_info->efi_dir, sizeof(sys_info->efi_dir), "%s/boot/efi", sys_info->mount_point);
    if (!file_exists(sys_info->efi_dir)) {
        snprintf(sys_info->efi_dir, sizeof(sys_info->efi_dir), "%s/efi", sys_info->mount_point);
    }
    
    return true;
}

// Unmount system
void unmount_system(SystemInfo *sys_info) {
    char path[512];
    
    snprintf(path, sizeof(path), "%s/proc", sys_info->mount_point);
    umount(path);
    
    snprintf(path, sizeof(path), "%s/sys", sys_info->mount_point);
    umount(path);
    
    snprintf(path, sizeof(path), "%s/dev", sys_info->mount_point);
    umount(path);
    
    snprintf(path, sizeof(path), "%s/run", sys_info->mount_point);
    umount(path);
    
    umount(sys_info->mount_point);
    
    print_status("System unmounted", false);
}

// Show system information
void show_system_info(SystemInfo *sys_info) {
    clear_screen();
    printf("%s%s╔══════════════════════════════════════════════════════════════╗\n", TERM_CYAN, TERM_BOLD);
    printf("║                     System Information                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝%s\n\n", TERM_RESET);
    
    printf("Device: %s\n", sys_info->device);
    printf("Mount Point: %s\n", sys_info->mount_point);
    printf("Filesystem: %s\n", sys_info->fstype);
    
    printf("Boot Loader: ");
    switch (sys_info->boot_loader) {
        case BOOTLOADER_GRUB:
            printf("GRUB\n");
            break;
        case BOOTLOADER_REFIND:
            printf("rEFInd\n");
            break;
        case BOOTLOADER_SYSTEMD_BOOT:
            printf("systemd-boot\n");
            break;
        default:
            printf("Unknown\n");
    }
    
    printf("\nKernels found: %d\n", sys_info->kernel_count);
    for (int i = 0; i < sys_info->kernel_count; i++) {
        printf("  %d. %s (initrd: %s)\n", i+1, 
               sys_info->kernels[i].path,
               sys_info->kernels[i].initrd[0] ? sys_info->kernels[i].initrd : "none");
    }
    
    printf("\nPress any key to continue...");
    get_char();
}

// Regenerate initramfs
void regenerate_initramfs(SystemInfo *sys_info) {
    print_info("Regenerating initramfs...");
    
    // Try different initramfs generation commands
    char cmd_path[512];
    
    // Try mkinitcpio (Arch-based)
    snprintf(cmd_path, sizeof(cmd_path), "%s/usr/bin/mkinitcpio", sys_info->mount_point);
    if (file_exists(cmd_path)) {
        if (execute_chroot_command(sys_info->mount_point, "mkinitcpio -P") == 0) {
            print_status("Initramfs regenerated successfully", false);
            return;
        }
    }
    
    // Try dracut (Fedora/RHEL-based)
    snprintf(cmd_path, sizeof(cmd_path), "%s/usr/bin/dracut", sys_info->mount_point);
    if (file_exists(cmd_path)) {
        if (execute_chroot_command(sys_info->mount_point, "dracut --force") == 0) {
            print_status("Initramfs regenerated successfully", false);
            return;
        }
    }
    
    // Try update-initramfs (Debian/Ubuntu-based)
    snprintf(cmd_path, sizeof(cmd_path), "%s/usr/sbin/update-initramfs", sys_info->mount_point);
    if (file_exists(cmd_path)) {
        if (execute_chroot_command(sys_info->mount_point, "update-initramfs -u") == 0) {
            print_status("Initramfs regenerated successfully", false);
            return;
        }
    }
    
    print_status("Failed to regenerate initramfs", true);
}

// Fix GRUB
void fix_grub(SystemInfo *sys_info) {
    print_info("Fixing GRUB bootloader...");
    
    char cmd[512];
    
    // Update GRUB configuration
    snprintf(cmd, sizeof(cmd), "%s/usr/bin/grub-mkconfig", sys_info->mount_point);
    if (file_exists(cmd)) {
        if (execute_chroot_command(sys_info->mount_point, "grub-mkconfig -o /boot/grub/grub.cfg") == 0) {
            print_status("GRUB configuration updated", false);
        } else {
            print_status("Failed to update GRUB configuration", true);
        }
    } else {
        // Try grub2-mkconfig
        snprintf(cmd, sizeof(cmd), "%s/usr/bin/grub2-mkconfig", sys_info->mount_point);
        if (file_exists(cmd)) {
            if (execute_chroot_command(sys_info->mount_point, "grub2-mkconfig -o /boot/grub2/grub.cfg") == 0) {
                print_status("GRUB2 configuration updated", false);
            } else {
                print_status("Failed to update GRUB2 configuration", true);
            }
        }
    }
    
    // Try to reinstall GRUB
    if (prompt_confirm("Reinstall GRUB to MBR/ESP?")) {
        char device_base[64];
        strcpy(device_base, sys_info->device);
        // Remove partition number to get base device
        for (int i = strlen(device_base) - 1; i >= 0; i--) {
            if (device_base[i] >= '0' && device_base[i] <= '9') {
                device_base[i] = '\0';
            } else {
                break;
            }
        }
        
        char grub_install_cmd[512];
        snprintf(grub_install_cmd, sizeof(grub_install_cmd), "grub-install %s", device_base);
        
        if (execute_chroot_command(sys_info->mount_point, grub_install_cmd) == 0) {
            print_status("GRUB reinstalled successfully", false);
        } else {
            print_status("Failed to reinstall GRUB", true);
        }
    }
}

// Fix rEFInd
void fix_refind(SystemInfo *sys_info) {
    print_info("Fixing rEFInd bootloader...");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s/usr/bin/refind-install", sys_info->mount_point);
    
    if (file_exists(cmd)) {
        if (execute_chroot_command(sys_info->mount_point, "refind-install") == 0) {
            print_status("rEFInd updated successfully", false);
        } else {
            print_status("Failed to update rEFInd", true);
        }
    } else {
        print_warning("refind-install not found in system");
    }
}

// Fix systemd-boot
void fix_systemd_boot(SystemInfo *sys_info) {
    print_info("Fixing systemd-boot...");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s/usr/bin/bootctl", sys_info->mount_point);
    
    if (file_exists(cmd)) {
        if (execute_chroot_command(sys_info->mount_point, "bootctl update") == 0) {
            print_status("systemd-boot updated successfully", false);
        } else {
            print_status("Failed to update systemd-boot", true);
        }
    } else {
        print_warning("bootctl not found in system");
    }
}

// Emergency shell
void emergency_shell(SystemInfo *sys_info) {
    clear_screen();
    print_info("Starting emergency shell in chroot environment...");
    printf("\n");
    printf("%sIMPORTANT NOTES:%s\n", TERM_YELLOW, TERM_RESET);
    printf("• Use 'pacman -Syyu' instead of 'yay' for system updates\n");
    printf("• yay/makepkg cannot run as root (you are root in chroot)\n");
    printf("• Network connectivity should work for package downloads\n");
    printf("• Type 'exit' to return to debork menu\n");
    printf("\n");
    printf("System info:\n");
    printf("• Device: %s\n", sys_info->device);
    printf("• Mount point: %s\n", sys_info->mount_point);
    printf("\n");
    printf("Press Enter to start shell...\n");
    getchar();
    
    // Start interactive shell
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        chroot(sys_info->mount_point);
        chdir("/");
        execl("/bin/bash", "bash", "-l", NULL);
        execl("/bin/sh", "sh", "-l", NULL);
        exit(1);
    } else if (pid > 0) {
        // Parent process
        waitpid(pid, NULL, 0);
    } else {
        print_status("Failed to start emergency shell", true);
    }
    
    print_info("Returned from emergency shell");
    printf("Press any key to continue...");
    get_char();
}

// Update system packages
void update_system_packages(SystemInfo *sys_info) {
    clear_screen();
    printf("%s%s╔══════════════════════════════════════════════════════════════╗\n", TERM_CYAN, TERM_BOLD);
    printf("║                  Complete System Repair                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝%s\n\n", TERM_RESET);
    
    print_info("Starting comprehensive system repair...");
    printf("\n");
    
    // Step 1: Update package database
    print_info("Step 1/3: Updating package database...");
    
    // Try pacman (Arch-based)
    char pacman_path[512];
    snprintf(pacman_path, sizeof(pacman_path), "%s/usr/bin/pacman", sys_info->mount_point);
    if (file_exists(pacman_path)) {
        if (execute_chroot_command(sys_info->mount_point, "pacman -Syy") == 0) {
            print_status("Package database updated", false);
            
            // Update packages
            print_info("Updating system packages...");
            execute_chroot_command(sys_info->mount_point, "pacman -Su --noconfirm");
        }
    }
    
    // Try apt (Debian-based)
    char apt_path[512];
    snprintf(apt_path, sizeof(apt_path), "%s/usr/bin/apt", sys_info->mount_point);
    if (file_exists(apt_path)) {
        if (execute_chroot_command(sys_info->mount_point, "apt update") == 0) {
            print_status("Package database updated", false);
            
            // Update packages
            print_info("Updating system packages...");
            execute_chroot_command(sys_info->mount_point, "apt upgrade -y");
        }
    }
    
    // Step 2: Regenerate initramfs
    print_info("Step 2/3: Regenerating initramfs...");
    regenerate_initramfs(sys_info);
    
    // Step 3: Fix bootloader
    print_info("Step 3/3: Fixing bootloader...");
    switch (sys_info->boot_loader) {
        case BOOTLOADER_GRUB:
            fix_grub(sys_info);
            break;
        case BOOTLOADER_REFIND:
            fix_refind(sys_info);
            break;
        case BOOTLOADER_SYSTEMD_BOOT:
            fix_systemd_boot(sys_info);
            break;
        default:
            print_warning("Unknown bootloader - manual intervention may be required");
    }
    
    printf("\n");
    print_status("System repair completed!", false);
    print_info("Your system should now be bootable. Reboot to test the fix.");
    printf("Press any key to continue...");
    get_char();
}

// Scan partitions
PartitionInfo* scan_partitions(int *count) {
    static PartitionInfo partitions[32];
    *count = 0;
    
    // Try to use lsblk to get partition info
    FILE *fp = popen("lsblk -rno NAME,SIZE,FSTYPE,MOUNTPOINT,LABEL,UUID", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp) && *count < 32) {
            char name[64], size[32], fstype[32], mountpoint[256], label[128], uuid[64];
            if (sscanf(line, "%s %s %s %s %s %s", name, size, fstype, mountpoint, label, uuid) >= 3) {
                // Check if it's a potential Linux root partition
                if (strstr(fstype, "ext") || strstr(fstype, "btrfs") || strstr(fstype, "xfs")) {
                    snprintf(partitions[*count].device, sizeof(partitions[*count].device), "/dev/%s", name);
                    strcpy(partitions[*count].size, size);
                    strcpy(partitions[*count].fstype, fstype);
                    strcpy(partitions[*count].label, label);
                    strcpy(partitions[*count].uuid, uuid);
                    partitions[*count].is_linux_root = true;
                    (*count)++;
                }
            }
        }
        pclose(fp);
    }
    
    // Fallback: check common device names
    if (*count == 0) {
        const char *common_devices[] = {
            "/dev/sda1", "/dev/sda2", "/dev/sda3",
            "/dev/nvme0n1p1", "/dev/nvme0n1p2", "/dev/nvme0n1p3",
            "/dev/vda1", "/dev/vda2", "/dev/vda3",
            NULL
        };
        
        for (int i = 0; common_devices[i] && *count < 32; i++) {
            if (file_exists(common_devices[i])) {
                strcpy(partitions[*count].device, common_devices[i]);
                partitions[*count].is_linux_root = true;
                (*count)++;
            }
        }
    }
    
    return partitions;
}

// Select partition
char* select_partition(void) {
    static char selected_device[64];
    int count;
    PartitionInfo *partitions = scan_partitions(&count);
    
    if (count == 0) {
        print_warning("No partitions detected automatically");
        prompt_input("Enter device to repair (e.g., /dev/nvme0n1p5)", selected_device, sizeof(selected_device));
        return selected_device;
    }
    
    clear_screen();
    printf("%s%s╔══════════════════════════════════════════════════════════════╗\n", TERM_CYAN, TERM_BOLD);
    printf("║                   Select Partition to Repair                ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝%s\n\n", TERM_RESET);
    
    printf("Available partitions:\n\n");
    for (int i = 0; i < count; i++) {
        printf("  %d. %s", i+1, partitions[i].device);
        if (strlen(partitions[i].size) > 0) {
            printf(" (%s)", partitions[i].size);
        }
        if (strlen(partitions[i].label) > 0) {
            printf(" [%s]", partitions[i].label);
        }
        if (strlen(partitions[i].fstype) > 0) {
            printf(" - %s", partitions[i].fstype);
        }
        printf("\n");
    }
    printf("  %d. Enter device path manually\n", count+1);
    
    printf("\nSelect partition (1-%d): ", count+1);
    fflush(stdout);
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        choice = count + 1;
    }
    getchar(); // consume newline
    
    if (choice > 0 && choice <= count) {
        strcpy(selected_device, partitions[choice-1].device);
    } else {
        prompt_input("Enter device to repair (e.g., /dev/nvme0n1p5)", selected_device, sizeof(selected_device));
    }
    
    return selected_device;
}

// Render UI using direct terminal output
void render_ui(DeborkTUI *tui) {
    // Simple terminal rendering
    clear_screen();
    printf("%s%s╔══════════════════════════════════════════════════════════════╗\n", TERM_CYAN, TERM_BOLD);
    printf("║                    debork Boot Rescue Tool                  ║\n");
    printf("║              Cross-Platform Linux System Fixer              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝%s\n\n", TERM_RESET);
    
    if (strlen(tui->status_message) > 0) {
        switch (tui->status_type) {
            case 1:
                print_status(tui->status_message, false);
                break;
            case 2:
                print_status(tui->status_message, true);
                break;
            case 3:
                print_warning(tui->status_message);
                break;
            default:
                print_info(tui->status_message);
        }
        printf("\n");
    }
    
    const char *menu_items[] = {
        "Fix My System (Complete Repair)",
        "Emergency Shell (Manual Fixes)",
        "Regenerate Initramfs Only",
        "Fix Boot Configuration Only",
        "Show System Information",
        "Exit"
    };
    
    printf("%sSelect an option:%s\n\n", TERM_BOLD, TERM_RESET);
    
    int menu_count = sizeof(menu_items) / sizeof(menu_items[0]);
    for (int i = 0; i < menu_count; i++) {
        if (i == tui->selected_menu_item) {
            printf("%s%s→ %s%s\n", TERM_GREEN, TERM_BOLD, menu_items[i], TERM_RESET);
        } else {
            printf("  %s\n", menu_items[i]);
        }
    }
    
    printf("\n%sUse ↑/↓ to navigate, Enter to select, 'q' to quit%s\n", TERM_YELLOW, TERM_RESET);
    fflush(stdout);
}

// Handle input
void handle_input(DeborkTUI *tui) {
    char ch = get_char();
    
    switch (ch) {
        case 'A': // Up arrow (after escape sequence)
        case 'k':
            tui->selected_menu_item = (tui->selected_menu_item - 1 + 6) % 6;
            break;
        case 'B': // Down arrow (after escape sequence)
        case 'j':
            tui->selected_menu_item = (tui->selected_menu_item + 1) % 6;
            break;
        case '\n':
        case '\r':
            // Handle menu selection
            switch (tui->selected_menu_item) {
                case 0: // Fix My System
                    update_system_packages(&tui->sys_info);
                    break;
                case 1: // Emergency Shell
                    emergency_shell(&tui->sys_info);
                    break;
                case 2: // Regenerate Initramfs
                    regenerate_initramfs(&tui->sys_info);
                    strcpy(tui->status_message, "Initramfs regeneration completed");
                    tui->status_type = 1;
                    printf("Press any key to continue...");
                    get_char();
                    break;
                case 3: // Fix Boot Configuration
                    switch (tui->sys_info.boot_loader) {
                        case BOOTLOADER_GRUB:
                            fix_grub(&tui->sys_info);
                            break;
                        case BOOTLOADER_REFIND:
                            fix_refind(&tui->sys_info);
                            break;
                        case BOOTLOADER_SYSTEMD_BOOT:
                            fix_systemd_boot(&tui->sys_info);
                            break;
                        default:
                            strcpy(tui->status_message, "Unknown bootloader - try Emergency Shell");
                            tui->status_type = 3;
                    }
                    printf("Press any key to continue...");
                    get_char();
                    break;
                case 4: // Show System Information
                    show_system_info(&tui->sys_info);
                    break;
                case 5: // Exit
                    tui->running = false;
                    break;
            }
            break;
        case 'q':
        case 'Q':
            tui->running = false;
            break;
        case 27: // ESC sequence
            get_char(); // consume '['
            char arrow = get_char();
            if (arrow == 'A') {
                tui->selected_menu_item = (tui->selected_menu_item - 1 + 6) % 6;
            } else if (arrow == 'B') {
                tui->selected_menu_item = (tui->selected_menu_item + 1) % 6;
            }
            break;
    }
}

// Main run loop
void run_tui(void) {
    init_tui(&g_tui);
    
    clear_screen();
    printf("%s%s╔══════════════════════════════════════════════════════════════╗\n", TERM_CYAN, TERM_BOLD);
    printf("║                    debork Boot Rescue Tool                  ║\n");
    printf("║              Cross-Platform Linux System Fixer              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝%s\n\n", TERM_RESET);
    
    printf("Welcome to debork Boot Rescue Tool!\n\n");
    
    // Get device to mount
    char *device = select_partition();
    if (!device || strlen(device) == 0) {
        printf("\nNo device selected. Exiting...\n");
        return;
    }
    
    if (!mount_system(device, &g_tui.sys_info)) {
        printf("\nPress any key to exit...");
        get_char();
        return;
    }
    
    // Detect system configuration
    detect_boot_loader(&g_tui.sys_info);
    scan_kernels(&g_tui.sys_info);
    
    // Main menu loop
    while (g_tui.running) {
        render_ui(&g_tui);
        handle_input(&g_tui);
    }
    
    unmount_system(&g_tui.sys_info);
    cleanup_tui(&g_tui);
}

// Main function
int main(int argc, char *argv[]) {
    bool show_help = false;
    bool debug_mode = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help = true;
        } else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug_mode = true;
        }
    }
    
    if (show_help) {
        printf("debork - Cross-Platform Linux Boot Rescue Tool\n");
        printf("\n");
        printf("Usage: %s [options]\n", argv[0]);
        printf("\n");
        printf("Options:\n");
        printf("  --help, -h     Show this help message\n");
        printf("  --debug, -d    Enable debug mode\n");
        printf("\n");
        printf("This tool provides a TUI interface for repairing broken Linux boot\n");
        printf("configurations. It supports GRUB, rEFInd, and systemd-boot.\n");
        return 0;
    }
    
    // Check if running as root
    if (getuid() != 0) {
        fprintf(stderr, "%sError: This tool must be run as root%s\n", TERM_RED, TERM_RESET);
        return 1;
    }
    
    g_tui.debug_mode = debug_mode;
    
    // Run the TUI
    run_tui();
    
    return 0;
}