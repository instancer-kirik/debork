/**
 * debork - Cute Terminal Boot Rescue Tool
 * A lightweight, adorable alternative to Clay UI
 * With kawaii aesthetics and smooth animations! ✨
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <locale.h>
#include <wchar.h>

// ANSI escape codes for colors and cursor control
#define ESC "\033"
#define CSI "\033["
#define RESET CSI "0m"
#define BOLD CSI "1m"
#define DIM CSI "2m"
#define ITALIC CSI "3m"
#define UNDERLINE CSI "4m"
#define BLINK CSI "5m"
#define REVERSE CSI "7m"
#define HIDE_CURSOR CSI "?25l"
#define SHOW_CURSOR CSI "?25h"
#define CLEAR_SCREEN CSI "2J" CSI "H"
#define CLEAR_LINE CSI "2K"
#define SAVE_CURSOR CSI "s"
#define RESTORE_CURSOR CSI "u"
#define ALTERNATE_SCREEN CSI "?1049h"
#define NORMAL_SCREEN CSI "?1049l"

// RGB color macros for true color support
#define RGB_FG(r,g,b) CSI "38;2;" #r ";" #g ";" #b "m"
#define RGB_BG(r,g,b) CSI "48;2;" #r ";" #g ";" #b "m"
#define MOVETO(x,y) CSI #y ";" #x "H"

// Cute color palette (Pastel/Kawaii theme)
#define COLOR_PINK RGB_FG(255,182,193)
#define COLOR_PEACH RGB_FG(255,218,185)
#define COLOR_YELLOW RGB_FG(255,253,184)
#define COLOR_MINT RGB_FG(185,251,192)
#define COLOR_SKY RGB_FG(173,216,230)
#define COLOR_LAVENDER RGB_FG(221,160,221)
#define COLOR_WHITE RGB_FG(255,255,255)
#define COLOR_SOFT_BLACK RGB_FG(64,64,64)
#define COLOR_ERROR RGB_FG(255,99,71)
#define COLOR_SUCCESS RGB_FG(144,238,144)
#define COLOR_WARNING RGB_FG(255,215,0)

// Background colors
#define BG_PINK RGB_BG(255,182,193)
#define BG_DARK RGB_BG(30,30,40)
#define BG_SELECTED RGB_BG(100,149,237)
#define BG_MENU RGB_BG(45,45,60)

// Cute Unicode symbols
#define HEART "♥"
#define STAR "★"
#define SPARKLE "✨"
#define FLOWER "❀"
#define BUNNY "🐰"
#define BEAR "🐻"
#define CAT "🐱"
#define CHECK "✓"
#define CROSS "✗"
#define ARROW_RIGHT "→"
#define ARROW_LEFT "←"
#define DOTS "･ﾟ✧*:･ﾟ✧"
#define WAVE "～"
#define MUSIC "♪"
#define CLOUD "☁"
#define RAINBOW "🌈"
#define PENGUIN "🐧"

// Boot loader types
typedef enum {
    BOOTLOADER_UNKNOWN,
    BOOTLOADER_GRUB,
    BOOTLOADER_REFIND,
    BOOTLOADER_SYSTEMD_BOOT
} BootLoader;

// Kernel information
typedef struct {
    char version[128];
    char path[256];
    char initrd[256];
    bool is_current;
} KernelInfo;

// Partition information
typedef struct {
    char device[64];
    char filesystem[32];
    char label[128];
    char mount_point[256];
    unsigned long size_mb;
    bool is_system;
    bool is_efi;
} PartitionInfo;

// System information
typedef struct {
    char hostname[256];
    char distro[128];
    char arch[32];
    char device[64];
    char mount_point[256];
    BootLoader boot_loader;
    KernelInfo *kernels;
    int kernel_count;
    PartitionInfo *partitions;
    int partition_count;
    bool mounted;
    bool is_chrooted;
} SystemInfo;

// Cute TUI state
typedef struct {
    SystemInfo sys_info;
    int selected_menu_item;
    int menu_count;
    bool running;
    bool demo_mode;
    bool debug_mode;
    char log_file[256];
    char status_message[512];
    int status_type; // 0=info, 1=success, 2=error, 3=warning
    
    // Animation state
    float animation_time;
    int frame_counter;
    int sparkle_frame;
    int rainbow_offset;
    
    // Terminal dimensions
    int term_width;
    int term_height;
    
    // Input handling
    struct termios original_termios;
    bool raw_mode_enabled;
} CuteTUI;

// Function declarations
void init_cute_tui(CuteTUI *tui);
void cleanup_cute_tui(CuteTUI *tui);
void enable_raw_mode(CuteTUI *tui);
void disable_raw_mode(CuteTUI *tui);
void get_terminal_size(CuteTUI *tui);
void render_cute_ui(CuteTUI *tui);
void render_header(CuteTUI *tui);
void render_menu(CuteTUI *tui);
void render_status(CuteTUI *tui);
void render_footer(CuteTUI *tui);
void handle_input(CuteTUI *tui);
void animate_selection(CuteTUI *tui, int old_item, int new_item);
void sparkle_effect(int x, int y);
void rainbow_text(const char *text, int offset);
void cute_box(int x, int y, int width, int height, const char *title);
void type_text(const char *text, int delay_ms);
bool file_exists(const char *path);
int execute_command(const char *cmd);
int execute_chroot_command(const char *mount_point, const char *cmd);
void detect_boot_loader(SystemInfo *sys_info);
void scan_kernels(SystemInfo *sys_info);
bool mount_system(SystemInfo *sys_info, const char *device);
void unmount_system(SystemInfo *sys_info);
void show_system_info(CuteTUI *tui);
void fix_system(CuteTUI *tui);
void emergency_shell(CuteTUI *tui);
void regenerate_initramfs(CuteTUI *tui);
void fix_boot_configuration(CuteTUI *tui);
void update_system_packages(CuteTUI *tui);
PartitionInfo* scan_partitions(int *count);
char* select_partition(CuteTUI *tui);
void log_message(const char *level, const char *msg, const char *log_file);
void set_status(CuteTUI *tui, const char *msg, int type);
void msleep(int milliseconds);
double get_time(void);

// Initialize the cute TUI
void init_cute_tui(CuteTUI *tui) {
    memset(tui, 0, sizeof(CuteTUI));
    setlocale(LC_ALL, "");  // Enable Unicode support
    
    // Set up log file
    snprintf(tui->log_file, sizeof(tui->log_file), "/tmp/debork_%d.log", getpid());
    
    // Get terminal dimensions
    get_terminal_size(tui);
    
    // Initialize animation state
    tui->animation_time = 0.0;
    tui->frame_counter = 0;
    tui->sparkle_frame = 0;
    tui->rainbow_offset = 0;
    
    // Set up terminal
    printf(ALTERNATE_SCREEN);
    printf(HIDE_CURSOR);
    printf(CLEAR_SCREEN);
    fflush(stdout);
    
    enable_raw_mode(tui);
    tui->running = true;
    tui->menu_count = 6;
}

// Cleanup and restore terminal
void cleanup_cute_tui(CuteTUI *tui) {
    disable_raw_mode(tui);
    printf(SHOW_CURSOR);
    printf(NORMAL_SCREEN);
    printf(RESET);
    fflush(stdout);
    
    // Free allocated memory
    if (tui->sys_info.kernels) {
        free(tui->sys_info.kernels);
    }
    if (tui->sys_info.partitions) {
        free(tui->sys_info.partitions);
    }
}

// Enable raw mode for input handling
void enable_raw_mode(CuteTUI *tui) {
    if (tui->raw_mode_enabled) return;
    
    tcgetattr(STDIN_FILENO, &tui->original_termios);
    struct termios raw = tui->original_termios;
    
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;
    
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    tui->raw_mode_enabled = true;
}

// Disable raw mode
void disable_raw_mode(CuteTUI *tui) {
    if (!tui->raw_mode_enabled) return;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tui->original_termios);
    tui->raw_mode_enabled = false;
}

// Get terminal dimensions
void get_terminal_size(CuteTUI *tui) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    tui->term_width = w.ws_col;
    tui->term_height = w.ws_row;
}

// Render the cute header with ASCII art
void render_header(CuteTUI *tui) {
    printf(MOVETO(1,1));
    
    // Animated sparkles
    int sparkle = (tui->sparkle_frame / 5) % 4;
    const char *sparkles[] = {"✧", "✦", "✧", "･"};
    
    // Cute ASCII art banner
    printf(COLOR_PINK);
    printf("      %s %s %s %s %s %s %s\n", sparkles[sparkle], sparkles[(sparkle+1)%4], 
           sparkles[(sparkle+2)%4], sparkles[(sparkle+3)%4], 
           sparkles[sparkle], sparkles[(sparkle+1)%4], sparkles[(sparkle+2)%4]);
    
    printf(COLOR_LAVENDER "    ╭" COLOR_PINK "─────────────────────────────────" COLOR_LAVENDER "╮\n");
    printf("    │  " COLOR_PEACH "  ♥ " COLOR_WHITE "debork " COLOR_PEACH "♥" COLOR_YELLOW "  " PENGUIN " " COLOR_MINT "v2.0  " COLOR_LAVENDER "│\n");
    printf("    │  " COLOR_SKY "    Boot Rescue Tool " SPARKLE "       " COLOR_LAVENDER "│\n");
    printf("    ╰" COLOR_PINK "─────────────────────────────────" COLOR_LAVENDER "╯\n");
    
    // Cute decorative line
    printf(COLOR_PINK "    " WAVE WAVE WAVE " ");
    rainbow_text("Kawaii Linux Fixer", tui->rainbow_offset);
    printf(COLOR_PINK " " WAVE WAVE WAVE "\n\n");
    
    printf(RESET);
}

// Rainbow text effect
void rainbow_text(const char *text, int offset) {
    const char *colors[] = {
        RGB_FG(255,0,0),    // Red
        RGB_FG(255,127,0),  // Orange
        RGB_FG(255,255,0),  // Yellow
        RGB_FG(0,255,0),    // Green
        RGB_FG(0,0,255),    // Blue
        RGB_FG(75,0,130),   // Indigo
        RGB_FG(148,0,211)   // Violet
    };
    
    int len = strlen(text);
    for (int i = 0; i < len; i++) {
        int color_idx = (i + offset) % 7;
        printf("%s%c", colors[color_idx], text[i]);
    }
}

// Render the menu with animations
void render_menu(CuteTUI *tui) {
    const char *menu_items[] = {
        "Fix My System (Auto-Repair)",
        "Emergency Shell (Manual)",
        "Regenerate Initramfs",
        "Fix Boot Configuration",
        "Show System Information",
        "Exit"
    };
    
    const char *menu_icons[] = {
        "🔧", "💻", "⚙️", "🔨", "📊", "👋"
    };
    
    int menu_x = (tui->term_width - 40) / 2;
    int menu_y = 10;
    
    // Menu box
    printf(MOVETO(menu_x - 2, menu_y - 1));
    printf(COLOR_LAVENDER "╭────────────────────────────────────╮\n");
    
    for (int i = 0; i < tui->menu_count; i++) {
        printf(MOVETO(menu_x - 2, menu_y + i));
        printf(COLOR_LAVENDER "│ ");
        
        if (i == tui->selected_menu_item) {
            // Animated selection with pulsing effect
            float pulse = sin(tui->animation_time * 5.0) * 0.5 + 0.5;
            if (pulse > 0.5) {
                printf(COLOR_YELLOW BOLD);
            } else {
                printf(COLOR_PEACH BOLD);
            }
            printf("→ %s ", menu_icons[i]);
            printf(COLOR_WHITE "%s", menu_items[i]);
            
            // Add sparkles to selected item
            if (tui->frame_counter % 10 == 0) {
                printf(" " SPARKLE);
            }
        } else {
            printf(COLOR_SOFT_BLACK "  %s ", menu_icons[i]);
            printf(DIM COLOR_WHITE "%s", menu_items[i]);
        }
        
        // Pad to box width
        int item_len = strlen(menu_items[i]) + 5;
        for (int j = item_len; j < 35; j++) {
            printf(" ");
        }
        printf(COLOR_LAVENDER "│");
    }
    
    printf(MOVETO(menu_x - 2, menu_y + tui->menu_count));
    printf(COLOR_LAVENDER "╰────────────────────────────────────╯\n");
    printf(RESET);
}

// Render status messages
void render_status(CuteTUI *tui) {
    if (strlen(tui->status_message) == 0) return;
    
    int status_y = 18;
    int status_x = (tui->term_width - strlen(tui->status_message) - 4) / 2;
    
    printf(MOVETO(status_x, status_y));
    
    switch (tui->status_type) {
        case 0: // Info
            printf(COLOR_SKY "ℹ " COLOR_WHITE);
            break;
        case 1: // Success
            printf(COLOR_SUCCESS CHECK " ");
            break;
        case 2: // Error
            printf(COLOR_ERROR CROSS " ");
            break;
        case 3: // Warning
            printf(COLOR_WARNING "⚠ ");
            break;
    }
    
    printf("%s" RESET "\n", tui->status_message);
}

// Render footer with controls
void render_footer(CuteTUI *tui) {
    int footer_y = tui->term_height - 2;
    
    printf(MOVETO(1, footer_y));
    printf(COLOR_SOFT_BLACK "─────────────────────────────────────────────\n");
    
    printf(COLOR_MINT "  [↑↓] Navigate  ");
    printf(COLOR_PEACH "[Enter] Select  ");
    printf(COLOR_SKY "[Q] Quit  ");
    
    // Add cute animation at the end
    const char *animals[] = {CAT, BUNNY, BEAR};
    int animal_idx = (tui->frame_counter / 30) % 3;
    printf(COLOR_PINK "  %s" RESET, animals[animal_idx]);
}

// Main render function
void render_cute_ui(CuteTUI *tui) {
    printf(CLEAR_SCREEN);
    
    render_header(tui);
    render_menu(tui);
    render_status(tui);
    render_footer(tui);
    
    fflush(stdout);
    
    // Update animation counters
    tui->frame_counter++;
    tui->sparkle_frame++;
    tui->rainbow_offset = (tui->rainbow_offset + 1) % 7;
    tui->animation_time += 0.016; // ~60 FPS
}

// Animate menu selection change
void animate_selection(CuteTUI *tui, int old_item, int new_item) {
    // Quick animation between selections
    for (int i = 0; i < 3; i++) {
        tui->selected_menu_item = old_item;
        render_cute_ui(tui);
        msleep(30);
        tui->selected_menu_item = new_item;
        render_cute_ui(tui);
        msleep(30);
    }
}

// Handle keyboard input
void handle_input(CuteTUI *tui) {
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return;
    
    int old_selection = tui->selected_menu_item;
    
    switch (c) {
        case '\033': // Escape sequence
            {
                char seq[2];
                if (read(STDIN_FILENO, &seq[0], 1) != 1) break;
                if (read(STDIN_FILENO, &seq[1], 1) != 1) break;
                
                if (seq[0] == '[') {
                    switch (seq[1]) {
                        case 'A': // Up arrow
                            tui->selected_menu_item = (tui->selected_menu_item - 1 + tui->menu_count) % tui->menu_count;
                            animate_selection(tui, old_selection, tui->selected_menu_item);
                            break;
                        case 'B': // Down arrow
                            tui->selected_menu_item = (tui->selected_menu_item + 1) % tui->menu_count;
                            animate_selection(tui, old_selection, tui->selected_menu_item);
                            break;
                    }
                }
            }
            break;
            
        case 'k': // Vim-style up
            tui->selected_menu_item = (tui->selected_menu_item - 1 + tui->menu_count) % tui->menu_count;
            animate_selection(tui, old_selection, tui->selected_menu_item);
            break;
            
        case 'j': // Vim-style down
            tui->selected_menu_item = (tui->selected_menu_item + 1) % tui->menu_count;
            animate_selection(tui, old_selection, tui->selected_menu_item);
            break;
            
        case '\n': // Enter
        case '\r':
            switch (tui->selected_menu_item) {
                case 0:
                    fix_system(tui);
                    break;
                case 1:
                    emergency_shell(tui);
                    break;
                case 2:
                    regenerate_initramfs(tui);
                    break;
                case 3:
                    fix_boot_configuration(tui);
                    break;
                case 4:
                    show_system_info(tui);
                    break;
                case 5:
                    tui->running = false;
                    break;
            }
            break;
            
        case 'q':
        case 'Q':
            tui->running = false;
            break;
    }
}

// Sleep for milliseconds
void msleep(int milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

// Get current time in seconds
double get_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

// Check if file exists
bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// Execute a command
int execute_command(const char *cmd) {
    return system(cmd);
}

// Execute command in chroot
int execute_chroot_command(const char *mount_point, const char *cmd) {
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "chroot %s %s", mount_point, cmd);
    return execute_command(full_cmd);
}

// Set status message
void set_status(CuteTUI *tui, const char *msg, int type) {
    strncpy(tui->status_message, msg, sizeof(tui->status_message) - 1);
    tui->status_type = type;
    render_cute_ui(tui);
}

// Log message to file
void log_message(const char *level, const char *msg, const char *log_file) {
    FILE *fp = fopen(log_file, "a");
    if (!fp) return;
    
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    
    fprintf(fp, "[%s] [%s] %s\n", timestamp, level, msg);
    fclose(fp);
}

// Detect boot loader
void detect_boot_loader(SystemInfo *sys_info) {
    if (file_exists("/boot/grub") || file_exists("/boot/grub2")) {
        sys_info->boot_loader = BOOTLOADER_GRUB;
    } else if (file_exists("/boot/efi/EFI/refind")) {
        sys_info->boot_loader = BOOTLOADER_REFIND;
    } else if (file_exists("/boot/efi/EFI/systemd") || file_exists("/boot/efi/EFI/BOOT/systemd-boot")) {
        sys_info->boot_loader = BOOTLOADER_SYSTEMD_BOOT;
    } else {
        sys_info->boot_loader = BOOTLOADER_UNKNOWN;
    }
}

// Scan for kernels
void scan_kernels(SystemInfo *sys_info) {
    DIR *dir = opendir("/boot");
    if (!dir) return;
    
    sys_info->kernels = malloc(sizeof(KernelInfo) * 10);
    sys_info->kernel_count = 0;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && sys_info->kernel_count < 10) {
        if (strncmp(entry->d_name, "vmlinuz-", 8) == 0) {
            KernelInfo *kernel = &sys_info->kernels[sys_info->kernel_count];
            strncpy(kernel->version, entry->d_name + 8, sizeof(kernel->version) - 1);
            snprintf(kernel->path, sizeof(kernel->path), "/boot/%s", entry->d_name);
            
            // Look for matching initrd
            char initrd_name[256];
            snprintf(initrd_name, sizeof(initrd_name), "/boot/initrd.img-%s", kernel->version);
            if (file_exists(initrd_name)) {
                strncpy(kernel->initrd, initrd_name, sizeof(kernel->initrd) - 1);
            }
            
            sys_info->kernel_count++;
        }
    }
    
    closedir(dir);
}

// Mount system partition
bool mount_system(SystemInfo *sys_info, const char *device) {
    char mount_cmd[256];
    snprintf(sys_info->mount_point, sizeof(sys_info->mount_point), "/mnt/debork_%d", getpid());
    
    // Create mount point
    char mkdir_cmd[256];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", sys_info->mount_point);
    execute_command(mkdir_cmd);
    
    // Mount the device
    snprintf(mount_cmd, sizeof(mount_cmd), "mount %s %s", device, sys_info->mount_point);
    if (execute_command(mount_cmd) != 0) {
        return false;
    }
    
    strncpy(sys_info->device, device, sizeof(sys_info->device) - 1);
    sys_info->mounted = true;
    
    // Mount necessary filesystems for chroot
    snprintf(mount_cmd, sizeof(mount_cmd), "mount --bind /dev %s/dev", sys_info->mount_point);
    execute_command(mount_cmd);
    snprintf(mount_cmd, sizeof(mount_cmd), "mount --bind /proc %s/proc", sys_info->mount_point);
    execute_command(mount_cmd);
    snprintf(mount_cmd, sizeof(mount_cmd), "mount --bind /sys %s/sys", sys_info->mount_point);
    execute_command(mount_cmd);
    
    return true;
}

// Unmount system
void unmount_system(SystemInfo *sys_info) {
    if (!sys_info->mounted) return;
    
    char umount_cmd[256];
    snprintf(umount_cmd, sizeof(umount_cmd), "umount %s/dev", sys_info->mount_point);
    execute_command(umount_cmd);
    snprintf(umount_cmd, sizeof(umount_cmd), "umount %s/proc", sys_info->mount_point);
    execute_command(umount_cmd);
    snprintf(umount_cmd, sizeof(umount_cmd), "umount %s/sys", sys_info->mount_point);
    execute_command(umount_cmd);
    snprintf(umount_cmd, sizeof(umount_cmd), "umount %s", sys_info->mount_point);
    execute_command(umount_cmd);
    
    sys_info->mounted = false;
}

// Show system information
void show_system_info(CuteTUI *tui) {
    set_status(tui, "Gathering system information...", 0);
    
    detect_boot_loader(&tui->sys_info);
    scan_kernels(&tui->sys_info);
    
    // Clear screen for info display
    printf(CLEAR_SCREEN);
    printf(COLOR_LAVENDER "╭─────────────────────────────────────╮\n");
    printf("│     " COLOR_WHITE "System Information " SPARKLE "        " COLOR_LAVENDER "│\n");
    printf("╰─────────────────────────────────────╯\n\n" RESET);
    
    const char *bootloader_names[] = {
        "Unknown", "GRUB", "rEFInd", "systemd-boot"
    };
    
    printf(COLOR_MINT "  Boot Loader: " COLOR_WHITE "%s\n", bootloader_names[tui->sys_info.boot_loader]);
    printf(COLOR_MINT "  Kernels Found: " COLOR_WHITE "%d\n\n", tui->sys_info.kernel_count);
    
    if (tui->sys_info.kernel_count > 0) {
        printf(COLOR_PEACH "  Available Kernels:\n");
        for (int i = 0; i < tui->sys_info.kernel_count; i++) {
            printf(COLOR_SKY "    • " COLOR_WHITE "%s\n", tui->sys_info.kernels[i].version);
        }
    }
    
    printf("\n" COLOR_YELLOW "  Press any key to continue..." RESET);
    fflush(stdout);
    
    // Wait for key press
    char c;
    while (read(STDIN_FILENO, &c, 1) != 1);
}

// Fix system (main repair function)
void fix_system(CuteTUI *tui) {
    set_status(tui, "Starting system repair... " SPARKLE, 0);
    msleep(1000);
    
    // Select partition if not mounted
    if (!tui->sys_info.mounted) {
        char *partition = select_partition(tui);
        if (!partition) {
            set_status(tui, "No partition selected!", 2);
            return;
        }
        
        if (!mount_system(&tui->sys_info, partition)) {
            set_status(tui, "Failed to mount partition!", 2);
            free(partition);
            return;
        }
        free(partition);
    }
    
    // Detect boot loader
    set_status(tui, "Detecting boot loader...", 0);
    detect_boot_loader(&tui->sys_info);
    
    // Fix boot configuration
    set_status(tui, "Repairing boot configuration...", 0);
    fix_boot_configuration(tui);
    
    // Regenerate initramfs
    set_status(tui, "Regenerating initramfs...", 0);
    regenerate_initramfs(tui);
    
    // Update packages if needed
    set_status(tui, "Checking for package updates...", 0);
    update_system_packages(tui);
    
    set_status(tui, "System repair completed! " CHECK " " SPARKLE, 1);
    msleep(2000);
}

// Emergency shell
void emergency_shell(CuteTUI *tui) {
    disable_raw_mode(tui);
    printf(SHOW_CURSOR);
    printf(CLEAR_SCREEN);
    printf(RESET);
    
    printf(COLOR_YELLOW "═══════════════════════════════════════\n");
    printf("  " PENGUIN " Emergency Shell Mode\n");
    printf("═══════════════════════════════════════\n\n" RESET);
    
    printf(COLOR_MINT "Dropping to shell. Type 'exit' to return to menu.\n\n" RESET);
    
    if (tui->sys_info.mounted) {
        printf(COLOR_SKY "System mounted at: %s\n", tui->sys_info.mount_point);
        printf("To chroot: chroot %s\n\n" RESET, tui->sys_info.mount_point);
    }
    
    // Launch shell
    system("/bin/bash");
    
    printf(HIDE_CURSOR);
    enable_raw_mode(tui);
    set_status(tui, "Returned from emergency shell", 0);
}

// Regenerate initramfs
void regenerate_initramfs(CuteTUI *tui) {
    if (!tui->sys_info.mounted) {
        set_status(tui, "System not mounted!", 2);
        return;
    }
    
    set_status(tui, "Regenerating initramfs... " SPARKLE, 0);
    
    // Try dracut first (Fedora/RHEL)
    if (file_exists("/usr/bin/dracut")) {
        execute_chroot_command(tui->sys_info.mount_point, "dracut -f --regenerate-all");
    }
    // Try mkinitcpio (Arch)
    else if (file_exists("/usr/bin/mkinitcpio")) {
        execute_chroot_command(tui->sys_info.mount_point, "mkinitcpio -P");
    }
    // Try update-initramfs (Debian/Ubuntu)
    else if (file_exists("/usr/sbin/update-initramfs")) {
        execute_chroot_command(tui->sys_info.mount_point, "update-initramfs -u -k all");
    }
    
    set_status(tui, "Initramfs regenerated! " CHECK, 1);
    msleep(1500);
}

// Fix boot configuration
void fix_boot_configuration(CuteTUI *tui) {
    if (!tui->sys_info.mounted) {
        set_status(tui, "System not mounted!", 2);
        return;
    }
    
    switch (tui->sys_info.boot_loader) {
        case BOOTLOADER_GRUB:
            set_status(tui, "Fixing GRUB configuration...", 0);
            execute_chroot_command(tui->sys_info.mount_point, "grub-mkconfig -o /boot/grub/grub.cfg");
            execute_chroot_command(tui->sys_info.mount_point, "grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB");
            break;
            
        case BOOTLOADER_REFIND:
            set_status(tui, "Fixing rEFInd configuration...", 0);
            execute_chroot_command(tui->sys_info.mount_point, "refind-install");
            break;
            
        case BOOTLOADER_SYSTEMD_BOOT:
            set_status(tui, "Fixing systemd-boot configuration...", 0);
            execute_chroot_command(tui->sys_info.mount_point, "bootctl update");
            break;
            
        default:
            set_status(tui, "Unknown boot loader!", 3);
            return;
    }
    
    set_status(tui, "Boot configuration fixed! " CHECK, 1);
    msleep(1500);
}

// Update system packages
void update_system_packages(CuteTUI *tui) {
    if (!tui->sys_info.mounted) {
        set_status(tui, "System not mounted!", 2);
        return;
    }
    
    set_status(tui, "Updating package database...", 0);
    
    // Try different package managers
    if (file_exists("/usr/bin/pacman")) {
        // Arch Linux
        execute_chroot_command(tui->sys_info.mount_point, "pacman -Sy");
    } else if (file_exists("/usr/bin/apt")) {
        // Debian/Ubuntu
        execute_chroot_command(tui->sys_info.mount_point, "apt update");
    } else if (file_exists("/usr/bin/dnf")) {
        // Fedora
        execute_chroot_command(tui->sys_info.mount_point, "dnf check-update");
    } else if (file_exists("/usr/bin/zypper")) {
        // openSUSE
        execute_chroot_command(tui->sys_info.mount_point, "zypper refresh");
    }
    
    set_status(tui, "Package database updated! " CHECK, 1);
    msleep(1500);
}

// Scan partitions
PartitionInfo* scan_partitions(int *count) {
    PartitionInfo *partitions = malloc(sizeof(PartitionInfo) * 20);
    *count = 0;
    
    FILE *fp = popen("lsblk -nro NAME,FSTYPE,LABEL,SIZE,MOUNTPOINT", "r");
    if (!fp) return partitions;
    
    char line[512];
    while (fgets(line, sizeof(line), fp) && *count < 20) {
        PartitionInfo *part = &partitions[*count];
        char size_str[32];
        
        if (sscanf(line, "%s %s %s %s %s", 
                   part->device, part->filesystem, part->label, 
                   size_str, part->mount_point) >= 2) {
            // Convert size to MB (rough estimate)
            part->size_mb = 0; // Would need proper parsing
            
            // Check if it's a system partition
            if (strcmp(part->filesystem, "ext4") == 0 || 
                strcmp(part->filesystem, "btrfs") == 0 ||
                strcmp(part->filesystem, "xfs") == 0) {
                part->is_system = true;
            }
            
            if (strcmp(part->filesystem, "vfat") == 0) {
                part->is_efi = true;
            }
            
            (*count)++;
        }
    }
    
    pclose(fp);
    return partitions;
}

// Select partition interactively
char* select_partition(CuteTUI *tui) {
    int count;
    PartitionInfo *partitions = scan_partitions(&count);
    
    if (count == 0) {
        free(partitions);
        return NULL;
    }
    
    // Show partition selection screen
    disable_raw_mode(tui);
    printf(CLEAR_SCREEN);
    printf(COLOR_LAVENDER "╭─────────────────────────────────────╮\n");
    printf("│     " COLOR_WHITE "Select System Partition " FLOWER "    " COLOR_LAVENDER "│\n");
    printf("╰─────────────────────────────────────╯\n\n" RESET);
    
    for (int i = 0; i < count; i++) {
        if (partitions[i].is_system) {
            printf(COLOR_MINT "  [%d] " COLOR_WHITE "/dev/%s", i + 1, partitions[i].device);
            if (strlen(partitions[i].label) > 0) {
                printf(" (%s)", partitions[i].label);
            }
            printf(" - %s\n", partitions[i].filesystem);
        }
    }
    
    printf("\n" COLOR_YELLOW "Enter partition number: " RESET);
    fflush(stdout);
    
    int choice;
    scanf("%d", &choice);
    
    char *selected = NULL;
    if (choice > 0 && choice <= count) {
        selected = malloc(256);
        snprintf(selected, 256, "/dev/%s", partitions[choice - 1].device);
    }
    
    free(partitions);
    enable_raw_mode(tui);
    return selected;
}

// Main function
int main(int argc, char *argv[]) {
    CuteTUI tui;
    init_cute_tui(&tui);
    
    // Check for demo mode
    if (argc > 1 && strcmp(argv[1], "--demo") == 0) {
        tui.demo_mode = true;
        set_status(&tui, "Running in DEMO mode " RAINBOW, 0);
    }
    
    // Check for root privileges
    if (!tui.demo_mode && geteuid() != 0) {
        cleanup_cute_tui(&tui);
        printf(COLOR_ERROR "Error: This tool must be run as root!\n");
        printf(COLOR_YELLOW "Try: sudo %s\n", argv[0]);
        printf(COLOR_SKY "Or use --demo for demo mode\n" RESET);
        return 1;
    }
    
    // Main loop
    double last_frame_time = get_time();
    const double frame_time = 1.0 / 60.0; // 60 FPS
    
    while (tui.running) {
        double current_time = get_time();
        
        // Handle input
        handle_input(&tui);
        
        // Render at 60 FPS
        if (current_time - last_frame_time >= frame_time) {
            render_cute_ui(&tui);
            last_frame_time = current_time;
        }
        
        // Small sleep to prevent CPU spinning
        msleep(5);
    }
    
    cleanup_cute_tui(&tui);
    
    // Cute goodbye message
    printf(COLOR_PINK "\n  Goodbye! " HEART " Thanks for using debork!\n");
    printf(COLOR_LAVENDER "  " SPARKLE " Stay kawaii! " SPARKLE "\n\n" RESET);
    
    return 0;
}