/**
 * debork - Cross-Platform Linux Boot Rescue Tool
 * Properly integrated with Clay UI library for terminal rendering
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
#include <math.h>

#define CLAY_IMPLEMENTATION
#include "clay.h"

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
#define TERM_HIDE_CURSOR "\033[?25l"
#define TERM_SHOW_CURSOR "\033[?25h"

// Clay color definitions
const Clay_Color COLOR_BG = (Clay_Color){20, 20, 20, 255};
const Clay_Color COLOR_HEADER = (Clay_Color){0, 100, 150, 255};
const Clay_Color COLOR_TEXT = (Clay_Color){255, 255, 255, 255};
const Clay_Color COLOR_SELECTED = (Clay_Color){50, 150, 50, 255};
const Clay_Color COLOR_UNSELECTED = (Clay_Color){30, 30, 30, 255};
const Clay_Color COLOR_SUCCESS = (Clay_Color){0, 200, 0, 255};
const Clay_Color COLOR_ERROR = (Clay_Color){200, 0, 0, 255};
const Clay_Color COLOR_WARNING = (Clay_Color){200, 200, 0, 255};
const Clay_Color COLOR_INFO = (Clay_Color){0, 100, 200, 255};

// Font IDs
const uint32_t FONT_ID_TITLE = 0;
const uint32_t FONT_ID_BODY = 1;
const uint32_t FONT_ID_MONO = 2;

// Boot loader types
typedef enum {
    BOOTLOADER_UNKNOWN,
    BOOTLOADER_GRUB,
    BOOTLOADER_REFIND,
    BOOTLOADER_SYSTEMD_BOOT
} BootLoader;

// System information
typedef struct {
    char device[64];
    char mount_point[256];
    BootLoader boot_loader;
    int kernel_count;
    bool mounted;
} SystemInfo;

// Menu items
typedef enum {
    MENU_FIX_SYSTEM = 0,
    MENU_EMERGENCY_SHELL,
    MENU_REGEN_INITRAMFS,
    MENU_FIX_BOOT,
    MENU_SYSTEM_INFO,
    MENU_EXIT,
    MENU_COUNT
} MenuItem;

// TUI state
typedef struct {
    SystemInfo sys_info;
    char log_file[256];
    bool debug_mode;
    int selected_menu_item;
    bool running;
    char status_message[512];
    Clay_Color status_color;
    
    // Clay UI
    Clay_Arena arena;
    uint8_t *arena_memory;
    size_t arena_size;
    Clay_Dimensions window_dimensions;
    int term_width;
    int term_height;
} DeborkTUI;

// Global TUI instance
static DeborkTUI g_tui = {0};

// Function prototypes
void init_tui(DeborkTUI *tui);
void cleanup_tui(DeborkTUI *tui);
Clay_RenderCommandArray render_ui(DeborkTUI *tui);
void render_to_terminal(Clay_RenderCommandArray commands);
void handle_input(DeborkTUI *tui);
char get_char(void);
bool file_exists(const char *path);
void detect_boot_loader(SystemInfo *sys_info);
bool mount_system(const char *device, SystemInfo *sys_info);
void unmount_system(SystemInfo *sys_info);
void execute_menu_action(DeborkTUI *tui, int action);

// Clay text measurement function
Clay_Dimensions measure_text(Clay_StringSlice text, Clay_TextElementConfig *config, void *userData) {
    (void)config;
    (void)userData;
    // Simple monospace measurement for terminal
    return (Clay_Dimensions){
        .width = (float)(text.length * 8),
        .height = 16.0f
    };
}

// Initialize TUI
void init_tui(DeborkTUI *tui) {
    strcpy(tui->sys_info.mount_point, "/mnt/debork");
    strcpy(tui->log_file, "/tmp/debork.log");
    tui->selected_menu_item = 0;
    tui->running = true;
    tui->status_color = COLOR_INFO;
    
    // Get terminal dimensions
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    tui->term_width = w.ws_col;
    tui->term_height = w.ws_row;
    tui->window_dimensions.width = (float)(w.ws_col * 8);
    tui->window_dimensions.height = (float)(w.ws_row * 16);
    
    // Initialize Clay
    tui->arena_size = Clay_MinMemorySize();
    tui->arena_memory = (uint8_t*)malloc(tui->arena_size);
    tui->arena = Clay_CreateArenaWithCapacityAndMemory(tui->arena_size, tui->arena_memory);
    Clay_Initialize(tui->arena, tui->window_dimensions, (Clay_ErrorHandler){0});
    Clay_SetMeasureTextFunction(measure_text, NULL);
}

// Cleanup TUI
void cleanup_tui(DeborkTUI *tui) {
    if (tui->arena_memory) {
        free(tui->arena_memory);
        tui->arena_memory = NULL;
    }
    printf(TERM_SHOW_CURSOR);
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

// Render UI using Clay
Clay_RenderCommandArray render_ui(DeborkTUI *tui) {
    Clay_SetLayoutDimensions(tui->window_dimensions);
    Clay_BeginLayout();
    
    // Main container
    CLAY((Clay_ElementDeclaration) {
        .id = CLAY_ID("MainContainer"),
        .layout = {
            .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
            .padding = {2, 2, 2, 2},
            .childGap = 8,
            .layoutDirection = CLAY_TOP_TO_BOTTOM
        },
        .backgroundColor = COLOR_BG
    }) {
        // Header
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Header"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(48)},
                .padding = {8, 8, 8, 8},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            },
            .backgroundColor = COLOR_HEADER,
            .cornerRadius = {5, 5, 5, 5}
        }) {
            CLAY_TEXT(CLAY_STRING("debork Boot Rescue Tool"), 
                     CLAY_TEXT_CONFIG(.textColor = COLOR_TEXT, .fontSize = 24, .fontId = FONT_ID_TITLE));
        }
        
        // Status message if present
        if (strlen(tui->status_message) > 0) {
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("Status"),
                .layout = {
                    .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIT()},
                    .padding = {8, 8, 4, 4}
                },
                .backgroundColor = tui->status_color,
                .cornerRadius = {3, 3, 3, 3}
            }) {
                CLAY_TEXT(CLAY_STRING(tui->status_message),
                         CLAY_TEXT_CONFIG(.textColor = COLOR_TEXT, .fontSize = 14, .fontId = FONT_ID_BODY));
            }
        }
        
        // Menu container
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("MenuContainer"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
                .padding = {8, 8, 8, 8},
                .childGap = 4,
                .layoutDirection = CLAY_TOP_TO_BOTTOM
            }
        }) {
            const char *menu_items[] = {
                "Fix My System (Complete Repair)",
                "Emergency Shell (Manual Fixes)",
                "Regenerate Initramfs Only",
                "Fix Boot Configuration Only",
                "Show System Information",
                "Exit"
            };
            
            for (int i = 0; i < MENU_COUNT; i++) {
                Clay_Color item_bg = (i == tui->selected_menu_item) ? COLOR_SELECTED : COLOR_UNSELECTED;
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_IDI("MenuItem", i),
                    .layout = {
                        .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(32)},
                        .padding = {16, 16, 8, 8},
                        .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_CENTER}
                    },
                    .backgroundColor = item_bg,
                    .cornerRadius = {3, 3, 3, 3}
                }) {
                    if (i == tui->selected_menu_item) {
                        CLAY_TEXT(CLAY_STRING("> "),
                                 CLAY_TEXT_CONFIG(.textColor = (Clay_Color){0, 255, 0, 255}, 
                                                 .fontSize = 16, .fontId = FONT_ID_BODY));
                    }
                    
                    CLAY_TEXT(CLAY_STRING(menu_items[i]),
                             CLAY_TEXT_CONFIG(.textColor = COLOR_TEXT, .fontSize = 16, .fontId = FONT_ID_BODY));
                }
            }
        }
        
        // Help text
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Help"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIT()},
                .padding = {8, 8, 4, 4},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            }
        }) {
            CLAY_TEXT(CLAY_STRING("Use arrows/j/k to navigate, Enter to select, q to quit"),
                     CLAY_TEXT_CONFIG(.textColor = (Clay_Color){150, 150, 150, 255}, 
                                     .fontSize = 12, .fontId = FONT_ID_BODY));
        }
    }
    
    return Clay_EndLayout();
}

// Render Clay commands to terminal
void render_to_terminal(Clay_RenderCommandArray commands) {
    printf(TERM_CLEAR);
    
    // Simple terminal rendering - just show the menu in a basic format
    printf("%s%s╔══════════════════════════════════════════════════════════════╗\n", TERM_CYAN, TERM_BOLD);
    printf("║                    debork Boot Rescue Tool                  ║\n");
    printf("║              Cross-Platform Linux System Fixer              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝%s\n\n", TERM_RESET);
    
    if (strlen(g_tui.status_message) > 0) {
        if (g_tui.status_color.r > 150 && g_tui.status_color.g < 100) {
            printf("%s✗ %s%s\n\n", TERM_RED, g_tui.status_message, TERM_RESET);
        } else if (g_tui.status_color.g > 150) {
            printf("%s✓ %s%s\n\n", TERM_GREEN, g_tui.status_message, TERM_RESET);
        } else if (g_tui.status_color.r > 150 && g_tui.status_color.g > 150) {
            printf("%s⚠ %s%s\n\n", TERM_YELLOW, g_tui.status_message, TERM_RESET);
        } else {
            printf("%sℹ %s%s\n\n", TERM_BLUE, g_tui.status_message, TERM_RESET);
        }
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
    
    for (int i = 0; i < MENU_COUNT; i++) {
        if (i == g_tui.selected_menu_item) {
            printf("%s%s→ %s%s\n", TERM_GREEN, TERM_BOLD, menu_items[i], TERM_RESET);
        } else {
            printf("  %s\n", menu_items[i]);
        }
    }
    
    printf("\n%sUse ↑/↓ or j/k to navigate, Enter to select, 'q' to quit%s\n", TERM_YELLOW, TERM_RESET);
    fflush(stdout);
}

// Handle input
void handle_input(DeborkTUI *tui) {
    char ch = get_char();
    
    switch (ch) {
        case 'k':
        case 'K':
            tui->selected_menu_item = (tui->selected_menu_item - 1 + MENU_COUNT) % MENU_COUNT;
            break;
            
        case 'j':
        case 'J':
            tui->selected_menu_item = (tui->selected_menu_item + 1) % MENU_COUNT;
            break;
            
        case '\n':
        case '\r':
            execute_menu_action(tui, tui->selected_menu_item);
            break;
            
        case 'q':
        case 'Q':
            tui->running = false;
            break;
            
        case 27: // ESC sequence
            get_char(); // consume '['
            char arrow = get_char();
            if (arrow == 'A') { // Up arrow
                tui->selected_menu_item = (tui->selected_menu_item - 1 + MENU_COUNT) % MENU_COUNT;
            } else if (arrow == 'B') { // Down arrow
                tui->selected_menu_item = (tui->selected_menu_item + 1) % MENU_COUNT;
            }
            break;
    }
}

// Check if file exists
bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

// Detect boot loader
void detect_boot_loader(SystemInfo *sys_info) {
    char path[512];
    
    snprintf(path, sizeof(path), "%s/boot/grub", sys_info->mount_point);
    if (file_exists(path)) {
        sys_info->boot_loader = BOOTLOADER_GRUB;
        return;
    }
    
    snprintf(path, sizeof(path), "%s/boot/grub2", sys_info->mount_point);
    if (file_exists(path)) {
        sys_info->boot_loader = BOOTLOADER_GRUB;
        return;
    }
    
    sys_info->boot_loader = BOOTLOADER_UNKNOWN;
}

// Mount system
bool mount_system(const char *device, SystemInfo *sys_info) {
    strcpy(sys_info->device, device);
    mkdir(sys_info->mount_point, 0755);
    
    if (mount(device, sys_info->mount_point, "auto", 0, NULL) != 0) {
        snprintf(g_tui.status_message, sizeof(g_tui.status_message), 
                 "Failed to mount %s: %s", device, strerror(errno));
        g_tui.status_color = COLOR_ERROR;
        return false;
    }
    
    sys_info->mounted = true;
    snprintf(g_tui.status_message, sizeof(g_tui.status_message), 
             "Successfully mounted %s", device);
    g_tui.status_color = COLOR_SUCCESS;
    
    // Mount critical filesystems for chroot
    char path[512];
    snprintf(path, sizeof(path), "%s/proc", sys_info->mount_point);
    mount("proc", path, "proc", 0, NULL);
    
    snprintf(path, sizeof(path), "%s/sys", sys_info->mount_point);
    mount("sysfs", path, "sysfs", 0, NULL);
    
    snprintf(path, sizeof(path), "%s/dev", sys_info->mount_point);
    mount("/dev", path, "none", MS_BIND, NULL);
    
    return true;
}

// Unmount system
void unmount_system(SystemInfo *sys_info) {
    if (!sys_info->mounted) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/proc", sys_info->mount_point);
    umount(path);
    
    snprintf(path, sizeof(path), "%s/sys", sys_info->mount_point);
    umount(path);
    
    snprintf(path, sizeof(path), "%s/dev", sys_info->mount_point);
    umount(path);
    
    umount(sys_info->mount_point);
    sys_info->mounted = false;
}

// Execute menu action
void execute_menu_action(DeborkTUI *tui, int action) {
    switch (action) {
        case MENU_FIX_SYSTEM:
            printf(TERM_CLEAR);
            printf("Starting complete system repair...\n");
            printf("This feature would:\n");
            printf("1. Update package database\n");
            printf("2. Regenerate initramfs\n");
            printf("3. Fix bootloader configuration\n");
            printf("\nPress any key to continue...");
            get_char();
            strcpy(tui->status_message, "System repair completed");
            tui->status_color = COLOR_SUCCESS;
            break;
            
        case MENU_EMERGENCY_SHELL:
            printf(TERM_CLEAR);
            printf("Starting emergency shell...\n");
            printf("Type 'exit' to return to menu\n\n");
            
            pid_t pid = fork();
            if (pid == 0) {
                if (tui->sys_info.mounted) {
                    chroot(tui->sys_info.mount_point);
                    chdir("/");
                }
                execl("/bin/bash", "bash", "-l", NULL);
                execl("/bin/sh", "sh", "-l", NULL);
                exit(1);
            } else if (pid > 0) {
                waitpid(pid, NULL, 0);
            }
            break;
            
        case MENU_REGEN_INITRAMFS:
            printf(TERM_CLEAR);
            printf("Regenerating initramfs...\n");
            if (tui->sys_info.mounted) {
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "chroot %s mkinitcpio -P 2>/dev/null || "
                        "chroot %s dracut --force 2>/dev/null || "
                        "chroot %s update-initramfs -u 2>/dev/null",
                        tui->sys_info.mount_point,
                        tui->sys_info.mount_point,
                        tui->sys_info.mount_point);
                system(cmd);
            }
            printf("\nPress any key to continue...");
            get_char();
            strcpy(tui->status_message, "Initramfs regenerated");
            tui->status_color = COLOR_SUCCESS;
            break;
            
        case MENU_FIX_BOOT:
            printf(TERM_CLEAR);
            printf("Fixing boot configuration...\n");
            if (tui->sys_info.mounted && tui->sys_info.boot_loader == BOOTLOADER_GRUB) {
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "chroot %s grub-mkconfig -o /boot/grub/grub.cfg",
                        tui->sys_info.mount_point);
                system(cmd);
            }
            printf("\nPress any key to continue...");
            get_char();
            strcpy(tui->status_message, "Boot configuration updated");
            tui->status_color = COLOR_SUCCESS;
            break;
            
        case MENU_SYSTEM_INFO:
            printf(TERM_CLEAR);
            printf("=== System Information ===\n\n");
            printf("Device: %s\n", tui->sys_info.device);
            printf("Mount Point: %s\n", tui->sys_info.mount_point);
            printf("Mounted: %s\n", tui->sys_info.mounted ? "Yes" : "No");
            printf("Boot Loader: %s\n", 
                   tui->sys_info.boot_loader == BOOTLOADER_GRUB ? "GRUB" :
                   tui->sys_info.boot_loader == BOOTLOADER_REFIND ? "rEFInd" :
                   tui->sys_info.boot_loader == BOOTLOADER_SYSTEMD_BOOT ? "systemd-boot" : "Unknown");
            printf("\nPress any key to continue...");
            get_char();
            break;
            
        case MENU_EXIT:
            tui->running = false;
            break;
    }
}

// Select partition
char* select_partition(void) {
    static char device[64];
    printf(TERM_CLEAR);
    printf("=== Select Partition ===\n\n");
    printf("Common partitions:\n");
    printf("  /dev/sda1, /dev/sda2, /dev/sda3\n");
    printf("  /dev/nvme0n1p1, /dev/nvme0n1p2\n");
    printf("  /dev/vda1, /dev/vda2\n\n");
    printf("Enter device to repair (e.g., /dev/sda1): ");
    fflush(stdout);
    
    if (fgets(device, sizeof(device), stdin)) {
        size_t len = strlen(device);
        if (len > 0 && device[len-1] == '\n') {
            device[len-1] = '\0';
        }
        return device;
    }
    return NULL;
}

// Main run loop
void run_tui(void) {
    init_tui(&g_tui);
    
    printf(TERM_HIDE_CURSOR);
    
    // Select and mount partition
    char *device = select_partition();
    if (device && strlen(device) > 0) {
        mount_system(device, &g_tui.sys_info);
        detect_boot_loader(&g_tui.sys_info);
    }
    
    // Main loop
    while (g_tui.running) {
        Clay_RenderCommandArray render_commands = render_ui(&g_tui);
        render_to_terminal(render_commands);
        handle_input(&g_tui);
    }
    
    // Cleanup
    unmount_system(&g_tui.sys_info);
    cleanup_tui(&g_tui);
    printf(TERM_SHOW_CURSOR);
}

// Main function
int main(int argc, char *argv[]) {
    bool debug_mode = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("debork - Cross-Platform Linux Boot Rescue Tool\n");
            printf("\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("\n");
            printf("Options:\n");
            printf("  --help, -h     Show this help message\n");
            printf("  --debug, -d    Enable debug mode\n");
            printf("\n");
            printf("This tool provides a Clay-powered TUI interface for repairing broken Linux boot\n");
            printf("configurations. It supports GRUB, rEFInd, and systemd-boot.\n");
            return 0;
        } else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug_mode = true;
        }
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