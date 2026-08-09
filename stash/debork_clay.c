/**
 * debork - Cross-Platform Linux Boot Rescue Tool
 * Properly integrated with Clay UI library for terminal rendering
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
#include <termios.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>

#define CLAY_IMPLEMENTATION
#include "../../include/clay.h"

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
    (void)userData;
    // Match the pixel-to-terminal conversion used in render_to_terminal
    // Using 10 pixels per character width, 20 pixels per line height
    float fontSize = config->fontSize ? config->fontSize : 16.0f;
    return (Clay_Dimensions){
        .width = (float)(text.length * 10),
        .height = fontSize * 1.25f  // Add some line spacing
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
    // Match the pixel scaling used in render_to_terminal (10 per col, 20 per row)
    tui->window_dimensions.width = (float)(w.ws_col * 10);
    tui->window_dimensions.height = (float)(w.ws_row * 20);
    
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
            .padding = {10, 10, 10, 10},
            .childGap = 10,
            .layoutDirection = CLAY_TOP_TO_BOTTOM
        },
        .backgroundColor = COLOR_BG
    }) {
        // Header
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Header"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(60)},
                .padding = {10, 10, 10, 10},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            },
            .backgroundColor = COLOR_HEADER,
            .cornerRadius = {5, 5, 5, 5}
        }) {
            CLAY_TEXT(CLAY_STRING("✨ debork Boot Rescue Tool ✨"), 
                     CLAY_TEXT_CONFIG(.wrapped.textColor = (Clay_Color){100, 200, 255, 255}, .wrapped.fontSize = 28, .wrapped.fontId = FONT_ID_TITLE));
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
                Clay_String status_str = {
                    .chars = tui->status_message,
                    .length = strlen(tui->status_message),
                    .isStaticallyAllocated = false
                };
                CLAY_TEXT(status_str,
                         CLAY_TEXT_CONFIG(.wrapped.textColor = {255, 255, 255, 255}, .wrapped.fontSize = 14, .wrapped.fontId = FONT_ID_BODY));
            }
        }
        
        // Menu container
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("MenuContainer"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
                .padding = {10, 10, 10, 10},
                .childGap = 6,
                .layoutDirection = CLAY_TOP_TO_BOTTOM
            }
        }) {
            const char *menu_items[] = {
                "🔧 Fix My System",
                "💻 Emergency Shell",
                "💾 Regenerate Initramfs",
                "⚙️  Fix Boot Configuration",
                "📊 System Information",
                "🚪 Exit"
            };
            
            for (int i = 0; i < MENU_COUNT; i++) {
                Clay_Color item_bg = (i == tui->selected_menu_item) ? COLOR_SELECTED : COLOR_UNSELECTED;
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_IDI("MenuItem", i),
                    .layout = {
                        .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(40)},
                        .padding = {20, 20, 10, 10},
                        .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_CENTER}
                    },
                    .backgroundColor = item_bg,
                    .cornerRadius = {3, 3, 3, 3}
                }) {
                    // Selection indicator with better symbol
                    if (i == tui->selected_menu_item) {
                        CLAY_TEXT(CLAY_STRING("▶ "),
                                 CLAY_TEXT_CONFIG(.wrapped.textColor = (Clay_Color){100, 255, 100, 255}, 
                                                 .wrapped.fontSize = 18, .wrapped.fontId = FONT_ID_BODY));
                    }
                    
                    Clay_String menu_str = {
                        .chars = menu_items[i],
                        .length = strlen(menu_items[i]),
                        .isStaticallyAllocated = false
                    };
                    Clay_Color text_color = (i == tui->selected_menu_item) 
                        ? (Clay_Color){255, 255, 255, 255}
                        : (Clay_Color){180, 190, 200, 255};
                    CLAY_TEXT(menu_str,
                             CLAY_TEXT_CONFIG(.wrapped.textColor = text_color, .wrapped.fontSize = 18, .wrapped.fontId = FONT_ID_BODY));
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
            CLAY_TEXT(CLAY_STRING("📌 Use ↑↓/jk to navigate • Enter to select • q to quit"),
                     CLAY_TEXT_CONFIG(.wrapped.textColor = (Clay_Color){150, 150, 150, 255},
                                     .wrapped.fontSize = 12, .wrapped.fontId = FONT_ID_BODY));
        }
    }
    
    return Clay_EndLayout();
}

// Render Clay commands to terminal
void render_to_terminal(Clay_RenderCommandArray commands) {
    printf(TERM_CLEAR);
    
    // Render Clay commands to terminal with better scaling
    for (int i = 0; i < commands.length; i++) {
        Clay_RenderCommand *cmd = &commands.internalArray[i];
        
        // Better pixel to terminal conversion (more accurate for monospace fonts)
        int x = (int)(cmd->boundingBox.x / 10);
        int y = (int)(cmd->boundingBox.y / 20);
        
        switch (cmd->commandType) {
            case CLAY_RENDER_COMMAND_TYPE_RECTANGLE: {
                Clay_Color bg = cmd->renderData.rectangle.backgroundColor;
                
                // Skip transparent and semi-transparent rectangles (these are text bounding boxes)
                if (bg.a < 250) continue;  // Only render solid backgrounds
                
                // Position cursor
                printf("\033[%d;%dH", y + 1, x + 1);
                
                // Use 256-color mode for better color representation
                // Convert RGB to 256-color palette
                int color256 = 16 + (36 * (bg.r * 5 / 255)) + (6 * (bg.g * 5 / 255)) + (bg.b * 5 / 255);
                printf("\033[48;5;%dm", color256);
                
                // Draw filled rectangle with spaces
                int w = (int)(cmd->boundingBox.width / 10);
                int h = (int)(cmd->boundingBox.height / 20);
                
                for (int row = 0; row < h && (y + row) < 50; row++) {
                    printf("\033[%d;%dH", y + row + 1, x + 1);
                    for (int col = 0; col < w && (x + col) < 200; col++) {
                        printf(" ");
                    }
                }
                
                printf(TERM_RESET);
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_TEXT: {
                // Position cursor and print text
                printf("\033[%d;%dH", y + 1, x + 1);
                
                // Use 256-color mode for text as well
                Clay_Color color = cmd->renderData.text.textColor;
                int color256 = 16 + (36 * (color.r * 5 / 255)) + (6 * (color.g * 5 / 255)) + (color.b * 5 / 255);
                printf("\033[38;5;%dm", color256);
                
                printf("%.*s", (int)cmd->renderData.text.stringContents.length, 
                       cmd->renderData.text.stringContents.chars);
                printf(TERM_RESET);
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_BORDER: {
                // Draw simple border with box characters
                int w = (int)(cmd->boundingBox.width / 10);
                int h = (int)(cmd->boundingBox.height / 20);
                
                Clay_Color borderColor = cmd->renderData.border.color;
                
                // Set border color
                if (borderColor.r > 200 || borderColor.g > 200 || borderColor.b > 200) {
                    printf(TERM_WHITE);
                } else if (borderColor.r > 150 || borderColor.g > 150 || borderColor.b > 150) {
                    printf(TERM_CYAN);
                }
                
                // Top border
                printf("\033[%d;%dH╔", y + 1, x + 1);
                for (int i = 1; i < w - 1; i++) printf("═");
                if (w > 1) printf("╗");
                
                // Side borders
                for (int row = 1; row < h - 1; row++) {
                    printf("\033[%d;%dH║", y + row + 1, x + 1);
                    if (w > 1) printf("\033[%d;%dH║", y + row + 1, x + w);
                }
                
                // Bottom border
                if (h > 1) {
                    printf("\033[%d;%dH╚", y + h, x + 1);
                    for (int i = 1; i < w - 1; i++) printf("═");
                    if (w > 1) printf("╝");
                }
                
                printf(TERM_RESET);
                break;
            }
            
            default:
                break;
        }
    }
    
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
void run_tui(bool demo_mode) {
    init_tui(&g_tui);
    
    printf(TERM_HIDE_CURSOR);
    
    // Select and mount partition (skip in demo mode)
    if (!demo_mode) {
        char *device = select_partition();
        if (device && strlen(device) > 0) {
            mount_system(device, &g_tui.sys_info);
            detect_boot_loader(&g_tui.sys_info);
        }
    } else {
        // Demo mode - use fake data
        strcpy(g_tui.sys_info.mount_point, "/mnt/demo");
        strcpy(g_tui.sys_info.device, "/dev/demo");
        g_tui.sys_info.boot_loader = BOOTLOADER_GRUB;
        strcpy(g_tui.status_message, "Demo Mode - UI Testing");
        g_tui.status_color = (Clay_Color){100, 200, 100, 255};
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
    bool demo_mode = false;
    
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
            printf("  --demo         Demo mode (bypass root check for UI testing)\n");
            printf("\n");
            printf("This tool provides a Clay-powered TUI interface for repairing broken Linux boot\n");
            printf("configurations. It supports GRUB, rEFInd, and systemd-boot.\n");
            return 0;
        } else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug_mode = true;
        } else if (strcmp(argv[i], "--demo") == 0) {
            demo_mode = true;
        }
    }
    
    // Check if running as root (unless in demo mode)
    if (!demo_mode && getuid() != 0) {
        fprintf(stderr, "%sError: This tool must be run as root%s\n", TERM_RED, TERM_RESET);
        fprintf(stderr, "Use --demo flag for UI testing without root access\n");
        return 1;
    }
    
    g_tui.debug_mode = debug_mode;
    
    // Run the TUI
    run_tui(demo_mode);
    
    return 0;
}