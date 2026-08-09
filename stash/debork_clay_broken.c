/*
 * debork - Cross-Platform Linux Boot Rescue Tool
 * Clay UI Version
 * 
 * This tool helps recover broken Linux boot configurations
 * with a modern TUI interface powered by Clay.
 * 
 * Features:
 * - Automatic boot loader detection
 * - Kernel and initramfs management
 * - Multiple boot loader support (GRUB, rEFInd, systemd-boot)
 * - Emergency shell access
 * - System package updates
 * 
 * Author: Assistant
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>

#define CLAY_IMPLEMENTATION
#include "clay.h"

// ANSI color codes
#define TERM_RESET      "\033[0m"
#define TERM_RED        "\033[31m"
#define TERM_GREEN      "\033[32m"
#define TERM_YELLOW     "\033[33m"
#define TERM_BLUE       "\033[34m"
#define TERM_MAGENTA    "\033[35m"
#define TERM_CYAN       "\033[36m"
#define TERM_WHITE      "\033[37m"
#define TERM_BOLD       "\033[1m"
#define TERM_CLEAR      "\033[2J\033[H"
#define TERM_HIDE_CURSOR "\033[?25l"
#define TERM_SHOW_CURSOR "\033[?25h"
#define TERM_SAVE_POS   "\033[s"
#define TERM_RESTORE_POS "\033[u"

// Boot loader types
typedef enum {
    BOOT_LOADER_UNKNOWN = 0,
    BOOT_LOADER_GRUB,
    BOOT_LOADER_REFIND,
    BOOT_LOADER_SYSTEMD_BOOT
} BootLoader;

// Kernel info structure
typedef struct {
    char version[256];
    char path[512];
    char initrd_path[512];
    bool has_initrd;
    bool is_current;
} KernelInfo;

// System info structure
typedef struct {
    char mount_point[256];
    char boot_dir[256];
    char efi_dir[256];
    char root_device[64];
    char distro[128];
    BootLoader boot_loader;
    KernelInfo *kernels;
    int kernel_count;
    bool is_uefi;
    bool is_mounted;
    bool has_network;
} SystemInfo;

// Menu item structure
typedef struct {
    const char *label;
    const char *description;
    char shortcut;
    void (*action)(void);
    bool enabled;
    bool dangerous;
} MenuItem;

// TUI state structure
typedef struct {
    SystemInfo sys_info;
    int selected_menu_item;
    int menu_item_count;
    bool running;
    bool needs_redraw;
    char status_message[512];
    int status_type; // 0 = info, 1 = success, 2 = warning, 3 = error
    char log_buffer[4096];
    int log_line_count;
    BootLoader selected_boot_loader;
    int selected_kernel_index;
    struct termios orig_termios;
    int term_width;
    int term_height;
    
    // Clay specific
    Clay_Arena clay_arena;
    Clay_RenderCommandArray render_commands;
} DeborkTUI;

// Global TUI instance
static DeborkTUI *g_tui = NULL;

// Terminal renderer for Clay
typedef struct {
    int width;
    int height;
    char *buffer;
    size_t buffer_size;
} TermRenderer;

static TermRenderer g_renderer = {0};

// Function declarations
void init_tui(DeborkTUI *tui);
void cleanup_tui(DeborkTUI *tui);
void render_ui(DeborkTUI *tui);
void handle_input(DeborkTUI *tui);
void init_terminal_renderer(void);
void cleanup_terminal_renderer(void);
void render_clay_to_terminal(Clay_RenderCommandArray *commands);
void draw_box(int x, int y, int width, int height, const char *title);
Clay_Dimensions measure_text_function(Clay_StringSlice text, Clay_TextElementConfig *config, void *userData);
void log_message(DeborkTUI *tui, const char *format, ...);
char get_char(void);
bool file_exists(const char *path);
void detect_boot_loader(SystemInfo *info);
void scan_kernels(SystemInfo *info);
bool mount_system(SystemInfo *info, const char *device);
void unmount_system(SystemInfo *info);
void emergency_shell(void);
void regenerate_initramfs(void);
void fix_grub(void);
void show_system_info(void);
void update_system_packages(void);
char* select_partition(void);

// Terminal renderer implementation
void init_terminal_renderer(void) {
    struct winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    g_renderer.width = ws.ws_col;
    g_renderer.height = ws.ws_row;
    g_renderer.buffer_size = g_renderer.width * g_renderer.height * 32;
    g_renderer.buffer = malloc(g_renderer.buffer_size);
    memset(g_renderer.buffer, 0, g_renderer.buffer_size);
}

void cleanup_terminal_renderer(void) {
    if (g_renderer.buffer) {
        free(g_renderer.buffer);
        g_renderer.buffer = NULL;
    }
}

// Clay measure text function
Clay_Dimensions measure_text_function(Clay_StringSlice text, Clay_TextElementConfig *config, void *userData) {
    (void)userData; // Unused
    // Simple monospace text measurement
    // Assuming 1 character = 8 pixels width, font height based on fontSize
    int char_width = 8;
    int char_height = config->fontSize ? config->fontSize : 16;
    
    return (Clay_Dimensions) {
        .width = text.length * char_width,
        .height = char_height
    };
}

// Render Clay commands to terminal
void render_clay_to_terminal(Clay_RenderCommandArray *commands) {
    printf(TERM_CLEAR);
    
    for (int i = 0; i < commands->length; i++) {
        Clay_RenderCommand *cmd = &commands->internalArray[i];
        
        switch (cmd->commandType) {
            case CLAY_RENDER_COMMAND_TYPE_RECTANGLE: {
                Clay_Color bg = cmd->renderData.rectangle.backgroundColor;
                int x = cmd->boundingBox.x / 8;
                int y = cmd->boundingBox.y / 16;
                int w = cmd->boundingBox.width / 8;
                int h = cmd->boundingBox.height / 16;
                
                // Draw background with ANSI colors
                if (bg.a > 0) {
                    printf("\033[%d;%dH", y + 1, x + 1);
                    
                    // Map RGB to basic ANSI colors
                    if (bg.r > 200 && bg.g > 200 && bg.b > 200) {
                        printf("\033[47m"); // White background
                    } else if (bg.r > 128) {
                        printf("\033[41m"); // Red background
                    } else if (bg.g > 128) {
                        printf("\033[42m"); // Green background
                    } else if (bg.b > 128) {
                        printf("\033[44m"); // Blue background
                    } else if (bg.r > 50 || bg.g > 50 || bg.b > 50) {
                        printf("\033[100m"); // Dark gray background
                    } else {
                        printf("\033[40m"); // Black background
                    }
                    
                    // Fill area with spaces
                    for (int row = 0; row < h && (y + row) < g_renderer.height; row++) {
                        printf("\033[%d;%dH", y + row + 1, x + 1);
                        for (int col = 0; col < w && (x + col) < g_renderer.width; col++) {
                            printf(" ");
                        }
                    }
                    printf(TERM_RESET);
                }
                
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_TEXT: {
                Clay_Color color = {255, 255, 255, 255}; // Default white text
                int x = cmd->boundingBox.x / 8;
                int y = cmd->boundingBox.y / 16;
                
                printf("\033[%d;%dH", y + 1, x + 1);
                
                // Set text color
                if (color.r > 200 && color.g > 200 && color.b > 200) {
                    printf(TERM_WHITE);
                } else if (color.r > color.g && color.r > color.b) {
                    printf(TERM_RED);
                } else if (color.g > color.r && color.g > color.b) {
                    printf(TERM_GREEN);
                } else if (color.b > color.r && color.b > color.g) {
                    printf(TERM_BLUE);
                } else if (color.r > 200 && color.g > 200) {
                    printf(TERM_YELLOW);
                } else if (color.r > 200 && color.b > 200) {
                    printf(TERM_MAGENTA);
                } else if (color.g > 200 && color.b > 200) {
                    printf(TERM_CYAN);
                }
                
                // Print text
                printf("%.*s", (int)cmd->renderData.text.stringContents.length, cmd->renderData.text.stringContents.chars);
                printf(TERM_RESET);
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_BORDER: {
                // Draw border
                int x = cmd->boundingBox.x / 8;
                int y = cmd->boundingBox.y / 16;
                int w = cmd->boundingBox.width / 8;
                int h = cmd->boundingBox.height / 16;
                
                draw_box(x, y, w, h, NULL);
                break;
            }
            
            default:
                break;
        }
    }
    
    fflush(stdout);
}

// Initialize TUI
void init_tui(DeborkTUI *tui) {
    // Save terminal settings
    tcgetattr(STDIN_FILENO, &tui->orig_termios);
    
    // Set raw mode
    struct termios raw = tui->orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    
    // Get terminal size
    struct winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    tui->term_width = ws.ws_col;
    tui->term_height = ws.ws_row;
    
    // Initialize Clay
    uint64_t arenaMemorySize = 1024 * 1024;
    void *arenaMemory = malloc(arenaMemorySize);
    tui->clay_arena = Clay_CreateArenaWithCapacityAndMemory(arenaMemorySize, arenaMemory);
    Clay_SetMeasureTextFunction(measure_text_function, NULL);
    
    // Initialize terminal renderer
    init_terminal_renderer();
    
    // Hide cursor and clear screen
    printf(TERM_HIDE_CURSOR TERM_CLEAR);
    fflush(stdout);
}

// Cleanup TUI
void cleanup_tui(DeborkTUI *tui) {
    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tui->orig_termios);
    printf(TERM_SHOW_CURSOR TERM_CLEAR);
    fflush(stdout);
    
    cleanup_terminal_renderer();
}

// Get single character input
char get_char(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) == 1) {
        return c;
    }
    return 0;
}

// Log message
void log_message(DeborkTUI *tui, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    char buffer[512];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    // Add to log buffer
    size_t current_len = strlen(tui->log_buffer);
    size_t new_len = strlen(buffer);
    
    if (current_len + new_len + 2 < sizeof(tui->log_buffer)) {
        strcat(tui->log_buffer, buffer);
        strcat(tui->log_buffer, "\n");
        tui->log_line_count++;
    }
    
    va_end(args);
}

// Render UI using Clay
void render_ui(DeborkTUI *tui) {
    // Configure Clay for this frame
    Clay_SetLayoutDimensions((Clay_Dimensions) {
        .width = tui->term_width * 8,  // Convert to pixels
        .height = tui->term_height * 16
    });
    
    // Begin layout
    Clay_BeginLayout();
    
    // Root container
    CLAY((Clay_ElementDeclaration) {
        .id = CLAY_ID("RootContainer"),
        .layoutConfig = {
            .sizing = {
                .width = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 1}},
                .height = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 1}}
            },
            .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_TOP},
            .layoutDirection = CLAY_LAYOUT_DIRECTION_TOP_TO_BOTTOM,
            .padding = {8, 8, 8, 8}
        },
        .backgroundColor = {20, 20, 20, 255}
    }) {
        
        // Title bar
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("TitleBar"),
            .layoutConfig = {
                .sizing = {
                    .width = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 1}},
                    .height = {.type = CLAY_SIZE_TYPE_FIXED, .value = {.fixed = 40}}
                },
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER},
                .padding = {10, 10, 10, 10}
            },
            .backgroundColor = {40, 40, 40, 255},
            .cornerRadius = {4, 4, 4, 4},
            .borderConfig = {
                .color = {100, 100, 100, 255},
                .width = {2, 2, 2, 2}
            }
        }) {
            
            CLAY_TEXT(CLAY_STRING("debork Boot Rescue Tool"), 
                     CLAY_TEXT_CONFIG(
                         .textColor = {255, 255, 255, 255},
                         .fontSize = 20,
                         .fontId = 0
                     ));
        }
        
        // Status message if present
        if (strlen(tui->status_message) > 0) {
            Clay_Color status_bg = {50, 50, 50, 255};
            if (tui->status_type == 1) status_bg = (Clay_Color){0, 100, 0, 255};
            else if (tui->status_type == 2) status_bg = (Clay_Color){100, 100, 0, 255};
            else if (tui->status_type == 3) status_bg = (Clay_Color){100, 0, 0, 255};
            
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("StatusBar"),
                .layoutConfig = {
                    .sizing = {
                        .width = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 1}},
                        .height = {.type = CLAY_SIZE_TYPE_FIXED, .value = {.fixed = 30}}
                    },
                    .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER},
                    .padding = {8, 8, 4, 4}
                },
                .backgroundColor = status_bg,
                .cornerRadius = {4, 4, 4, 4}
            }) {
                
                CLAY_TEXT(CLAY_STRING(tui->status_message),
                         CLAY_TEXT_CONFIG(
                             .textColor = {255, 255, 255, 255},
                             .fontSize = 14,
                             .fontId = 0
                         ));
            }
        }
        
        // Menu container
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("MenuContainer"),
            .layoutConfig = {
                .sizing = {
                    .width = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 0.8}},
                    .height = {.type = CLAY_SIZE_TYPE_GROW, .value = {}}
                },
                .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_TOP},
                .layoutDirection = CLAY_LAYOUT_DIRECTION_TOP_TO_BOTTOM,
                .padding = {10, 10, 10, 10}
            },
            .backgroundColor = {30, 30, 30, 255},
            .cornerRadius = {8, 8, 8, 8}
        }) {
            
            // Menu items
            const MenuItem menu_items[] = {
                {"Detect System", "Scan and detect boot configuration", 'd', NULL, true, false},
                {"Fix GRUB", "Repair GRUB bootloader", 'g', fix_grub, true, false},
                {"Fix rEFInd", "Repair rEFInd bootloader", 'r', NULL, true, false},
                {"Fix systemd-boot", "Repair systemd-boot", 's', NULL, true, false},
                {"Regenerate initramfs", "Rebuild initial RAM filesystem", 'i', regenerate_initramfs, true, false},
                {"Emergency Shell", "Drop to emergency shell", 'e', emergency_shell, true, true},
                {"System Info", "Show detailed system information", 'n', show_system_info, true, false},
                {"Update Packages", "Update system packages", 'u', update_system_packages, true, false},
                {"Quit", "Exit debork", 'q', NULL, true, false}
            };
            
            for (int i = 0; i < 9; i++) {
                Clay_Color bg_color = (i == tui->selected_menu_item) 
                    ? (Clay_Color){60, 60, 60, 255}
                    : (Clay_Color){30, 30, 30, 255};
                
                char item_id[32];
                snprintf(item_id, sizeof(item_id), "MenuItem%d", i);
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_ID(item_id),
                    .layoutConfig = {
                        .sizing = {
                            .width = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 1}},
                            .height = {.type = CLAY_SIZE_TYPE_FIXED, .value = {.fixed = 30}}
                        },
                        .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_CENTER},
                        .layoutDirection = CLAY_LAYOUT_DIRECTION_LEFT_TO_RIGHT,
                        .padding = {8, 8, 4, 4}
                    },
                    .backgroundColor = bg_color,
                    .cornerRadius = {4, 4, 4, 4}
                }) {
                    
                    // Selection indicator
                    if (i == tui->selected_menu_item) {
                        CLAY_TEXT(CLAY_STRING("> "),
                                 CLAY_TEXT_CONFIG(
                                     .textColor = {0, 255, 0, 255},
                                     .fontSize = 16,
                                     .fontId = 0
                                 ));
                    }
                    
                    // Shortcut
                    char shortcut_text[8];
                    snprintf(shortcut_text, sizeof(shortcut_text), "[%c] ", menu_items[i].shortcut);
                    CLAY_TEXT(CLAY_STRING(shortcut_text),
                             CLAY_TEXT_CONFIG(
                                 .textColor = {100, 200, 255, 255},
                                 .fontSize = 14,
                                 .fontId = 0
                             ));
                    
                    // Menu item label
                    CLAY_TEXT(CLAY_STRING(menu_items[i].label),
                             CLAY_TEXT_CONFIG(
                                 .textColor = {255, 255, 255, 255},
                                 .fontSize = 16,
                                 .fontId = 0
                             ));
                }
            }
        }
        
        // Help text at bottom
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("HelpBar"),
            .layoutConfig = {
                .sizing = {
                    .width = {.type = CLAY_SIZE_TYPE_PERCENT, .value = {.percent = 1}},
                    .height = {.type = CLAY_SIZE_TYPE_FIXED, .value = {.fixed = 20}}
                },
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            }
        }) {
            
            CLAY_TEXT(CLAY_STRING("Use arrows/j/k to navigate, Enter to select, q to quit"),
                     CLAY_TEXT_CONFIG(
                         .textColor = {150, 150, 150, 255},
                         .fontSize = 12,
                         .fontId = 0
                     ));
        }
    }
    
    // End layout and get render commands
    tui->render_commands = Clay_EndLayout();
    
    // Render to terminal
    render_clay_to_terminal(&tui->render_commands);
}

// Handle input
void handle_input(DeborkTUI *tui) {
    char c = get_char();
    
    switch (c) {
        case 'q':
        case 'Q':
            tui->running = false;
            break;
            
        case 'j':
        case 'J':
        case 'B':  // Arrow down
            tui->selected_menu_item++;
            if (tui->selected_menu_item >= tui->menu_item_count) {
                tui->selected_menu_item = 0;
            }
            tui->needs_redraw = true;
            break;
            
        case 'k':
        case 'K':
        case 'A':  // Arrow up
            tui->selected_menu_item--;
            if (tui->selected_menu_item < 0) {
                tui->selected_menu_item = tui->menu_item_count - 1;
            }
            tui->needs_redraw = true;
            break;
            
        case '\n':
        case '\r':
            // Execute selected menu item
            switch (tui->selected_menu_item) {
                case 0: // Detect System
                    strcpy(tui->status_message, "Detecting system configuration...");
                    tui->status_type = 0;
                    tui->needs_redraw = true;
                    detect_boot_loader(&tui->sys_info);
                    scan_kernels(&tui->sys_info);
                    strcpy(tui->status_message, "System detection complete");
                    tui->status_type = 1;
                    break;
                    
                case 1: // Fix GRUB
                    fix_grub();
                    break;
                    
                case 4: // Regenerate initramfs
                    regenerate_initramfs();
                    break;
                    
                case 5: // Emergency Shell
                    emergency_shell();
                    tui->needs_redraw = true;
                    break;
                    
                case 6: // System Info
                    show_system_info();
                    break;
                    
                case 7: // Update Packages
                    update_system_packages();
                    break;
                    
                case 8: // Quit
                    tui->running = false;
                    break;
            }
            break;
            
        case 'd':
        case 'D':
            detect_boot_loader(&tui->sys_info);
            strcpy(tui->status_message, "Boot loader detection complete");
            tui->status_type = 1;
            tui->needs_redraw = true;
            break;
    }
}

// Stub implementations for boot functions
bool file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

// Draw box helper
void draw_box(int x, int y, int width, int height, const char *title) {
    // Implementation would draw box borders using terminal characters
}

void detect_boot_loader(SystemInfo *info) {
    if (file_exists("/boot/grub/grub.cfg") || file_exists("/boot/grub2/grub.cfg")) {
        info->boot_loader = BOOT_LOADER_GRUB;
    } else if (file_exists("/boot/efi/EFI/refind/refind.conf")) {
        info->boot_loader = BOOT_LOADER_REFIND;
    } else if (file_exists("/boot/loader/loader.conf")) {
        info->boot_loader = BOOT_LOADER_SYSTEMD_BOOT;
    } else {
        info->boot_loader = BOOT_LOADER_UNKNOWN;
    }
}

void scan_kernels(SystemInfo *info) {
    // Stub: Would scan /boot for kernel images
    info->kernel_count = 0;
    info->kernels = NULL;
    
    // In real implementation, would:
    // 1. List files in /boot
    // 2. Find vmlinuz-* files
    // 3. Match with initrd/initramfs files
    // 4. Populate kernel list
}

bool mount_system(SystemInfo *info, const char *device) {
    // Stub: Would mount the root filesystem
    strcpy(info->mount_point, "/mnt");
    strcpy(info->root_device, device);
    info->is_mounted = true;
    return true;
}

void unmount_system(SystemInfo *info) {
    // Stub: Would unmount the filesystem
    info->is_mounted = false;
}

void emergency_shell(void) {
    printf(TERM_CLEAR);
    printf("Entering emergency shell...\n");
    printf("Type 'exit' to return to debork\n\n");
    
    // Restore terminal for shell
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_tui->orig_termios);
    printf(TERM_SHOW_CURSOR);
    
    system("/bin/bash");
    
    // Re-setup terminal for TUI
    struct termios raw = g_tui->orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    printf(TERM_HIDE_CURSOR);
}

void regenerate_initramfs(void) {
    // Stub: Would regenerate initramfs
    strcpy(g_tui->status_message, "Regenerating initramfs...");
    g_tui->status_type = 0;
}

void fix_grub(void) {
    // Stub: Would fix GRUB configuration
    strcpy(g_tui->status_message, "Fixing GRUB configuration...");
    g_tui->status_type = 0;
}

void show_system_info(void) {
    // Stub: Would show detailed system information
    printf(TERM_CLEAR);
    printf("System Information:\n");
    printf("Boot Loader: %s\n", 
           g_tui->sys_info.boot_loader == BOOT_LOADER_GRUB ? "GRUB" :
           g_tui->sys_info.boot_loader == BOOT_LOADER_REFIND ? "rEFInd" :
           g_tui->sys_info.boot_loader == BOOT_LOADER_SYSTEMD_BOOT ? "systemd-boot" :
           "Unknown");
    printf("\nPress any key to continue...");
    get_char();
}

void update_system_packages(void) {
    // Stub: Would update system packages
    strcpy(g_tui->status_message, "Updating system packages...");
    g_tui->status_type = 0;
}

char* select_partition(void) {
    // Stub: Would show partition selection dialog
    static char partition[64] = "/dev/sda1";
    return partition;
}

// Main TUI loop
void run_tui(DeborkTUI *tui) {
    tui->running = true;
    tui->needs_redraw = true;
    tui->selected_menu_item = 0;
    tui->menu_item_count = 9;
    
    // Initial status
    strcpy(tui->status_message, "Welcome to debork - Press 'd' to detect system");
    tui->status_type = 0;
    
    while (tui->running) {
        if (tui->needs_redraw) {
            render_ui(tui);
            tui->needs_redraw = false;
        }
        
        handle_input(tui);
        
        // Small delay to prevent CPU spinning
        usleep(10000); // 10ms
    }
}

// Main function
int main(int argc, char *argv[]) {
    // Check for help flag
    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        printf("debork - Cross-Platform Linux Boot Rescue Tool\n\n");
        printf("Usage: %s [options]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --help, -h     Show this help message\n");
        printf("  --debug, -d    Enable debug mode\n\n");
        printf("This tool provides a Clay-powered TUI interface for repairing broken Linux boot\n");
        printf("configurations. It supports GRUB, rEFInd, and systemd-boot.\n");
        return 0;
    }
    
    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This tool must be run as root\n");
        return 1;
    }
    
    // Initialize TUI
    DeborkTUI tui = {0};
    g_tui = &tui;
    
    init_tui(&tui);
    
    // Run the TUI
    run_tui(&tui);
    
    // Cleanup
    cleanup_tui(&tui);
    
    return 0;
}