#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <math.h>

// Clay configuration
#define CLAY_IMPLEMENTATION
#include "../../include/clay.h"

// ANSI escape codes for better terminal control
#define TERM_RESET      "\033[0m"
#define TERM_BOLD       "\033[1m"
#define TERM_DIM        "\033[2m"
#define TERM_ITALIC     "\033[3m"
#define TERM_UNDERLINE  "\033[4m"
#define TERM_BLINK      "\033[5m"
#define TERM_REVERSE    "\033[7m"
#define TERM_HIDDEN     "\033[8m"
#define TERM_STRIKETHROUGH "\033[9m"

// Cursor control
#define TERM_CLEAR      "\033[2J\033[H"
#define TERM_CLEAR_LINE "\033[2K"
#define TERM_HIDE_CURSOR "\033[?25l"
#define TERM_SHOW_CURSOR "\033[?25h"
#define TERM_SAVE_POS   "\033[s"
#define TERM_RESTORE_POS "\033[u"
#define TERM_ALT_BUFFER "\033[?1049h"
#define TERM_MAIN_BUFFER "\033[?1049l"

// Modern color palette with gradients
#define COLOR_BG        ((Clay_Color){18, 18, 24, 255})      // Deep dark blue-gray
#define COLOR_BG_ALT    ((Clay_Color){24, 24, 32, 255})      // Slightly lighter
#define COLOR_HEADER    ((Clay_Color){32, 35, 48, 255})      // Header background
#define COLOR_SELECTED  ((Clay_Color){88, 91, 112, 255})     // Selected item - purple-gray
#define COLOR_UNSELECTED ((Clay_Color){35, 38, 52, 255})     // Unselected item
#define COLOR_HOVER     ((Clay_Color){58, 61, 82, 255})      // Hover state
#define COLOR_SUCCESS   ((Clay_Color){115, 218, 202, 255})   // Success - mint green
#define COLOR_ERROR     ((Clay_Color){255, 117, 127, 255})   // Error - coral red
#define COLOR_WARNING   ((Clay_Color){255, 216, 102, 255})   // Warning - golden
#define COLOR_INFO      ((Clay_Color){147, 199, 255, 255})   // Info - sky blue
#define COLOR_TEXT      ((Clay_Color){205, 214, 244, 255})   // Main text
#define COLOR_TEXT_DIM  ((Clay_Color){139, 148, 178, 255})   // Dimmed text
#define COLOR_ACCENT    ((Clay_Color){189, 147, 249, 255})   // Accent purple

// Font IDs
#define FONT_ID_TITLE 0
#define FONT_ID_BODY 1
#define FONT_ID_MONO 2

// Menu item count
#define MENU_COUNT 6

// Frame timing
#define TARGET_FPS 60
#define FRAME_TIME_MS (1000 / TARGET_FPS)

// Terminal buffer for double buffering
typedef struct {
    char **current;
    char **previous;
    int width;
    int height;
    bool *dirty_lines;
} TerminalBuffer;

// Boot loader types
typedef enum {
    BOOTLOADER_UNKNOWN,
    BOOTLOADER_GRUB,
    BOOTLOADER_SYSTEMD_BOOT,
    BOOTLOADER_REFIND
} BootLoader;

// System information
typedef struct {
    char mount_point[256];
    char device[256];
    BootLoader boot_loader;
    bool is_mounted;
} SystemInfo;

// Menu item structure
typedef struct {
    const char *label;
    const char *icon;
    const char *description;
    void (*action)(void *context);
    bool dangerous;
    bool requires_mount;
} MenuItem;

// Main TUI structure
typedef struct {
    SystemInfo sys_info;
    int selected_menu_item;
    int previous_selected;
    bool running;
    char status_message[512];
    Clay_Color status_color;
    char log_file[256];
    Clay_Dimensions window_dimensions;
    Clay_Arena arena;
    uint8_t *arena_memory;
    size_t arena_size;
    int term_width;
    int term_height;
    TerminalBuffer buffer;
    struct timeval last_render_time;
    struct timeval last_input_time;
    float animation_progress;
    bool needs_redraw;
    int scroll_offset;
    bool show_help;
} DeborkTUI;

// Global TUI instance
static DeborkTUI g_tui = {0};

// Terminal buffer management
TerminalBuffer create_terminal_buffer(int width, int height) {
    TerminalBuffer buffer;
    buffer.width = width;
    buffer.height = height;
    
    buffer.current = calloc(height, sizeof(char*));
    buffer.previous = calloc(height, sizeof(char*));
    buffer.dirty_lines = calloc(height, sizeof(bool));
    
    for (int i = 0; i < height; i++) {
        buffer.current[i] = calloc(width + 1, sizeof(char));
        buffer.previous[i] = calloc(width + 1, sizeof(char));
        buffer.dirty_lines[i] = true; // Initially all lines are dirty
    }
    
    return buffer;
}

void free_terminal_buffer(TerminalBuffer *buffer) {
    for (int i = 0; i < buffer->height; i++) {
        free(buffer->current[i]);
        free(buffer->previous[i]);
    }
    free(buffer->current);
    free(buffer->previous);
    free(buffer->dirty_lines);
}

void swap_buffers(TerminalBuffer *buffer) {
    char **temp = buffer->current;
    buffer->current = buffer->previous;
    buffer->previous = temp;
    
    // Mark dirty lines
    for (int i = 0; i < buffer->height; i++) {
        buffer->dirty_lines[i] = strcmp(buffer->current[i], buffer->previous[i]) != 0;
    }
}

// Function declarations
void init_tui(DeborkTUI *tui);
void cleanup_tui(DeborkTUI *tui);
Clay_RenderCommandArray render_ui(DeborkTUI *tui);
void render_to_terminal_optimized(DeborkTUI *tui, Clay_RenderCommandArray commands);
void handle_input(DeborkTUI *tui);
char get_char(void);
bool file_exists(const char *path);
void detect_boot_loader(SystemInfo *info);
bool mount_system(const char *device, SystemInfo *info);
void unmount_system(SystemInfo *info);
void execute_menu_action(DeborkTUI *tui);
long get_time_ms(void);
int rgb_to_256color(int r, int g, int b);
void set_animation_progress(DeborkTUI *tui);

// Custom text measurement function for Clay
Clay_Dimensions measure_text(Clay_StringSlice text, Clay_TextElementConfig *config, void *user_data) {
    (void)user_data; // Unused parameter
    
    // Simple estimation for monospace terminal fonts
    float char_width = 10.0f;  // Pixels per character
    float char_height = 20.0f; // Pixels per line
    
    if (config && config->fontSize > 0) {
        char_height = config->fontSize * 1.2f;
        char_width = char_height * 0.5f;
    }
    
    return (Clay_Dimensions){
        .width = text.length * char_width,
        .height = char_height
    };
}

// Convert RGB to 256-color terminal palette
int rgb_to_256color(int r, int g, int b) {
    // Use the 216 color cube (16-231) for better color accuracy
    if (r == g && g == b) {
        // Grayscale ramp (232-255)
        if (r < 8) return 16;
        if (r > 248) return 231;
        return 232 + ((r - 8) / 10);
    }
    
    // Color cube
    return 16 + (36 * (r * 5 / 255)) + (6 * (g * 5 / 255)) + (b * 5 / 255);
}

// Get current time in milliseconds
long get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Calculate animation progress
void set_animation_progress(DeborkTUI *tui) {
    long current_time = get_time_ms();
    tui->animation_progress = (float)(current_time % 2000) / 2000.0f;
}

// Initialize TUI with optimizations
void init_tui(DeborkTUI *tui) {
    strcpy(tui->sys_info.mount_point, "/mnt/debork");
    strcpy(tui->log_file, "/tmp/debork.log");
    tui->selected_menu_item = 0;
    tui->previous_selected = -1;
    tui->running = true;
    tui->status_color = COLOR_INFO;
    tui->needs_redraw = true;
    tui->show_help = false;
    
    // Get terminal dimensions
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    tui->term_width = w.ws_col;
    tui->term_height = w.ws_row;
    
    // Initialize double buffer
    tui->buffer = create_terminal_buffer(w.ws_col, w.ws_row);
    
    // Pixel dimensions for Clay (optimized scaling)
    tui->window_dimensions.width = (float)(w.ws_col * 8);
    tui->window_dimensions.height = (float)(w.ws_row * 16);
    
    // Initialize Clay
    tui->arena_size = Clay_MinMemorySize();
    tui->arena_memory = (uint8_t*)malloc(tui->arena_size);
    tui->arena = Clay_CreateArenaWithCapacityAndMemory(tui->arena_size, tui->arena_memory);
    Clay_Initialize(tui->arena, tui->window_dimensions, (Clay_ErrorHandler){0});
    Clay_SetMeasureTextFunction(measure_text, NULL);
    
    // Initialize timing
    gettimeofday(&tui->last_render_time, NULL);
    gettimeofday(&tui->last_input_time, NULL);
    
    // Switch to alternate buffer for cleaner rendering
    printf(TERM_ALT_BUFFER);
    printf(TERM_HIDE_CURSOR);
    printf(TERM_CLEAR);
}

// Cleanup TUI
void cleanup_tui(DeborkTUI *tui) {
    free(tui->arena_memory);
    free_terminal_buffer(&tui->buffer);
    
    // Return to main buffer
    printf(TERM_MAIN_BUFFER);
    printf(TERM_SHOW_CURSOR);
    printf(TERM_RESET);
}

// Get single character input (non-blocking)
char get_char(void) {
    struct termios oldt, newt;
    char ch;
    
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    newt.c_cc[VMIN] = 0;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    int result = read(STDIN_FILENO, &ch, 1);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    return (result == 1) ? ch : 0;
}

// Render UI with Clay (optimized)
Clay_RenderCommandArray render_ui(DeborkTUI *tui) {
    Clay_SetLayoutDimensions(tui->window_dimensions);
    Clay_BeginLayout();
    
    set_animation_progress(tui);
    
    // Main container with gradient effect
    CLAY((Clay_ElementDeclaration) {
        .id = CLAY_ID("MainContainer"),
        .layout = {
            .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
            .padding = {12, 12, 12, 12},
            .childGap = 8,
            .layoutDirection = CLAY_TOP_TO_BOTTOM
        },
        .backgroundColor = COLOR_BG
    }) {
        // Animated header with glow effect
        float glow_intensity = (sinf(tui->animation_progress * 6.28f) + 1.0f) * 0.5f;
        Clay_Color header_color = COLOR_HEADER;
        header_color.r += (int)(20 * glow_intensity);
        header_color.g += (int)(20 * glow_intensity);
        header_color.b += (int)(30 * glow_intensity);
        
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Header"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(50)},
                .padding = {15, 15, 10, 10},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            },
            .backgroundColor = header_color,
            .cornerRadius = {8, 8, 8, 8}
        }) {
            // Gradient text effect
            Clay_Color title_color = COLOR_ACCENT;
            title_color.b = 200 + (int)(55 * glow_intensity);
            
            CLAY_TEXT(CLAY_STRING("⚡ debork Boot Rescue Tool ⚡"), 
                     CLAY_TEXT_CONFIG(.wrapped.textColor = title_color, 
                                     .wrapped.fontSize = 24, 
                                     .wrapped.fontId = FONT_ID_TITLE));
        }
        
        // Status message with smooth transitions
        if (strlen(tui->status_message) > 0) {
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("Status"),
                .layout = {
                    .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIT()},
                    .padding = {10, 10, 6, 6}
                },
                .backgroundColor = tui->status_color,
                .cornerRadius = {4, 4, 4, 4}
            }) {
                Clay_String status_str = {
                    .chars = tui->status_message,
                    .length = strlen(tui->status_message),
                    .isStaticallyAllocated = false
                };
                CLAY_TEXT(status_str,
                         CLAY_TEXT_CONFIG(.wrapped.textColor = COLOR_TEXT, 
                                        .wrapped.fontSize = 14, 
                                        .wrapped.fontId = FONT_ID_BODY));
            }
        }
        
        // Menu container with shadow effect
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("MenuContainer"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
                .padding = {8, 8, 8, 8},
                .childGap = 4,
                .layoutDirection = CLAY_TOP_TO_BOTTOM
            },
            .backgroundColor = COLOR_BG_ALT,
            .cornerRadius = {6, 6, 6, 6}
        }) {
            // Enhanced menu items
            const MenuItem menu_items[] = {
                {"Fix My System", "🔧", "Automatically detect and fix common boot issues", NULL, false, true},
                {"Emergency Shell", "💻", "Drop to a root shell for manual repairs", NULL, false, false},
                {"Regenerate Initramfs", "💾", "Rebuild initial ramdisk for current kernel", NULL, false, true},
                {"Fix Boot Configuration", "⚙️", "Repair bootloader configuration files", NULL, true, true},
                {"System Information", "📊", "Display detailed system and boot information", NULL, false, false},
                {"Exit", "🚪", "Exit debork and reboot system", NULL, false, false}
            };
            
            for (int i = 0; i < MENU_COUNT; i++) {
                // Smooth selection transition
                Clay_Color item_bg;
                Clay_Color text_color;
                if (i == tui->selected_menu_item) {
                    // Pulsing effect for selected item
                    float pulse = (sinf(tui->animation_progress * 8.0f) + 1.0f) * 0.5f;
                    item_bg = COLOR_SELECTED;
                    item_bg.r += (int)(15 * pulse);
                    item_bg.g += (int)(15 * pulse);
                    item_bg.b += (int)(20 * pulse);
                    text_color = COLOR_TEXT;
                } else {
                    item_bg = COLOR_UNSELECTED;
                    text_color = COLOR_TEXT_DIM;
                }
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_IDI("MenuItem", i),
                    .layout = {
                        .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(45)},
                        .padding = {20, 20, 10, 10},
                        .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_CENTER}
                    },
                    .backgroundColor = item_bg,
                    .cornerRadius = {4, 4, 4, 4}
                }) {
                    // Selection indicator with animation
                    if (i == tui->selected_menu_item) {
                        Clay_Color arrow_color = COLOR_SUCCESS;
                        arrow_color.a = 200 + (int)(55 * sinf(tui->animation_progress * 4.0f));
                        CLAY_TEXT(CLAY_STRING("▶ "),
                                 CLAY_TEXT_CONFIG(.wrapped.textColor = arrow_color, 
                                                .wrapped.fontSize = 16, 
                                                .wrapped.fontId = FONT_ID_BODY));
                    }
                    
                    // Icon
                    Clay_String icon_str = {
                        .chars = menu_items[i].icon,
                        .length = strlen(menu_items[i].icon),
                        .isStaticallyAllocated = false
                    };
                    CLAY_TEXT(icon_str,
                             CLAY_TEXT_CONFIG(.wrapped.textColor = text_color, 
                                            .wrapped.fontSize = 18, 
                                            .wrapped.fontId = FONT_ID_BODY));
                    
                    // Spacer
                    CLAY_TEXT(CLAY_STRING("  "),
                             CLAY_TEXT_CONFIG(.wrapped.textColor = text_color, 
                                            .wrapped.fontSize = 18, 
                                            .wrapped.fontId = FONT_ID_BODY));
                    
                    // Label
                    Clay_String label_str = {
                        .chars = menu_items[i].label,
                        .length = strlen(menu_items[i].label),
                        .isStaticallyAllocated = false
                    };
                    CLAY_TEXT(label_str,
                             CLAY_TEXT_CONFIG(.wrapped.textColor = text_color, 
                                            .wrapped.fontSize = 18, 
                                            .wrapped.fontId = FONT_ID_BODY));
                }
            }
        }
        
        // Help text with keyboard shortcuts
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Help"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIT()},
                .padding = {10, 10, 5, 5},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            },
            .backgroundColor = COLOR_BG_ALT,
            .cornerRadius = {4, 4, 4, 4}
        }) {
            const char *help_text = tui->show_help 
                ? "📌 ↑↓/jk: Navigate • Enter: Select • h: Hide help • q: Quit • F5: Refresh"
                : "📌 Press 'h' for help";
                
            Clay_String help_str = {
                .chars = help_text,
                .length = strlen(help_text),
                .isStaticallyAllocated = false
            };
            CLAY_TEXT(help_str,
                     CLAY_TEXT_CONFIG(.wrapped.textColor = COLOR_TEXT_DIM,
                                    .wrapped.fontSize = 12, 
                                    .wrapped.fontId = FONT_ID_MONO));
        }
    }
    
    return Clay_EndLayout();
}

// Optimized rendering to terminal with double buffering
void render_to_terminal_optimized(DeborkTUI *tui, Clay_RenderCommandArray commands) {
    // Clear current buffer
    for (int y = 0; y < tui->buffer.height; y++) {
        memset(tui->buffer.current[y], ' ', tui->buffer.width);
        tui->buffer.current[y][tui->buffer.width] = '\0';
    }
    
    // Render Clay commands to buffer
    for (int i = 0; i < commands.length; i++) {
        Clay_RenderCommand *cmd = &commands.internalArray[i];
        
        // Improved scaling factors
        int x = (int)(cmd->boundingBox.x / 8);
        int y = (int)(cmd->boundingBox.y / 16);
        int w = (int)(cmd->boundingBox.width / 8);
        int h = (int)(cmd->boundingBox.height / 16);
        
        // Clipping
        if (x >= tui->buffer.width || y >= tui->buffer.height) continue;
        if (x < 0) { w += x; x = 0; }
        if (y < 0) { h += y; y = 0; }
        if (x + w > tui->buffer.width) w = tui->buffer.width - x;
        if (y + h > tui->buffer.height) h = tui->buffer.height - y;
        
        switch (cmd->commandType) {
            case CLAY_RENDER_COMMAND_TYPE_RECTANGLE: {
                Clay_Color bg = cmd->renderData.rectangle.backgroundColor;
                if (bg.a == 0) continue; // Skip transparent
                
                // Draw to buffer instead of directly to terminal
                for (int row = 0; row < h && (y + row) < tui->buffer.height; row++) {
                    for (int col = 0; col < w && (x + col) < tui->buffer.width; col++) {
                        // Store colored space character (we'll apply colors during output)
                        tui->buffer.current[y + row][x + col] = ' ';
                    }
                }
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_TEXT: {
                // Buffer text content
                int text_len = cmd->renderData.text.stringContents.length;
                const char *text = cmd->renderData.text.stringContents.chars;
                
                if (y < tui->buffer.height && x < tui->buffer.width) {
                    int max_len = tui->buffer.width - x;
                    if (text_len > max_len) text_len = max_len;
                    
                    memcpy(&tui->buffer.current[y][x], text, text_len);
                }
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_BORDER: {
                // Enhanced border drawing with proper box characters
                if (w > 1 && h > 1) {
                    // Top border
                    if (y < tui->buffer.height) {
                        tui->buffer.current[y][x] = '+';
                        for (int i = 1; i < w - 1 && (x + i) < tui->buffer.width; i++) {
                            tui->buffer.current[y][x + i] = '-';
                        }
                        if ((x + w - 1) < tui->buffer.width) {
                            tui->buffer.current[y][x + w - 1] = '+';
                        }
                    }
                    
                    // Side borders
                    for (int row = 1; row < h - 1 && (y + row) < tui->buffer.height; row++) {
                        tui->buffer.current[y + row][x] = '|';
                        if ((x + w - 1) < tui->buffer.width) {
                            tui->buffer.current[y + row][x + w - 1] = '|';
                        }
                    }
                    
                    // Bottom border
                    if ((y + h - 1) < tui->buffer.height) {
                        tui->buffer.current[y + h - 1][x] = '+';
                        for (int i = 1; i < w - 1 && (x + i) < tui->buffer.width; i++) {
                            tui->buffer.current[y + h - 1][x + i] = '-';
                        }
                        if ((x + w - 1) < tui->buffer.width) {
                            tui->buffer.current[y + h - 1][x + w - 1] = '+';
                        }
                    }
                }
                break;
            }
            
            default:
                break;
        }
    }
    
    // Swap buffers and detect changes
    swap_buffers(&tui->buffer);
    
    // Only update changed lines (differential rendering)
    for (int y = 0; y < tui->buffer.height; y++) {
        if (tui->buffer.dirty_lines[y] || tui->needs_redraw) {
            printf("\033[%d;1H", y + 1);  // Position cursor
            printf(TERM_CLEAR_LINE);       // Clear line first
            
            // Apply colors and output the line
            // For simplicity, using a basic color scheme here
            // In production, you'd track colors per character
            printf("\033[38;5;%dm", rgb_to_256color(205, 214, 244));  // Text color
            printf("\033[48;5;%dm", rgb_to_256color(18, 18, 24));     // Background
            
            printf("%s", tui->buffer.current[y]);
            printf(TERM_RESET);
        }
    }
    
    tui->needs_redraw = false;
    fflush(stdout);
}

// Handle input with debouncing
void handle_input(DeborkTUI *tui) {
    char ch = get_char();
    if (ch == 0) return;
    
    // Simple debouncing
    struct timeval now;
    gettimeofday(&now, NULL);
    long time_diff = (now.tv_sec - tui->last_input_time.tv_sec) * 1000 + 
                     (now.tv_usec - tui->last_input_time.tv_usec) / 1000;
    
    if (time_diff < 50) return; // 50ms debounce
    tui->last_input_time = now;
    
    int old_selection = tui->selected_menu_item;
    
    switch (ch) {
        case 'q':
        case 'Q':
            tui->running = false;
            break;
            
        case 'k':
        case 'K':
        case '\033': // Escape sequence
            if (ch == '\033') {
                char seq[2];
                if (read(STDIN_FILENO, &seq[0], 1) == 1 && 
                    read(STDIN_FILENO, &seq[1], 1) == 1) {
                    if (seq[0] == '[') {
                        if (seq[1] == 'A') { // Up arrow
                            tui->selected_menu_item = (tui->selected_menu_item > 0) ? 
                                tui->selected_menu_item - 1 : MENU_COUNT - 1;
                        } else if (seq[1] == 'B') { // Down arrow
                            tui->selected_menu_item = (tui->selected_menu_item < MENU_COUNT - 1) ? 
                                tui->selected_menu_item + 1 : 0;
                        }
                    }
                }
            } else { // 'k' key
                tui->selected_menu_item = (tui->selected_menu_item > 0) ? 
                    tui->selected_menu_item - 1 : MENU_COUNT - 1;
            }
            break;
            
        case 'j':
        case 'J':
            tui->selected_menu_item = (tui->selected_menu_item < MENU_COUNT - 1) ? 
                tui->selected_menu_item + 1 : 0;
            break;
            
        case '\n':
        case '\r':
            execute_menu_action(tui);
            tui->needs_redraw = true;
            break;
            
        case 'h':
        case 'H':
            tui->show_help = !tui->show_help;
            tui->needs_redraw = true;
            break;
            
        case '\014': // Ctrl+L
        case '\022': // Ctrl+R
            printf(TERM_CLEAR);
            tui->needs_redraw = true;
            break;
    }
    
    // Only redraw if selection changed
    if (old_selection != tui->selected_menu_item) {
        tui->needs_redraw = true;
    }
}

// File existence check
bool file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

// Detect boot loader
void detect_boot_loader(SystemInfo *info) {
    if (file_exists("/boot/grub/grub.cfg") || file_exists("/boot/grub2/grub.cfg")) {
        info->boot_loader = BOOTLOADER_GRUB;
    } else if (file_exists("/boot/loader/loader.conf")) {
        info->boot_loader = BOOTLOADER_SYSTEMD_BOOT;
    } else if (file_exists("/boot/refind_linux.conf")) {
        info->boot_loader = BOOTLOADER_REFIND;
    } else {
        info->boot_loader = BOOTLOADER_UNKNOWN;
    }
}

// Mount system partition
bool mount_system(const char *device, SystemInfo *info) {
    // Create mount point if it doesn't exist
    struct stat st = {0};
    if (stat(info->mount_point, &st) == -1) {
        mkdir(info->mount_point, 0755);
    }
    
    // Attempt to mount the device
    if (mount(device, info->mount_point, "auto", 0, NULL) == 0) {
        strcpy(info->device, device);
        info->is_mounted = true;
        return true;
    }
    
    info->is_mounted = false;
    return false;
}

// Unmount system partition
void unmount_system(SystemInfo *info) {
    if (info->is_mounted) {
        umount(info->mount_point);
        info->is_mounted = false;
    }
}

// Execute menu action
void execute_menu_action(DeborkTUI *tui) {
    switch (tui->selected_menu_item) {
        case 0: // Fix My System
            strcpy(tui->status_message, "🔧 Analyzing system for issues...");
            tui->status_color = COLOR_INFO;
            tui->needs_redraw = true;
            // TODO: Implement system fix logic
            break;
            
        case 1: // Emergency Shell
            cleanup_tui(tui);
            printf("\n🚀 Dropping to emergency shell...\n");
            printf("Type 'exit' to return to debork\n\n");
            system("/bin/bash");
            init_tui(tui);
            tui->needs_redraw = true;
            break;
            
        case 2: // Regenerate Initramfs
            strcpy(tui->status_message, "💾 Regenerating initramfs...");
            tui->status_color = COLOR_WARNING;
            tui->needs_redraw = true;
            // TODO: Implement initramfs regeneration
            break;
            
        case 3: // Fix Boot Configuration
            strcpy(tui->status_message, "⚙️ Fixing boot configuration...");
            tui->status_color = COLOR_WARNING;
            tui->needs_redraw = true;
            // TODO: Implement boot config fix
            break;
            
        case 4: // System Information
            strcpy(tui->status_message, "📊 System Information");
            tui->status_color = COLOR_INFO;
            tui->needs_redraw = true;
            // TODO: Display system info
            break;
            
        case 5: // Exit
            tui->running = false;
            break;
    }
}

// Select partition (simplified version)
char* select_partition(void) {
    static char partition[256];
    printf(TERM_CLEAR);
    printf("🔍 Available partitions:\n\n");
    
    // List block devices
    system("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E 'part|disk'");
    
    printf("\n💾 Enter device path (e.g., /dev/sda1) or press Enter for demo mode: ");
    
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        if (strlen(input) > 0) {
            strcpy(partition, input);
            return partition;
        }
    }
    
    return NULL;
}

// Main TUI loop
void run_tui(bool demo_mode) {
    init_tui(&g_tui);
    
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
        strcpy(g_tui.status_message, "✨ Demo Mode - Testing Optimized UI");
        g_tui.status_color = COLOR_SUCCESS;
    }
    
    // Main render loop with frame rate limiting
    long last_frame_time = get_time_ms();
    
    while (g_tui.running) {
        long current_time = get_time_ms();
        long elapsed = current_time - last_frame_time;
        
        // Only render if enough time has passed or redraw is needed
        if (elapsed >= FRAME_TIME_MS || g_tui.needs_redraw) {
            Clay_RenderCommandArray render_commands = render_ui(&g_tui);
            render_to_terminal_optimized(&g_tui, render_commands);
            last_frame_time = current_time;
        }
        
        // Handle input (non-blocking)
        handle_input(&g_tui);
        
        // Small sleep to prevent CPU spinning
        usleep(1000); // 1ms
    }
    
    // Cleanup
    unmount_system(&g_tui.sys_info);
    cleanup_tui(&g_tui);
}

// Main entry point
int main(int argc, char *argv[]) {
    // Check if running as root
    if (geteuid() != 0 && argc < 2) {
        printf("⚠️  Warning: debork should be run as root for full functionality\n");
        printf("   Running in demo mode. Use 'sudo %s' for actual system rescue.\n\n", argv[0]);
        printf("Press Enter to continue in demo mode...");
        getchar();
    }
    
    // Check for demo flag
    bool demo_mode = false;
    if (argc > 1 && (strcmp(argv[1], "--demo") == 0 || strcmp(argv[1], "-d") == 0)) {
        demo_mode = true;
    }
    
    // Print banner
    printf("\n");
    printf("╔════════════════════════════════════════════╗\n");
    printf("║      ⚡ debork Boot Rescue Tool ⚡         ║\n");
    printf("║         Optimized Clay UI Version          ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    printf("\n");
    
    if (demo_mode) {
        printf("🎮 Running in DEMO mode - no system changes will be made\n\n");
    } else {
        printf("🚀 Starting rescue environment...\n\n");
    }
    
    sleep(1);
    
    // Run the TUI
    run_tui(demo_mode);
    
    printf("\n👋 Thank you for using debork!\n");
    printf("   System will reboot in 5 seconds...\n");
    
    if (!demo_mode) {
        sleep(5);
        system("reboot");
    }
    
    return 0;
}