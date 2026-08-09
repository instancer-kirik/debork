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
#include <math.h>
#include <signal.h>
#include <locale.h>

// Clay configuration
#define CLAY_IMPLEMENTATION
#include "../../include/clay.h"

// ============================================================================
// Modern Terminal Control & Colors
// ============================================================================

#define ESC "\033"
#define CSI "\033["

// Terminal control
#define CLEAR_SCREEN        CSI "2J" CSI "H"
#define CLEAR_TO_END        CSI "J"
#define CLEAR_LINE          CSI "2K"
#define HIDE_CURSOR         CSI "?25l"
#define SHOW_CURSOR         CSI "?25h"
#define SAVE_CURSOR         CSI "s"
#define RESTORE_CURSOR      CSI "u"
#define ALTERNATE_SCREEN    CSI "?1049h"
#define NORMAL_SCREEN       CSI "?1049l"
#define ENABLE_MOUSE        CSI "?1000h"
#define DISABLE_MOUSE       CSI "?1000l"
#define RESET_ALL           CSI "0m"

// Cursor movement
#define MOVE_TO(x,y)        CSI "%d;%dH", (y), (x)
#define MOVE_UP(n)          CSI "%dA", (n)
#define MOVE_DOWN(n)        CSI "%dB", (n)
#define MOVE_RIGHT(n)       CSI "%dC", (n)
#define MOVE_LEFT(n)        CSI "%dD", (n)

// Text attributes
#define BOLD                CSI "1m"
#define DIM                 CSI "2m"
#define ITALIC              CSI "3m"
#define UNDERLINE           CSI "4m"
#define BLINK               CSI "5m"
#define REVERSE             CSI "7m"
#define STRIKETHROUGH       CSI "9m"

// RGB colors (24-bit true color)
#define RGB_FG(r,g,b)       CSI "38;2;%d;%d;%dm", (int)(r), (int)(g), (int)(b)
#define RGB_BG(r,g,b)       CSI "48;2;%d;%d;%dm", (int)(r), (int)(g), (int)(b)

// ============================================================================
// Beautiful Color Palette - Catppuccin Mocha inspired
// ============================================================================

// Base colors
#define COLOR_BASE          ((Clay_Color){30, 30, 46, 255})      // Deep background
#define COLOR_MANTLE        ((Clay_Color){24, 24, 37, 255})      // Darker background
#define COLOR_CRUST         ((Clay_Color){17, 17, 27, 255})      // Darkest background
#define COLOR_SURFACE0      ((Clay_Color){49, 50, 68, 255})      // Surface
#define COLOR_SURFACE1      ((Clay_Color){69, 71, 90, 255})      // Surface alt
#define COLOR_SURFACE2      ((Clay_Color){88, 91, 112, 255})     // Surface highlight

// Text colors
#define COLOR_TEXT          ((Clay_Color){205, 214, 244, 255})   // Main text
#define COLOR_SUBTEXT1      ((Clay_Color){186, 194, 222, 255})   // Subtext 1
#define COLOR_SUBTEXT0      ((Clay_Color){166, 173, 200, 255})   // Subtext 0
#define COLOR_OVERLAY2      ((Clay_Color){147, 153, 178, 255})   // Overlay 2
#define COLOR_OVERLAY1      ((Clay_Color){127, 132, 156, 255})   // Overlay 1
#define COLOR_OVERLAY0      ((Clay_Color){108, 112, 134, 255})   // Overlay 0

// Accent colors
#define COLOR_BLUE          ((Clay_Color){137, 180, 250, 255})   // Blue
#define COLOR_LAVENDER      ((Clay_Color){180, 190, 254, 255})   // Lavender
#define COLOR_SAPPHIRE      ((Clay_Color){116, 199, 236, 255})   // Sapphire
#define COLOR_SKY           ((Clay_Color){137, 220, 235, 255})   // Sky
#define COLOR_TEAL          ((Clay_Color){148, 226, 213, 255})   // Teal
#define COLOR_GREEN         ((Clay_Color){166, 227, 161, 255})   // Green
#define COLOR_YELLOW        ((Clay_Color){249, 226, 175, 255})   // Yellow
#define COLOR_PEACH         ((Clay_Color){250, 179, 135, 255})   // Peach
#define COLOR_MAROON        ((Clay_Color){235, 160, 172, 255})   // Maroon
#define COLOR_RED           ((Clay_Color){243, 139, 168, 255})   // Red
#define COLOR_MAUVE         ((Clay_Color){203, 166, 247, 255})   // Mauve
#define COLOR_PINK          ((Clay_Color){245, 194, 231, 255})   // Pink
#define COLOR_FLAMINGO      ((Clay_Color){242, 205, 205, 255})   // Flamingo
#define COLOR_ROSEWATER     ((Clay_Color){245, 224, 220, 255})   // Rosewater

// ============================================================================
// Data Structures
// ============================================================================

typedef enum {
    MENU_FIX_SYSTEM,
    MENU_EMERGENCY_SHELL,
    MENU_REGENERATE_INITRAMFS,
    MENU_FIX_BOOT_CONFIG,
    MENU_SYSTEM_INFO,
    MENU_ADVANCED_OPTIONS,
    MENU_EXIT,
    MENU_COUNT
} MenuOption;

typedef struct {
    const char *label;
    const char *icon;
    const char *description;
    Clay_Color icon_color;
    bool dangerous;
    bool requires_root;
} MenuItem;

typedef struct {
    // UI State
    int selected_item;
    bool running;
    bool needs_redraw;
    bool show_description;
    bool show_particles;
    
    // Animation
    float time;
    float select_animation[MENU_COUNT];
    float hover_animation[MENU_COUNT];
    float global_pulse;
    
    // Terminal
    int term_width;
    int term_height;
    struct termios original_termios;
    
    // Status
    char status_message[256];
    Clay_Color status_color;
    float status_opacity;
    
    // Clay
    Clay_Dimensions window_dimensions;
    Clay_Arena arena;
    uint8_t *arena_memory;
    size_t arena_size;
    
    // Performance
    struct timeval last_frame;
    int frame_count;
    float fps;
} DeborkUI;

// ============================================================================
// Global State
// ============================================================================

static DeborkUI g_ui = {0};
static volatile bool g_resize_pending = false;

// Menu items with beautiful design
static const MenuItem g_menu_items[MENU_COUNT] = {
    {
        .label = "Fix My System",
        .icon = "🔧",
        .description = "Automatically detect and repair common boot issues",
        .icon_color = COLOR_GREEN,
        .dangerous = false,
        .requires_root = true
    },
    {
        .label = "Emergency Shell",
        .icon = "💻",
        .description = "Drop to a root shell for manual repairs",
        .icon_color = COLOR_BLUE,
        .dangerous = false,
        .requires_root = true
    },
    {
        .label = "Regenerate Initramfs",
        .icon = "💾",
        .description = "Rebuild initial RAM disk for all kernels",
        .icon_color = COLOR_YELLOW,
        .dangerous = false,
        .requires_root = true
    },
    {
        .label = "Fix Boot Configuration",
        .icon = "⚙️",
        .description = "Repair GRUB/systemd-boot configuration",
        .icon_color = COLOR_PEACH,
        .dangerous = true,
        .requires_root = true
    },
    {
        .label = "System Information",
        .icon = "📊",
        .description = "Display detailed system and boot information",
        .icon_color = COLOR_LAVENDER,
        .dangerous = false,
        .requires_root = false
    },
    {
        .label = "Advanced Options",
        .icon = "🚀",
        .description = "Expert tools and recovery options",
        .icon_color = COLOR_MAUVE,
        .dangerous = true,
        .requires_root = true
    },
    {
        .label = "Exit",
        .icon = "🚪",
        .description = "Exit debork and restart system",
        .icon_color = COLOR_RED,
        .dangerous = false,
        .requires_root = false
    }
};

// ============================================================================
// Terminal Management
// ============================================================================

void enable_raw_mode(void) {
    tcgetattr(STDIN_FILENO, &g_ui.original_termios);
    struct termios raw = g_ui.original_termios;
    
    // Input modes
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    // Output modes
    raw.c_oflag &= ~(OPOST);
    // Control modes
    raw.c_cflag |= (CS8);
    // Local modes
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    // Control characters
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void disable_raw_mode(void) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_ui.original_termios);
}

void handle_resize(int sig) {
    (void)sig;
    g_resize_pending = true;
}

void update_terminal_size(void) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    g_ui.term_width = w.ws_col;
    g_ui.term_height = w.ws_row;
    g_ui.window_dimensions.width = (float)(w.ws_col * 10);
    g_ui.window_dimensions.height = (float)(w.ws_row * 20);
    g_ui.needs_redraw = true;
}

// ============================================================================
// Animation & Timing
// ============================================================================

float ease_out_cubic(float t) {
    return 1.0f - powf(1.0f - t, 3.0f);
}

float ease_in_out_quad(float t) {
    return t < 0.5f ? 2.0f * t * t : 1.0f - powf(-2.0f * t + 2.0f, 2.0f) / 2.0f;
}

void update_animations(float dt) {
    g_ui.time += dt;
    g_ui.global_pulse = (sinf(g_ui.time * 2.0f) + 1.0f) * 0.5f;
    
    // Update selection animations
    for (int i = 0; i < MENU_COUNT; i++) {
        float target = (i == g_ui.selected_item) ? 1.0f : 0.0f;
        float diff = target - g_ui.select_animation[i];
        g_ui.select_animation[i] += diff * dt * 12.0f; // Smooth animation
        
        // Hover effect (proximity based)
        int distance = abs(i - g_ui.selected_item);
        float hover_target = (distance == 0) ? 1.0f : (distance == 1) ? 0.3f : 0.0f;
        float hover_diff = hover_target - g_ui.hover_animation[i];
        g_ui.hover_animation[i] += hover_diff * dt * 8.0f;
    }
    
    // Update status opacity
    if (g_ui.status_opacity > 0.0f) {
        g_ui.status_opacity -= dt * 0.5f;
        if (g_ui.status_opacity < 0.0f) g_ui.status_opacity = 0.0f;
    }
}

float get_delta_time(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    float dt = (now.tv_sec - g_ui.last_frame.tv_sec) + 
               (now.tv_usec - g_ui.last_frame.tv_usec) / 1000000.0f;
    
    g_ui.last_frame = now;
    
    // Calculate FPS
    g_ui.frame_count++;
    if (g_ui.frame_count % 30 == 0) {
        g_ui.fps = 1.0f / dt;
    }
    
    return dt;
}

// ============================================================================
// Clay Text Measurement
// ============================================================================

Clay_Dimensions measure_text(Clay_StringSlice text, Clay_TextElementConfig *config, void *user_data) {
    (void)user_data;
    
    float font_size = config ? config->fontSize : 16.0f;
    float char_width = font_size * 0.6f;
    float line_height = font_size * 1.4f;
    
    return (Clay_Dimensions){
        .width = text.length * char_width,
        .height = line_height
    };
}

// ============================================================================
// Beautiful UI Rendering
// ============================================================================

Clay_RenderCommandArray render_ui(void) {
    Clay_SetLayoutDimensions(g_ui.window_dimensions);
    Clay_BeginLayout();
    
    // Main gradient background
    CLAY((Clay_ElementDeclaration) {
        .id = CLAY_ID("Background"),
        .layout = {
            .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
            .padding = {0, 0, 0, 0}
        },
        .backgroundColor = COLOR_CRUST
    }) {
        // Content container with padding
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Container"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
                .padding = {20, 20, 15, 15},
                .childGap = 15,
                .layoutDirection = CLAY_TOP_TO_BOTTOM
            }
            // No background color - let children handle their own backgrounds
        }) {
            // Animated header
            float header_glow = g_ui.global_pulse * 0.3f;
            Clay_Color header_bg = COLOR_MANTLE;
            header_bg.r = (uint8_t)fminf(255, header_bg.r + header_glow * 20);
            header_bg.g = (uint8_t)fminf(255, header_bg.g + header_glow * 20);
            header_bg.b = (uint8_t)fminf(255, header_bg.b + header_glow * 30);
            
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("Header"),
                .layout = {
                    .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(70)},
                    .padding = {20, 20, 15, 15},
                    .childGap = 5,
                    .layoutDirection = CLAY_TOP_TO_BOTTOM,
                    .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
                },
                .backgroundColor = header_bg,
                .cornerRadius = {10, 10, 10, 10}
            }) {
                // Title with gradient effect
                Clay_Color title_color = COLOR_LAVENDER;
                title_color.r = (uint8_t)fminf(255, title_color.r + g_ui.global_pulse * 30);
                
                CLAY_TEXT(CLAY_STRING("⚡ DEBORK BOOT RESCUE ⚡"), 
                         CLAY_TEXT_CONFIG(
                             .wrapped.textColor = title_color,
                             .wrapped.fontSize = 28,
                             .wrapped.fontId = 0
                         ));
                
                CLAY_TEXT(CLAY_STRING("Advanced System Recovery Tool"), 
                         CLAY_TEXT_CONFIG(
                             .wrapped.textColor = COLOR_SUBTEXT0,
                             .wrapped.fontSize = 14,
                             .wrapped.fontId = 1
                         ));
            }
            
            // Status message (if present)
            if (g_ui.status_opacity > 0.01f) {
                Clay_Color status_bg = g_ui.status_color;
                status_bg.a = (uint8_t)(255 * g_ui.status_opacity);
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_ID("Status"),
                    .layout = {
                        .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIT()},
                        .padding = {15, 15, 10, 10}
                    },
                    .backgroundColor = status_bg,
                    .cornerRadius = {6, 6, 6, 6}
                }) {
                    Clay_String status_str = {
                        .chars = g_ui.status_message,
                        .length = strlen(g_ui.status_message),
                        .isStaticallyAllocated = false
                    };
                    
                    Clay_Color text_color = COLOR_TEXT;
                    text_color.a = (uint8_t)(255 * g_ui.status_opacity);
                    
                    CLAY_TEXT(status_str,
                             CLAY_TEXT_CONFIG(
                                 .wrapped.textColor = text_color,
                                 .wrapped.fontSize = 16,
                                 .wrapped.fontId = 0
                             ));
                }
            }
            
            // Main content area with menu
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("Content"),
                .layout = {
                    .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
                    .padding = {10, 10, 10, 10},
                    .childGap = 8,
                    .layoutDirection = CLAY_LEFT_TO_RIGHT
                },
                .backgroundColor = COLOR_BASE,
                .cornerRadius = {8, 8, 8, 8}
            }) {
                // Menu items column
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_ID("MenuColumn"),
                    .layout = {
                        .sizing = {CLAY_SIZING_PERCENT(0.6f), CLAY_SIZING_GROW()},
                        .padding = {5, 5, 5, 5},
                        .childGap = 6,
                        .layoutDirection = CLAY_TOP_TO_BOTTOM
                    }
                    // No background - items will have their own
                }) {
                    for (int i = 0; i < MENU_COUNT; i++) {
                        const MenuItem *item = &g_menu_items[i];
                        float selection = g_ui.select_animation[i];
                        float hover = g_ui.hover_animation[i];
                        
                        // Dynamic background color
                        Clay_Color bg = COLOR_SURFACE0;
                        if (selection > 0.01f) {
                            // Blend to selected color
                            Clay_Color selected_bg = COLOR_SURFACE2;
                            bg.r = bg.r + (uint8_t)((selected_bg.r - bg.r) * selection);
                            bg.g = bg.g + (uint8_t)((selected_bg.g - bg.g) * selection);
                            bg.b = bg.b + (uint8_t)((selected_bg.b - bg.b) * selection);
                        }
                        if (hover > 0.01f && selection < 0.99f) {
                            // Add hover effect
                            bg.r = (uint8_t)fminf(255, bg.r + hover * 15);
                            bg.g = (uint8_t)fminf(255, bg.g + hover * 15);
                            bg.b = (uint8_t)fminf(255, bg.b + hover * 20);
                        }
                        
                        // Add pulse for selected item
                        if (i == g_ui.selected_item) {
                            float pulse = g_ui.global_pulse * 0.15f;
                            bg.r = (uint8_t)fminf(255, bg.r + pulse * 20);
                            bg.g = (uint8_t)fminf(255, bg.g + pulse * 25);
                            bg.b = (uint8_t)fminf(255, bg.b + pulse * 30);
                        }
                        
                        CLAY((Clay_ElementDeclaration) {
                            .id = CLAY_IDI("MenuItem", i),
                            .layout = {
                                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(50)},
                                .padding = {15, 15, 12, 12},
                                .childGap = 10,
                                .layoutDirection = CLAY_LEFT_TO_RIGHT,
                                .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_CENTER}
                            },
                            .backgroundColor = bg,
                            .cornerRadius = {6, 6, 6, 6}
                        }) {
                            // Selection indicator
                            if (i == g_ui.selected_item) {
                                Clay_Color arrow_color = COLOR_GREEN;
                                arrow_color.a = (uint8_t)(200 + 55 * g_ui.global_pulse);
                                
                                CLAY_TEXT(CLAY_STRING("▶ "),
                                         CLAY_TEXT_CONFIG(
                                             .wrapped.textColor = arrow_color,
                                             .wrapped.fontSize = 18,
                                             .wrapped.fontId = 0
                                         ));
                            }
                            
                            // Icon with color
                            Clay_String icon_str = {
                                .chars = item->icon,
                                .length = strlen(item->icon),
                                .isStaticallyAllocated = false
                            };
                            
                            Clay_Color icon_color = item->icon_color;
                            if (selection > 0.01f) {
                                // Brighten icon when selected
                                icon_color.r = (uint8_t)fminf(255, icon_color.r + selection * 30);
                                icon_color.g = (uint8_t)fminf(255, icon_color.g + selection * 30);
                                icon_color.b = (uint8_t)fminf(255, icon_color.b + selection * 30);
                            }
                            
                            CLAY_TEXT(icon_str,
                                     CLAY_TEXT_CONFIG(
                                         .wrapped.textColor = icon_color,
                                         .wrapped.fontSize = 22,
                                         .wrapped.fontId = 0
                                     ));
                            
                            // Label
                            Clay_String label_str = {
                                .chars = item->label,
                                .length = strlen(item->label),
                                .isStaticallyAllocated = false
                            };
                            
                            Clay_Color text_color = selection > 0.5f ? COLOR_TEXT : COLOR_SUBTEXT1;
                            
                            CLAY_TEXT(label_str,
                                     CLAY_TEXT_CONFIG(
                                         .wrapped.textColor = text_color,
                                         .wrapped.fontSize = 18,
                                         .wrapped.fontId = 0
                                     ));
                            
                            // Danger indicator
                            if (item->dangerous) {
                                CLAY_TEXT(CLAY_STRING(" ⚠"),
                                         CLAY_TEXT_CONFIG(
                                             .wrapped.textColor = COLOR_YELLOW,
                                             .wrapped.fontSize = 16,
                                             .wrapped.fontId = 0
                                         ));
                            }
                        }
                    }
                }
                
                // Description panel
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_ID("DescriptionPanel"),
                    .layout = {
                        .sizing = {CLAY_SIZING_PERCENT(0.4f), CLAY_SIZING_GROW()},
                        .padding = {15, 15, 15, 15},
                        .childGap = 10,
                        .layoutDirection = CLAY_TOP_TO_BOTTOM
                    },
                    .backgroundColor = COLOR_MANTLE,
                    .cornerRadius = {6, 6, 6, 6}
                }) {
                    // Description title
                    CLAY_TEXT(CLAY_STRING("ℹ️ Information"),
                             CLAY_TEXT_CONFIG(
                                 .wrapped.textColor = COLOR_LAVENDER,
                                 .wrapped.fontSize = 18,
                                 .wrapped.fontId = 0
                             ));
                    
                    // Separator
                    CLAY((Clay_ElementDeclaration) {
                        .id = CLAY_ID("Separator"),
                        .layout = {
                            .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(2)}
                        },
                        .backgroundColor = COLOR_SURFACE1
                    }) {}
                    
                    // Current item description
                    const MenuItem *current = &g_menu_items[g_ui.selected_item];
                    Clay_String desc_str = {
                        .chars = current->description,
                        .length = strlen(current->description),
                        .isStaticallyAllocated = false
                    };
                    
                    CLAY_TEXT(desc_str,
                             CLAY_TEXT_CONFIG(
                                 .wrapped.textColor = COLOR_SUBTEXT0,
                                 .wrapped.fontSize = 14,
                                 .wrapped.fontId = 1
                             ));
                    
                    // Requirements
                    if (current->requires_root) {
                        CLAY_TEXT(CLAY_STRING("\n🔒 Requires root privileges"),
                                 CLAY_TEXT_CONFIG(
                                     .wrapped.textColor = COLOR_YELLOW,
                                     .wrapped.fontSize = 12,
                                     .wrapped.fontId = 1
                                 ));
                    }
                    
                    if (current->dangerous) {
                        CLAY_TEXT(CLAY_STRING("\n⚠️ This operation may modify system files"),
                                 CLAY_TEXT_CONFIG(
                                     .wrapped.textColor = COLOR_PEACH,
                                     .wrapped.fontSize = 12,
                                     .wrapped.fontId = 1
                                 ));
                    }
                }
            }
            
            // Footer with help
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("Footer"),
                .layout = {
                    .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(30)},
                    .padding = {10, 10, 5, 5},
                    .childGap = 15,
                    .layoutDirection = CLAY_LEFT_TO_RIGHT,
                    .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
                },
                .backgroundColor = COLOR_MANTLE,
                .cornerRadius = {6, 6, 6, 6}
            }) {
                CLAY_TEXT(CLAY_STRING("↑↓/jk Navigate"),
                         CLAY_TEXT_CONFIG(
                             .wrapped.textColor = COLOR_OVERLAY1,
                             .wrapped.fontSize = 12,
                             .wrapped.fontId = 1
                         ));
                
                CLAY_TEXT(CLAY_STRING("• Enter Select"),
                         CLAY_TEXT_CONFIG(
                             .wrapped.textColor = COLOR_OVERLAY1,
                             .wrapped.fontSize = 12,
                             .wrapped.fontId = 1
                         ));
                
                CLAY_TEXT(CLAY_STRING("• q Quit"),
                         CLAY_TEXT_CONFIG(
                             .wrapped.textColor = COLOR_OVERLAY1,
                             .wrapped.fontSize = 12,
                             .wrapped.fontId = 1
                         ));
                
                // FPS counter (debug)
                char fps_str[32];
                snprintf(fps_str, sizeof(fps_str), "• %.0f FPS", g_ui.fps);
                Clay_String fps_clay_str = {
                    .chars = fps_str,
                    .length = strlen(fps_str),
                    .isStaticallyAllocated = false
                };
                
                CLAY_TEXT(fps_clay_str,
                         CLAY_TEXT_CONFIG(
                             .wrapped.textColor = COLOR_OVERLAY0,
                             .wrapped.fontSize = 12,
                             .wrapped.fontId = 1
                         ));
            }
        }
    }
    
    return Clay_EndLayout();
}

// ============================================================================
// Optimized Terminal Rendering
// ============================================================================

void render_to_terminal(Clay_RenderCommandArray commands) {
    // Start rendering from home position
    printf(MOVE_TO(1, 1));
    
    // Pre-calculate scaling factors
    const float x_scale = 10.0f;
    const float y_scale = 20.0f;
    
    // Render each command
    for (int i = 0; i < commands.length; i++) {
        Clay_RenderCommand *cmd = &commands.internalArray[i];
        
        int x = (int)(cmd->boundingBox.x / x_scale);
        int y = (int)(cmd->boundingBox.y / y_scale);
        int w = (int)(cmd->boundingBox.width / x_scale);
        int h = (int)(cmd->boundingBox.height / y_scale);
        
        // Boundary checks
        if (x >= g_ui.term_width || y >= g_ui.term_height) continue;
        if (x < 0 || y < 0) continue;
        
        switch (cmd->commandType) {
            case CLAY_RENDER_COMMAND_TYPE_RECTANGLE: {
                Clay_Color bg = cmd->renderData.rectangle.backgroundColor;
                // Skip transparent rectangles (these are text bounding boxes)
                if (bg.a < 200) continue; // Only render solid backgrounds
                
                // Use true color if available
                printf(RGB_BG(bg.r, bg.g, bg.b));
                
                // Draw filled rectangle
                for (int row = 0; row < h && (y + row) < g_ui.term_height; row++) {
                    printf(MOVE_TO(x + 1, y + row + 1));
                    for (int col = 0; col < w && (x + col) < g_ui.term_width; col++) {
                        printf(" ");
                    }
                }
                printf(RESET_ALL);
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_TEXT: {
                Clay_Color color = cmd->renderData.text.textColor;
                if (color.a < 10) continue;
                
                printf(MOVE_TO(x + 1, y + 1));
                printf(RGB_FG(color.r, color.g, color.b));
                printf("%.*s", (int)cmd->renderData.text.stringContents.length,
                       cmd->renderData.text.stringContents.chars);
                printf(RESET_ALL);
                break;
            }
            
            default:
                break;
        }
    }
    
    fflush(stdout);
}

// ============================================================================
// Input Handling
// ============================================================================

int read_key(void) {
    char c;
    int nread = read(STDIN_FILENO, &c, 1);
    
    if (nread != 1) return -1;
    
    // Handle escape sequences
    if (c == '\033') {
        char seq[3];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return '\033';
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return '\033';
        
        if (seq[0] == '[') {
            switch (seq[1]) {
                case 'A': return 'k'; // Up arrow -> k
                case 'B': return 'j'; // Down arrow -> j
                case 'C': return 'l'; // Right arrow -> l
                case 'D': return 'h'; // Left arrow -> h
            }
        }
    }
    
    return c;
}

void handle_input(void) {
    int key = read_key();
    if (key == -1) return;
    
    int old_selection = g_ui.selected_item;
    
    switch (key) {
        case 'q':
        case 'Q':
            g_ui.running = false;
            break;
            
        case 'k':
        case 'K':
            g_ui.selected_item--;
            if (g_ui.selected_item < 0) g_ui.selected_item = MENU_COUNT - 1;
            break;
            
        case 'j':
        case 'J':
            g_ui.selected_item++;
            if (g_ui.selected_item >= MENU_COUNT) g_ui.selected_item = 0;
            break;
            
        case '\r':
        case '\n':
            // Execute action
            snprintf(g_ui.status_message, sizeof(g_ui.status_message),
                    "Executing: %s", g_menu_items[g_ui.selected_item].label);
            g_ui.status_color = COLOR_GREEN;
            g_ui.status_opacity = 1.0f;
            
            if (g_ui.selected_item == MENU_EXIT) {
                g_ui.running = false;
            } else if (g_ui.selected_item == MENU_EMERGENCY_SHELL) {
                // Temporarily exit to shell
                disable_raw_mode();
                printf(NORMAL_SCREEN);
                printf(SHOW_CURSOR);
                printf("\n🚀 Dropping to emergency shell...\n");
                printf("Type 'exit' to return to debork\n\n");
                system("/bin/bash");
                printf(ALTERNATE_SCREEN);
                printf(HIDE_CURSOR);
                enable_raw_mode();
                g_ui.needs_redraw = true;
            }
            break;
            
        case 'r':
        case 'R':
        case '\014': // Ctrl+L
            g_ui.needs_redraw = true;
            break;
    }
    
    if (old_selection != g_ui.selected_item) {
        g_ui.needs_redraw = true;
    }
}

// ============================================================================
// Initialization & Cleanup
// ============================================================================

void init_ui(void) {
    // Set locale for Unicode support
    setlocale(LC_ALL, "");
    
    // Initialize terminal
    enable_raw_mode();
    printf(ALTERNATE_SCREEN);
    printf(HIDE_CURSOR);
    printf(CLEAR_SCREEN);
    
    // Set up signal handlers
    signal(SIGWINCH, handle_resize);
    
    // Get terminal size
    update_terminal_size();
    
    // Initialize UI state
    g_ui.selected_item = 0;
    g_ui.running = true;
    g_ui.needs_redraw = true;
    g_ui.show_description = true;
    g_ui.show_particles = true;
    g_ui.time = 0.0f;
    g_ui.status_opacity = 0.0f;
    
    // Initialize animations
    for (int i = 0; i < MENU_COUNT; i++) {
        g_ui.select_animation[i] = 0.0f;
        g_ui.hover_animation[i] = 0.0f;
    }
    
    // Initialize Clay
    g_ui.arena_size = Clay_MinMemorySize();
    g_ui.arena_memory = malloc(g_ui.arena_size);
    g_ui.arena = Clay_CreateArenaWithCapacityAndMemory(g_ui.arena_size, g_ui.arena_memory);
    Clay_Initialize(g_ui.arena, g_ui.window_dimensions, (Clay_ErrorHandler){0});
    Clay_SetMeasureTextFunction(measure_text, NULL);
    
    // Initialize timing
    gettimeofday(&g_ui.last_frame, NULL);
    
    // Show welcome message
    strcpy(g_ui.status_message, "Welcome to debork! Select an option to begin.");
    g_ui.status_color = COLOR_SAPPHIRE;
    g_ui.status_opacity = 1.0f;
}

void cleanup_ui(void) {
    // Free Clay memory
    free(g_ui.arena_memory);
    
    // Restore terminal
    printf(NORMAL_SCREEN);
    printf(SHOW_CURSOR);
    printf(RESET_ALL);
    disable_raw_mode();
}

// ============================================================================
// Main Loop
// ============================================================================

void run_ui_loop(void) {
    const float target_fps = 60.0f;
    const float target_frame_time = 1.0f / target_fps;
    
    while (g_ui.running) {
        float dt = get_delta_time();
        
        // Handle terminal resize
        if (g_resize_pending) {
            update_terminal_size();
            g_resize_pending = false;
            printf(CLEAR_SCREEN);
        }
        
        // Update animations
        update_animations(dt);
        
        // Handle input
        handle_input();
        
        // Render if needed or if animating
        if (g_ui.needs_redraw || g_ui.status_opacity > 0.01f) {
            Clay_RenderCommandArray commands = render_ui();
            render_to_terminal(commands);
            g_ui.needs_redraw = false;
        }
        
        // Frame rate limiting
        float frame_time = get_delta_time();
        if (frame_time < target_frame_time) {
            usleep((useconds_t)((target_frame_time - frame_time) * 1000000));
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char *argv[]) {
    bool demo_mode = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--demo") == 0 || strcmp(argv[i], "-d") == 0) {
            demo_mode = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("debork - Boot Rescue Tool (Awesome Edition)\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  --demo, -d    Run in demo mode\n");
            printf("  --help, -h    Show this help\n");
            return 0;
        }
    }
    
    // Check privileges
    if (!demo_mode && geteuid() != 0) {
        printf("⚠️  Warning: debork should be run as root for full functionality\n");
        printf("   Run with --demo for UI testing, or use sudo for system rescue.\n\n");
        printf("Press Enter to exit or run: sudo %s\n", argv[0]);
        getchar();
        return 1;
    }
    
    // Initialize and run UI
    init_ui();
    
    if (demo_mode) {
        strcpy(g_ui.status_message, "🎮 Demo Mode - No system changes will be made");
        g_ui.status_color = COLOR_YELLOW;
        g_ui.status_opacity = 1.0f;
    }
    
    run_ui_loop();
    cleanup_ui();
    
    // Exit message
    printf("\n✨ Thank you for using debork!\n");
    
    if (!demo_mode && g_ui.selected_item == MENU_EXIT) {
        printf("   System will restart in 5 seconds...\n");
        sleep(5);
        system("reboot");
    }
    
    return 0;
}