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
#include <math.h>
#include <signal.h>
#include <locale.h>

// Clay configuration
#define CLAY_IMPLEMENTATION
#include "../../include/clay.h"

// Terminal control sequences
#define ESC "\033"
#define CSI "\033["
#define CLEAR_SCREEN        CSI "2J" CSI "H"
#define CLEAR_LINE          CSI "2K"
#define HIDE_CURSOR         CSI "?25l"
#define SHOW_CURSOR         CSI "?25h"
#define ALTERNATE_SCREEN    CSI "?1049h"
#define NORMAL_SCREEN       CSI "?1049l"
#define RESET_ALL           CSI "0m"
#define MOVE_TO(x,y)        printf(CSI "%d;%dH", (y), (x))

// True color support
#define SET_FG_RGB(r,g,b)   printf(CSI "38;2;%d;%d;%dm", (int)(r), (int)(g), (int)(b))
#define SET_BG_RGB(r,g,b)   printf(CSI "48;2;%d;%d;%dm", (int)(r), (int)(g), (int)(b))

// Color palette
#define COLOR_BG            ((Clay_Color){24, 24, 37, 255})
#define COLOR_SURFACE       ((Clay_Color){49, 50, 68, 255})
#define COLOR_SURFACE_LIGHT ((Clay_Color){69, 71, 90, 255})
#define COLOR_SELECTED      ((Clay_Color){88, 91, 112, 255})
#define COLOR_TEXT          ((Clay_Color){205, 214, 244, 255})
#define COLOR_TEXT_DIM      ((Clay_Color){166, 173, 200, 255})
#define COLOR_ACCENT        ((Clay_Color){180, 190, 254, 255})
#define COLOR_SUCCESS       ((Clay_Color){166, 227, 161, 255})
#define COLOR_WARNING       ((Clay_Color){249, 226, 175, 255})
#define COLOR_ERROR         ((Clay_Color){243, 139, 168, 255})

// Menu configuration
#define MENU_COUNT 7

typedef struct {
    const char *label;
    const char *icon;
    const char *description;
    Clay_Color accent_color;
} MenuItem;

typedef struct {
    int selected_item;
    bool running;
    float animation_time;
    float select_anim[MENU_COUNT];
    int term_width;
    int term_height;
    struct termios orig_termios;
    Clay_Dimensions window_dims;
    Clay_Arena arena;
    uint8_t *arena_memory;
    char status_message[256];
    float status_timer;
} AppState;

static AppState g_app = {0};

static const MenuItem g_menu_items[MENU_COUNT] = {
    {"Fix My System", "🔧", "Automatically detect and repair boot issues", COLOR_SUCCESS},
    {"Emergency Shell", "💻", "Drop to root shell for manual repairs", COLOR_ACCENT},
    {"Regenerate Initramfs", "💾", "Rebuild initial RAM disk", COLOR_WARNING},
    {"Fix Boot Config", "⚙️", "Repair bootloader configuration", COLOR_WARNING},
    {"System Information", "📊", "Display system details", COLOR_ACCENT},
    {"Advanced Options", "🚀", "Expert recovery tools", COLOR_ERROR},
    {"Exit", "🚪", "Exit and restart", COLOR_TEXT_DIM}
};

// Terminal management
void enable_raw_mode(void) {
    tcgetattr(STDIN_FILENO, &g_app.orig_termios);
    struct termios raw = g_app.orig_termios;
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void disable_raw_mode(void) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_app.orig_termios);
}

void get_terminal_size(void) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    g_app.term_width = w.ws_col;
    g_app.term_height = w.ws_row;
    // Clay uses pixels, we need to scale appropriately
    // Use smaller scaling factors for better alignment
    g_app.window_dims.width = (float)(w.ws_col * 8);
    g_app.window_dims.height = (float)(w.ws_row * 16);
}

// Text measurement for Clay
Clay_Dimensions measure_text(Clay_StringSlice text, Clay_TextElementConfig *config, void *user_data) {
    (void)user_data;
    float font_size = config ? config->fontSize : 16.0f;
    // More accurate character measurements
    float char_width = font_size * 0.5f;
    float line_height = font_size * 1.2f;
    return (Clay_Dimensions){
        .width = text.length * char_width,
        .height = line_height
    };
}

// Animation updates
void update_animations(float dt) {
    g_app.animation_time += dt;
    
    for (int i = 0; i < MENU_COUNT; i++) {
        float target = (i == g_app.selected_item) ? 1.0f : 0.0f;
        float diff = target - g_app.select_anim[i];
        g_app.select_anim[i] += diff * dt * 10.0f;
    }
    
    if (g_app.status_timer > 0) {
        g_app.status_timer -= dt;
    }
}

// Build the UI with Clay
Clay_RenderCommandArray build_ui(void) {
    Clay_SetLayoutDimensions(g_app.window_dims);
    Clay_BeginLayout();
    
    // Root container - NO BACKGROUND COLOR
    CLAY((Clay_ElementDeclaration) {
        .id = CLAY_ID("Root"),
        .layout = {
            .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
            .padding = {16, 16, 16, 16},
            .childGap = 12,
            .layoutDirection = CLAY_TOP_TO_BOTTOM
        }
        // NO backgroundColor - this prevents the full-screen rectangle
    }) {
        // Header with actual background
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Header"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(60)},
                .padding = {16, 16, 12, 12},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            },
            .backgroundColor = COLOR_SURFACE,
            .cornerRadius = {8, 8, 8, 8}
        }) {
            float pulse = (sinf(g_app.animation_time * 2.0f) + 1.0f) * 0.5f;
            Clay_Color title_color = COLOR_ACCENT;
            title_color.r = (uint8_t)fminf(255, title_color.r + pulse * 30);
            
            CLAY_TEXT(CLAY_STRING("⚡ DEBORK BOOT RESCUE ⚡"),
                     CLAY_TEXT_CONFIG(
                         .wrapped.textColor = title_color,
                         .wrapped.fontSize = 24,
                         .wrapped.fontId = 0
                     ));
        }
        
        // Status message if active
        if (g_app.status_timer > 0) {
            Clay_Color status_bg = COLOR_WARNING;
            status_bg.a = (uint8_t)(255 * fminf(1.0f, g_app.status_timer));
            
            CLAY((Clay_ElementDeclaration) {
                .id = CLAY_ID("Status"),
                .layout = {
                    .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIT()},
                    .padding = {12, 12, 8, 8}
                },
                .backgroundColor = status_bg,
                .cornerRadius = {4, 4, 4, 4}
            }) {
                Clay_String msg = {
                    .chars = g_app.status_message,
                    .length = strlen(g_app.status_message),
                    .isStaticallyAllocated = false
                };
                CLAY_TEXT(msg, CLAY_TEXT_CONFIG(
                    .wrapped.textColor = COLOR_TEXT,
                    .wrapped.fontSize = 14,
                    .wrapped.fontId = 0
                ));
            }
        }
        
        // Menu area - NO BACKGROUND on container
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("MenuArea"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_GROW()},
                .childGap = 6,
                .layoutDirection = CLAY_TOP_TO_BOTTOM
            }
            // NO backgroundColor
        }) {
            for (int i = 0; i < MENU_COUNT; i++) {
                const MenuItem *item = &g_menu_items[i];
                float anim = g_app.select_anim[i];
                
                // Calculate background color with animation
                Clay_Color bg = COLOR_SURFACE;
                if (anim > 0.01f) {
                    bg.r = bg.r + (uint8_t)((COLOR_SELECTED.r - bg.r) * anim);
                    bg.g = bg.g + (uint8_t)((COLOR_SELECTED.g - bg.g) * anim);
                    bg.b = bg.b + (uint8_t)((COLOR_SELECTED.b - bg.b) * anim);
                }
                
                // Add pulse effect for selected item
                if (i == g_app.selected_item) {
                    float pulse = (sinf(g_app.animation_time * 3.0f) + 1.0f) * 0.5f;
                    bg.r = (uint8_t)fminf(255, bg.r + pulse * 10);
                    bg.g = (uint8_t)fminf(255, bg.g + pulse * 10);
                    bg.b = (uint8_t)fminf(255, bg.b + pulse * 15);
                }
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_IDI("MenuItem", i),
                    .layout = {
                        .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(44)},
                        .padding = {12, 12, 10, 10},
                        .childGap = 8,
                        .layoutDirection = CLAY_LEFT_TO_RIGHT,
                        .childAlignment = {CLAY_ALIGN_X_LEFT, CLAY_ALIGN_Y_CENTER}
                    },
                    .backgroundColor = bg,
                    .cornerRadius = {4, 4, 4, 4}
                }) {
                    // Selection indicator
                    if (i == g_app.selected_item) {
                        Clay_Color arrow_color = COLOR_SUCCESS;
                        arrow_color.a = (uint8_t)(200 + 55 * sinf(g_app.animation_time * 4.0f));
                        CLAY_TEXT(CLAY_STRING("▶ "), CLAY_TEXT_CONFIG(
                            .wrapped.textColor = arrow_color,
                            .wrapped.fontSize = 16,
                            .wrapped.fontId = 0
                        ));
                    }
                    
                    // Icon
                    Clay_String icon_str = {
                        .chars = item->icon,
                        .length = strlen(item->icon),
                        .isStaticallyAllocated = false
                    };
                    CLAY_TEXT(icon_str, CLAY_TEXT_CONFIG(
                        .wrapped.textColor = item->accent_color,
                        .wrapped.fontSize = 20,
                        .wrapped.fontId = 0
                    ));
                    
                    // Label
                    Clay_String label_str = {
                        .chars = item->label,
                        .length = strlen(item->label),
                        .isStaticallyAllocated = false
                    };
                    Clay_Color text_color = (anim > 0.5f) ? COLOR_TEXT : COLOR_TEXT_DIM;
                    CLAY_TEXT(label_str, CLAY_TEXT_CONFIG(
                        .wrapped.textColor = text_color,
                        .wrapped.fontSize = 16,
                        .wrapped.fontId = 0
                    ));
                }
            }
        }
        
        // Footer help text
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Footer"),
            .layout = {
                .sizing = {CLAY_SIZING_GROW(), CLAY_SIZING_FIXED(30)},
                .padding = {8, 8, 6, 6},
                .childAlignment = {CLAY_ALIGN_X_CENTER, CLAY_ALIGN_Y_CENTER}
            },
            .backgroundColor = COLOR_SURFACE,
            .cornerRadius = {4, 4, 4, 4}
        }) {
            CLAY_TEXT(CLAY_STRING("↑↓/jk: Navigate • Enter: Select • q: Quit"),
                     CLAY_TEXT_CONFIG(
                         .wrapped.textColor = COLOR_TEXT_DIM,
                         .wrapped.fontSize = 12,
                         .wrapped.fontId = 0
                     ));
        }
    }
    
    return Clay_EndLayout();
}

// Optimized rendering to terminal
void render_to_terminal(Clay_RenderCommandArray commands) {
    // Clear screen once at start
    static bool first_render = true;
    if (first_render) {
        printf(CLEAR_SCREEN);
        first_render = false;
    }
    
    // Calculate scaling - must match what we use in get_terminal_size
    const float x_scale = 8.0f;
    const float y_scale = 16.0f;
    
    // First pass: render rectangles (backgrounds)
    for (int i = 0; i < commands.length; i++) {
        Clay_RenderCommand *cmd = &commands.internalArray[i];
        
        if (cmd->commandType != CLAY_RENDER_COMMAND_TYPE_RECTANGLE) continue;
        
        Clay_Color bg = cmd->renderData.rectangle.backgroundColor;
        
        // IMPORTANT: Skip transparent and nearly transparent rectangles
        // These are the text bounding boxes that cause the grey box issue
        if (bg.a < 250) continue; // Only render fully opaque backgrounds
        
        int x = (int)(cmd->boundingBox.x / x_scale);
        int y = (int)(cmd->boundingBox.y / y_scale);
        int w = (int)(cmd->boundingBox.width / x_scale);
        int h = (int)(cmd->boundingBox.height / y_scale);
        
        // Boundary checks
        if (x >= g_app.term_width || y >= g_app.term_height) continue;
        if (x < 0 || y < 0) continue;
        
        // Clamp to terminal bounds
        if (x + w > g_app.term_width) w = g_app.term_width - x;
        if (y + h > g_app.term_height) h = g_app.term_height - y;
        
        // Draw rectangle
        SET_BG_RGB(bg.r, bg.g, bg.b);
        for (int row = 0; row < h; row++) {
            MOVE_TO(x + 1, y + row + 1);
            for (int col = 0; col < w; col++) {
                printf(" ");
            }
        }
        printf(RESET_ALL);
    }
    
    // Second pass: render text
    for (int i = 0; i < commands.length; i++) {
        Clay_RenderCommand *cmd = &commands.internalArray[i];
        
        if (cmd->commandType != CLAY_RENDER_COMMAND_TYPE_TEXT) continue;
        
        Clay_Color fg = cmd->renderData.text.textColor;
        if (fg.a < 10) continue; // Skip invisible text
        
        int x = (int)(cmd->boundingBox.x / x_scale);
        int y = (int)(cmd->boundingBox.y / y_scale);
        
        if (x >= g_app.term_width || y >= g_app.term_height) continue;
        if (x < 0 || y < 0) continue;
        
        MOVE_TO(x + 1, y + 1);
        SET_FG_RGB(fg.r, fg.g, fg.b);
        printf("%.*s", (int)cmd->renderData.text.stringContents.length,
               cmd->renderData.text.stringContents.chars);
        printf(RESET_ALL);
    }
    
    fflush(stdout);
}

// Input handling
int read_key(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return -1;
    
    if (c == '\033') {
        char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return '\033';
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return '\033';
        
        if (seq[0] == '[') {
            switch (seq[1]) {
                case 'A': return 'k'; // Up
                case 'B': return 'j'; // Down
            }
        }
    }
    return c;
}

void handle_input(void) {
    int key = read_key();
    if (key == -1) return;
    
    switch (key) {
        case 'q':
        case 'Q':
            g_app.running = false;
            break;
            
        case 'k':
        case 'K':
            g_app.selected_item--;
            if (g_app.selected_item < 0) g_app.selected_item = MENU_COUNT - 1;
            break;
            
        case 'j':
        case 'J':
            g_app.selected_item++;
            if (g_app.selected_item >= MENU_COUNT) g_app.selected_item = 0;
            break;
            
        case '\r':
        case '\n':
            snprintf(g_app.status_message, sizeof(g_app.status_message),
                    "Selected: %s", g_menu_items[g_app.selected_item].label);
            g_app.status_timer = 2.0f;
            
            if (g_app.selected_item == MENU_COUNT - 1) { // Exit
                g_app.running = false;
            }
            break;
    }
}

// Initialize app
void init_app(void) {
    setlocale(LC_ALL, "");
    
    enable_raw_mode();
    printf(ALTERNATE_SCREEN);
    printf(HIDE_CURSOR);
    
    get_terminal_size();
    
    g_app.selected_item = 0;
    g_app.running = true;
    
    // Initialize Clay
    g_app.arena_memory = malloc(Clay_MinMemorySize());
    g_app.arena = Clay_CreateArenaWithCapacityAndMemory(
        Clay_MinMemorySize(), g_app.arena_memory);
    Clay_Initialize(g_app.arena, g_app.window_dims, (Clay_ErrorHandler){0});
    Clay_SetMeasureTextFunction(measure_text, NULL);
}

void cleanup_app(void) {
    free(g_app.arena_memory);
    printf(NORMAL_SCREEN);
    printf(SHOW_CURSOR);
    printf(RESET_ALL);
    disable_raw_mode();
}

// Main loop
int main(int argc, char *argv[]) {
    bool demo_mode = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--demo") == 0 || strcmp(argv[i], "-d") == 0) {
            demo_mode = true;
        }
    }
    
    if (!demo_mode && geteuid() != 0) {
        printf("⚠️  Run with --demo for testing, or use sudo for system rescue.\n");
        return 1;
    }
    
    init_app();
    
    struct timeval last_time;
    gettimeofday(&last_time, NULL);
    
    while (g_app.running) {
        struct timeval now;
        gettimeofday(&now, NULL);
        float dt = (now.tv_sec - last_time.tv_sec) + 
                   (now.tv_usec - last_time.tv_usec) / 1000000.0f;
        last_time = now;
        
        update_animations(dt);
        handle_input();
        
        Clay_RenderCommandArray commands = build_ui();
        render_to_terminal(commands);
        
        usleep(16666); // ~60 FPS
    }
    
    cleanup_app();
    printf("\n✨ Thank you for using debork!\n");
    
    return 0;
}