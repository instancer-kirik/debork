/*
 * debork - Simple Clay UI Example
 * A minimal working example of Clay integration for terminal UI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

#define CLAY_IMPLEMENTATION
#include "clay.h"

// ANSI color codes
#define TERM_RESET      "\033[0m"
#define TERM_RED        "\033[31m"
#define TERM_GREEN      "\033[32m"
#define TERM_YELLOW     "\033[33m"
#define TERM_BLUE       "\033[34m"
#define TERM_CLEAR      "\033[2J\033[H"
#define TERM_HIDE_CURSOR "\033[?25l"
#define TERM_SHOW_CURSOR "\033[?25h"

typedef struct {
    int selected_item;
    int menu_count;
    bool running;
    struct termios orig_termios;
    int term_width;
    int term_height;
    Clay_Arena arena;
    void *arena_memory;
} AppState;

// Global app state
static AppState g_app = {0};

// Clay text measurement function
Clay_Dimensions measure_text(Clay_StringSlice text, Clay_TextElementConfig *config, void *userData) {
    (void)userData;
    // Simple monospace measurement: 1 char = 8 pixels wide
    int char_width = 8;
    int char_height = config->fontSize ? config->fontSize : 16;
    
    return (Clay_Dimensions) {
        .width = text.length * char_width,
        .height = char_height
    };
}

// Initialize terminal
void init_terminal(AppState *app) {
    // Save terminal settings
    tcgetattr(STDIN_FILENO, &app->orig_termios);
    
    // Set raw mode
    struct termios raw = app->orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    
    // Get terminal size
    struct winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    app->term_width = ws.ws_col;
    app->term_height = ws.ws_row;
    
    // Hide cursor and clear screen
    printf(TERM_HIDE_CURSOR TERM_CLEAR);
    fflush(stdout);
}

// Cleanup terminal
void cleanup_terminal(AppState *app) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &app->orig_termios);
    printf(TERM_SHOW_CURSOR TERM_CLEAR);
    fflush(stdout);
}

// Get single character
char get_char(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) == 1) {
        return c;
    }
    return 0;
}

// Render Clay to terminal
void render_to_terminal(Clay_RenderCommandArray *commands) {
    printf(TERM_CLEAR);
    
    for (int i = 0; i < commands->length; i++) {
        Clay_RenderCommand *cmd = &commands->internalArray[i];
        
        int x = (int)(cmd->boundingBox.x / 8);
        int y = (int)(cmd->boundingBox.y / 16);
        
        switch (cmd->commandType) {
            case CLAY_RENDER_COMMAND_TYPE_RECTANGLE: {
                Clay_Color bg = cmd->renderData.rectangle.backgroundColor;
                
                // Position cursor
                printf("\033[%d;%dH", y + 1, x + 1);
                
                // Set background color
                if (bg.r > 200 && bg.g < 100 && bg.b < 100) {
                    printf("\033[41m"); // Red background
                } else if (bg.r < 100 && bg.g > 200 && bg.b < 100) {
                    printf("\033[42m"); // Green background
                } else if (bg.r < 100 && bg.g < 100 && bg.b > 200) {
                    printf("\033[44m"); // Blue background
                } else if (bg.r > 150 || bg.g > 150 || bg.b > 150) {
                    printf("\033[47m"); // Light gray background
                } else if (bg.r > 50 || bg.g > 50 || bg.b > 50) {
                    printf("\033[100m"); // Dark gray background
                }
                
                // Draw filled rectangle with spaces
                int w = (int)(cmd->boundingBox.width / 8);
                int h = (int)(cmd->boundingBox.height / 16);
                
                for (int row = 0; row < h; row++) {
                    printf("\033[%d;%dH", y + row + 1, x + 1);
                    for (int col = 0; col < w; col++) {
                        printf(" ");
                    }
                }
                
                printf(TERM_RESET);
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_TEXT: {
                // Position cursor and print text
                printf("\033[%d;%dH", y + 1, x + 1);
                
                // Set text color based on the text data
                Clay_Color color = cmd->renderData.text.textColor;
                if (color.r > 200 && color.g > 200 && color.b > 200) {
                    printf(TERM_YELLOW);
                } else if (color.r > 200) {
                    printf(TERM_RED);
                } else if (color.g > 200) {
                    printf(TERM_GREEN);
                } else if (color.b > 200) {
                    printf(TERM_BLUE);
                }
                
                printf("%.*s", (int)cmd->renderData.text.stringContents.length, 
                       cmd->renderData.text.stringContents.chars);
                printf(TERM_RESET);
                break;
            }
            
            case CLAY_RENDER_COMMAND_TYPE_BORDER: {
                // Draw simple border with box characters
                int w = (int)(cmd->boundingBox.width / 8);
                int h = (int)(cmd->boundingBox.height / 16);
                
                // Top border
                printf("\033[%d;%dH+", y + 1, x + 1);
                for (int i = 1; i < w - 1; i++) printf("-");
                if (w > 1) printf("+");
                
                // Side borders
                for (int row = 1; row < h - 1; row++) {
                    printf("\033[%d;%dH|", y + row + 1, x + 1);
                    if (w > 1) printf("\033[%d;%dH|", y + row + 1, x + w);
                }
                
                // Bottom border
                if (h > 1) {
                    printf("\033[%d;%dH+", y + h, x + 1);
                    for (int i = 1; i < w - 1; i++) printf("-");
                    if (w > 1) printf("+");
                }
                break;
            }
            
            default:
                break;
        }
    }
    
    fflush(stdout);
}

// Build UI with Clay
void build_ui(AppState *app) {
    // Set layout dimensions (convert terminal chars to pixels)
    Clay_SetLayoutDimensions((Clay_Dimensions) {
        .width = app->term_width * 8,
        .height = app->term_height * 16
    });
    
    // Begin layout
    Clay_BeginLayout();
    
    // Root container
    CLAY((Clay_ElementDeclaration) {
        .id = CLAY_ID("Root"),
        .layout = {
            .sizing = CLAY_SIZING_GROW(),
            .padding = {8, 8, 8, 8},
            .layoutDirection = CLAY_TOP_TO_BOTTOM,
            .childGap = 8
        },
        .backgroundColor = {20, 20, 30, 255}
    }) {
        
        // Title bar
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Title"),
            .layout = {
                .sizing = {
                    .width = CLAY_SIZING_GROW(),
                    .height = CLAY_SIZING_FIXED(32)
                },
                .padding = {16, 16, 8, 8},
                .childAlignment = {
                    .x = CLAY_ALIGN_X_CENTER,
                    .y = CLAY_ALIGN_Y_CENTER
                }
            },
            .backgroundColor = {40, 40, 60, 255},
            .cornerRadius = {4, 4, 4, 4}
        }) {
            CLAY_TEXT(CLAY_STRING("debork Boot Rescue Tool"),
                     CLAY_TEXT_CONFIG({
                         .textColor = {255, 255, 200, 255},
                         .fontSize = 20,
                         .fontId = 0
                     }));
        }
        
        // Menu container
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Menu"),
            .layout = {
                .sizing = CLAY_SIZING_GROW(),
                .padding = {8, 8, 8, 8},
                .layoutDirection = CLAY_TOP_TO_BOTTOM,
                .childGap = 4
            },
            .backgroundColor = {30, 30, 40, 255}
        }) {
            
            for (int i = 0; i < 6; i++) {
                Clay_Color item_bg = (i == app->selected_item) 
                    ? (Clay_Color){60, 60, 80, 255}
                    : (Clay_Color){40, 40, 50, 255};
                
                Clay_Color text_color = (i == app->selected_item)
                    ? (Clay_Color){255, 255, 100, 255}
                    : (Clay_Color){200, 200, 200, 255};
                
                CLAY((Clay_ElementDeclaration) {
                    .id = CLAY_IDI("MenuItem", i),
                    .layout = {
                        .sizing = {
                            .width = CLAY_SIZING_GROW(),
                            .height = CLAY_SIZING_FIXED(24)
                        },
                        .padding = {12, 12, 6, 6},
                        .childAlignment = {
                            .x = CLAY_ALIGN_X_LEFT,
                            .y = CLAY_ALIGN_Y_CENTER
                        }
                    },
                    .backgroundColor = item_bg,
                    .cornerRadius = {2, 2, 2, 2}
                }) {
                    if (i == app->selected_item) {
                        CLAY_TEXT(CLAY_STRING("> "),
                                 CLAY_TEXT_CONFIG({
                                     .textColor = {100, 255, 100, 255},
                                     .fontSize = 16,
                                     .fontId = 0
                                 }));
                    }
                    
                    Clay_String text = {0};
                    switch (i) {
                        case 0: text = CLAY_STRING("1. Detect System"); break;
                        case 1: text = CLAY_STRING("2. Fix GRUB"); break;
                        case 2: text = CLAY_STRING("3. Regenerate initramfs"); break;
                        case 3: text = CLAY_STRING("4. Emergency Shell"); break;
                        case 4: text = CLAY_STRING("5. System Info"); break;
                        case 5: text = CLAY_STRING("6. Exit"); break;
                    }
                    
                    CLAY_TEXT(text,
                             CLAY_TEXT_CONFIG({
                                 .textColor = text_color,
                                 .fontSize = 16,
                                 .fontId = 0
                             }));
                }
            }
        }
        
        // Status bar
        CLAY((Clay_ElementDeclaration) {
            .id = CLAY_ID("Status"),
            .layout = {
                .sizing = {
                    .width = CLAY_SIZING_GROW(),
                    .height = CLAY_SIZING_FIXED(24)
                },
                .padding = {8, 8, 4, 4},
                .childAlignment = {
                    .x = CLAY_ALIGN_X_CENTER,
                    .y = CLAY_ALIGN_Y_CENTER
                }
            },
            .backgroundColor = {25, 25, 35, 255}
        }) {
            CLAY_TEXT(CLAY_STRING("Use arrows to navigate, Enter to select, q to quit"),
                     CLAY_TEXT_CONFIG({
                         .textColor = {150, 150, 150, 255},
                         .fontSize = 12,
                         .fontId = 0
                     }));
        }
    }
    
    // End layout and render
    Clay_RenderCommandArray commands = Clay_EndLayout();
    render_to_terminal(&commands);
}

// Handle input
void handle_input(AppState *app) {
    char c = get_char();
    
    switch (c) {
        case 'q':
        case 'Q':
            app->running = false;
            break;
            
        case 'j':
        case 'J':
            app->selected_item = (app->selected_item + 1) % app->menu_count;
            break;
            
        case 'k':
        case 'K':
            app->selected_item = (app->selected_item - 1 + app->menu_count) % app->menu_count;
            break;
            
        case '\n':
        case '\r':
            if (app->selected_item == 5) { // Exit
                app->running = false;
            }
            break;
            
        case 27: // ESC sequence
            c = get_char(); // consume '['
            if (c == '[') {
                c = get_char();
                if (c == 'A') { // Up arrow
                    app->selected_item = (app->selected_item - 1 + app->menu_count) % app->menu_count;
                } else if (c == 'B') { // Down arrow
                    app->selected_item = (app->selected_item + 1) % app->menu_count;
                }
            }
            break;
    }
}

int main(void) {
    // Initialize
    g_app.selected_item = 0;
    g_app.menu_count = 6;
    g_app.running = true;
    
    // Allocate Clay memory
    size_t arena_size = 1024 * 1024; // 1MB
    g_app.arena_memory = malloc(arena_size);
    g_app.arena = Clay_CreateArenaWithCapacityAndMemory(arena_size, g_app.arena_memory);
    
    // Set text measurement function
    Clay_SetMeasureTextFunction(measure_text, NULL);
    
    // Initialize terminal
    init_terminal(&g_app);
    
    // Main loop
    while (g_app.running) {
        build_ui(&g_app);
        handle_input(&g_app);
        usleep(10000); // 10ms delay
    }
    
    // Cleanup
    cleanup_terminal(&g_app);
    free(g_app.arena_memory);
    
    return 0;
}