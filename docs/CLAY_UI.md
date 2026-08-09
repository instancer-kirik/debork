# debork Clay UI Documentation

## 🎨 Overview

The Clay UI version of debork provides a modern, visually appealing terminal user interface powered by the Clay layout engine. This version offers the same boot rescue functionality as the standard version but with enhanced visual presentation.

## ✨ Features

### Visual Enhancements
- **256-color support** for rich color gradients
- **Smooth layouts** with proper spacing and alignment
- **Unicode icons** for better visual feedback
- **Dynamic highlighting** of selected menu items
- **Color-coded status messages** (green for success, red for errors, yellow for warnings)

### UI Components
1. **Header Bar** - Displays the tool name with a gradient background
2. **Status Area** - Shows current operation status with color coding
3. **Menu Container** - Interactive menu with keyboard navigation
4. **Help Bar** - Displays available keyboard shortcuts

## 🔧 Building the Clay UI Version

### Prerequisites
- GCC or compatible C compiler
- Clay header file (included in `include/clay.h`)
- Terminal with 256-color support

### Build Commands
```bash
# Build the Clay UI version
make -f Makefile.c clay

# Build with debug symbols
make -f Makefile.c clay-debug

# Clean build artifacts
make -f Makefile.c clean
```

## 🚀 Running the Clay UI

### Normal Mode (requires root)
```bash
sudo ./build/debork-clay
```

### Demo Mode (no root required)
```bash
./build/debork-clay --demo
```

### Testing the UI
```bash
# Run the test script for automated demo
./test_ui.sh
```

## ⌨️ Keyboard Controls

| Key | Action |
|-----|--------|
| `↑` / `k` | Navigate up |
| `↓` / `j` | Navigate down |
| `Enter` | Select current item |
| `q` | Quit application |
| `h` | Show help (when available) |

## 🎨 Color Scheme

The Clay UI uses a modern color palette:

- **Background**: Dark blue-gray (#14141E)
- **Header**: Medium blue (#28283C)
- **Menu Items**: Dark gray (#1E1E28)
- **Selected Item**: Highlighted blue (#3C3C50)
- **Text**: Light gray (#C8D0E0)
- **Accent**: Cyan blue (#64C8FF)
- **Success**: Green (#64FF64)
- **Error**: Red (#FF6464)
- **Warning**: Yellow (#FFC864)

## 🛠️ Technical Details

### Pixel to Terminal Conversion
The Clay engine works with pixel coordinates, which are converted to terminal character positions:
- **X coordinate**: Divided by 10 (character width in pixels)
- **Y coordinate**: Divided by 20 (line height in pixels)

### Color Rendering
The renderer converts Clay's RGB colors to:
- **256-color mode** for backgrounds and text
- **ANSI escape sequences** for terminal compatibility

### Text Measurement
Text dimensions are calculated based on:
- Monospace font assumption
- 10 pixels per character width
- Font size × 1.25 for line height

## 📝 Menu Options

1. **🔧 Fix My System** - Complete system repair including package updates, initramfs regeneration, and bootloader fixes
2. **💻 Emergency Shell** - Drop to a shell for manual repairs
3. **💾 Regenerate Initramfs** - Rebuild initial RAM filesystem only
4. **⚙️ Fix Boot Configuration** - Repair bootloader configuration
5. **📊 System Information** - Display detected system configuration
6. **🚪 Exit** - Quit the application

## 🔍 Troubleshooting

### UI Looks Distorted
- Ensure your terminal supports 256 colors: `echo $TERM` should show `xterm-256color` or similar
- Try resizing your terminal window to at least 80×24 characters
- Use a monospace font in your terminal

### Colors Not Displaying Correctly
- Check terminal color support: `tput colors` should return 256
- Try different terminal emulators (recommended: kitty, alacritty, iTerm2)

### Text Overlapping
- Increase terminal size
- The UI is optimized for terminals at least 80 characters wide

## 🚀 Future Improvements

### Planned Features
- [ ] Mouse support for menu navigation
- [ ] Configurable color themes
- [ ] Progress bars for long operations
- [ ] Scrollable log viewer
- [ ] Animated transitions

### Code Improvements
- [ ] Better responsive scaling for different terminal sizes
- [ ] Optimized rendering to reduce flicker
- [ ] Custom border styles
- [ ] Gradient backgrounds support

## 📄 File Structure

```
debork/
├── src/c/
│   ├── debork_clay.c         # Main Clay UI implementation
│   ├── debork_clay_correct.c # Original Clay attempt
│   └── debork.c              # Standard version
├── include/
│   └── clay.h                # Clay layout engine header
├── build/
│   └── debork-clay           # Compiled Clay UI binary
└── test_ui.sh                # UI testing script
```

## 🤝 Contributing

To improve the Clay UI:

1. **Color Schemes**: Modify the color constants at the top of `debork_clay.c`
2. **Layout**: Adjust sizing and padding in the `render_ui()` function
3. **Animations**: Add state transitions in `handle_input()`
4. **Icons**: Update the menu item strings with different Unicode symbols

## 📚 References

- [Clay Layout Engine](https://github.com/nicbarker/clay) - The UI framework
- [ANSI Escape Codes](https://en.wikipedia.org/wiki/ANSI_escape_code) - Terminal control sequences
- [256 Color Palette](https://jonasjacek.github.io/colors/) - Terminal color reference

## 📜 License

This Clay UI implementation is part of the debork project and follows the same license terms.

---

*Last updated: 2024*