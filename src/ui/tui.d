module debork.ui.tui;

import std.stdio;
import std.string;
import std.conv;
import std.algorithm;
import std.format;
import std.array;
import core.sys.posix.termios;
import core.sys.posix.unistd;
import core.stdc.stdio : getchar;
import debork.core.types;
import debork.core.logger;

class TUI {
    private int selectedIndex = 0;
    private bool debugMode = false;

    this(bool debugFlag = false) {
        debugMode = debugFlag;
    }

    /**
     * Clear screen and position cursor at top
     */
    void clearScreen() {
        stdout.write("\033[2J\033[H");
        stdout.flush();
    }

    /**
     * Print the main header
     */
    void printHeader() {
        clearScreen();
        writeln(TermColor.BOLD ~ "╔══════════════════════════════════════════════════════════════╗" ~ TermColor.RESET);
        writeln(TermColor.BOLD ~ "║                    debork Boot Rescue Tool                  ║" ~ TermColor.RESET);
        writeln(TermColor.BOLD ~ "║              Cross-Platform Linux System Fixer              ║" ~ TermColor.RESET);
        writeln(TermColor.BOLD ~ "╚══════════════════════════════════════════════════════════════╝" ~ TermColor.RESET);
        writeln();
    }

    /**
     * Print status message with optional error styling
     */
    void printStatus(string message, bool isError = false) {
        string color = isError ? TermColor.RED : TermColor.GREEN;
        string prefix = isError ? "✗" : "✓";
        writeln(color ~ prefix ~ " " ~ message ~ TermColor.RESET);
    }

    /**
     * Print informational message
     */
    void printInfo(string message) {
        writeln(TermColor.BLUE ~ "ℹ " ~ message ~ TermColor.RESET);
    }

    /**
     * Print warning message
     */
    void printWarning(string message) {
        writeln(TermColor.YELLOW ~ "⚠ " ~ message ~ TermColor.RESET);
    }

    /**
     * Print error message
     */
    void printError(string message) {
        writeln(TermColor.RED ~ "✗ " ~ message ~ TermColor.RESET);
    }

    /**
     * Print debug message (only in debug mode)
     */
    void printDebug(string message) {
        if (debugMode) {
            writeln(TermColor.CYAN ~ "🐛 " ~ message ~ TermColor.RESET);
        }
    }

    /**
     * Display a menu and handle navigation
     */
    int showMenu(MenuOption[] options) {
        if (options.length == 0) {
            return -1;
        }

        while (true) {
            printMenu(options, 0);

            stdout.write("Enter your choice (1-" ~ to!string(options.length) ~ ", or 'q' to quit): ");
            stdout.flush();

            string input = readln().strip();

            if (input == "q" || input == "Q") {
                return -1;
            }

            try {
                int choice = to!int(input) - 1;
                if (choice >= 0 && choice < options.length && options[choice].enabled) {
                    return choice;
                }
                writeln("Invalid choice. Please try again.");
            } catch (Exception e) {
                writeln("Invalid input. Please enter a number.");
            }
        }
    }

    /**
     * Simple string menu (backward compatibility)
     */
    int showMenu(string[] options) {
        MenuOption[] menuOptions;
        foreach (option; options) {
            menuOptions ~= MenuOption(option, "", true);
        }
        return showMenu(menuOptions);
    }

    /**
     * Print menu options
     */
    private void printMenu(MenuOption[] options, int selected) {
        writeln(TermColor.BOLD ~ "Select an option:" ~ TermColor.RESET);
        writeln();

        foreach (i, option; options) {
            string color;

            if (!option.enabled) {
                color = TermColor.WHITE ~ "\033[2m"; // Dim
            } else {
                color = TermColor.RESET;
            }

            string numberPrefix = format("[%d] ", i + 1);
            writeln(color ~ numberPrefix ~ option.text ~ TermColor.RESET);

            // Show description if available
            if (option.description.length > 0) {
                string descColor = option.enabled ? TermColor.CYAN : TermColor.WHITE ~ "\033[2m";
                writeln(descColor ~ "      " ~ option.description ~ TermColor.RESET);
            }
        }

        writeln();
    }



    /**
     * Prompt user for text input
     */
    string promptInput(string prompt) {
        stdout.write(TermColor.CYAN ~ prompt ~ ": " ~ TermColor.RESET);
        stdout.flush();
        return readln().strip();
    }

    /**
     * Prompt user for confirmation (y/N)
     */
    bool promptConfirm(string prompt, bool defaultValue = false) {
        string defaultText = defaultValue ? "(Y/n)" : "(y/N)";
        stdout.write(TermColor.YELLOW ~ prompt ~ " " ~ defaultText ~ ": " ~ TermColor.RESET);
        stdout.flush();

        string response = readln().strip().toLower();

        if (response.length == 0) {
            return defaultValue;
        }

        return response == "y" || response == "yes";
    }

    /**
     * Display a progress bar
     */
    void showProgress(string operation, float percentage) {
        int barWidth = 40;
        int filled = cast(int)(percentage * barWidth / 100.0);

        stdout.write("\r" ~ TermColor.CYAN ~ operation ~ ": " ~ TermColor.RESET);
        stdout.write("[");

        foreach (i; 0..barWidth) {
            if (i < filled) {
                stdout.write(TermColor.GREEN ~ "█" ~ TermColor.RESET);
            } else {
                stdout.write(" ");
            }
        }

        stdout.write(format("] %.1f%%", percentage));
        stdout.flush();

        if (percentage >= 100.0) {
            writeln();
        }
    }

    /**
     * Display a list with colored bullets
     */
    void printList(string[] items, string bulletColor = TermColor.GREEN) {
        foreach (item; items) {
            writeln(bulletColor ~ "• " ~ TermColor.RESET ~ item);
        }
    }

    /**
     * Display system information in a formatted table
     */
    void printSystemInfo(ref SystemInfo sysInfo) {
        printHeader();
        writeln(TermColor.BOLD ~ "System Information:" ~ TermColor.RESET);
        writeln();

        // Basic info table
        printInfoRow("Device", sysInfo.device);
        printInfoRow("Mount Point", sysInfo.mountPoint);
        printInfoRow("Filesystem", sysInfo.fstype);
        printInfoRow("UUID", sysInfo.uuid.length > 0 ? sysInfo.uuid : "Not detected");

        if (sysInfo.isBtrfs) {
            printInfoRow("Btrfs Root Subvol", sysInfo.btrfsInfo.rootSubvolume);
            printInfoRow("Mounted Subvols", format("%d", sysInfo.btrfsInfo.mountedSubvolumes.length));
        }

        printInfoRow("Boot Directory", sysInfo.bootDir);
        printInfoRow("EFI Directory", sysInfo.efiDir);
        printInfoRow("Bootloader", bootLoaderToString(sysInfo.bootLoader));
        printInfoRow("Package Manager", packageManagerToString(sysInfo.packageManager));
        printInfoRow("Available Shells", format("%d", sysInfo.availableShells.length));
        printInfoRow("Network Config", sysInfo.hasNetworking ? "Available" : "Not available");
        printInfoRow("Validated", sysInfo.isValidated ? "Yes" : "No");

        writeln();

        // Kernels section
        if (sysInfo.kernels.length > 0) {
            writeln(TermColor.BOLD ~ "Available Kernels:" ~ TermColor.RESET);
            foreach (kernel; sysInfo.kernels) {
                string status = kernel.exists ? TermColor.GREEN ~ "✓" : TermColor.RED ~ "✗";
                string initrdStatus = kernel.initrdExists ? " (initrd: ✓)" : " (initrd: ✗)";
                writeln(format("%s %s (%s)%s", status, kernel.path, kernel.kernelVersion, initrdStatus));
            }
            writeln(TermColor.RESET);
        }
    }

    /**
     * Print a formatted information row
     */
    private void printInfoRow(string label, string value) {
        writeln(format("%-20s: %s", label, value));
    }

    /**
     * Display a box with important information
     */
    void printInfoBox(string title, string[] content) {
        int maxWidth = 60;

        // Calculate actual max width based on content
        int contentMaxWidth = cast(int)title.length;
        foreach (line; content) {
            if (cast(int)line.length > contentMaxWidth) {
                contentMaxWidth = cast(int)line.length;
            }
        }

        if (contentMaxWidth > maxWidth) {
            maxWidth = contentMaxWidth + 4;
        }

        // Top border
        writeln(TermColor.CYAN ~ "┌" ~ replicate("─", maxWidth - 2) ~ "┐" ~ TermColor.RESET);

        // Title
        int titlePadding = (maxWidth - 2 - cast(int)title.length) / 2;
        string paddedTitle = replicate(" ", titlePadding) ~ title ~ replicate(" ", maxWidth - 2 - titlePadding - cast(int)title.length);
        writeln(TermColor.CYAN ~ "│" ~ TermColor.BOLD ~ paddedTitle ~ TermColor.RESET ~ TermColor.CYAN ~ "│" ~ TermColor.RESET);

        // Separator
        writeln(TermColor.CYAN ~ "├" ~ replicate("─", maxWidth - 2) ~ "┤" ~ TermColor.RESET);

        // Content
        foreach (line; content) {
            int linePadding = maxWidth - 2 - cast(int)line.length;
            string paddedLine = " " ~ line ~ replicate(" ", linePadding - 1);
            writeln(TermColor.CYAN ~ "│" ~ TermColor.RESET ~ paddedLine ~ TermColor.CYAN ~ "│" ~ TermColor.RESET);
        }

        // Bottom border
        writeln(TermColor.CYAN ~ "└" ~ replicate("─", maxWidth - 2) ~ "┘" ~ TermColor.RESET);
        writeln();
    }

    /**
     * Wait for user to press any key
     */
    void waitForKey(string message = "Press Enter to continue...") {
        writeln(TermColor.YELLOW ~ message ~ TermColor.RESET);
        stdout.flush();
        readln();
    }

    /**
     * Display error with suggestions
     */
    void displayError(string error, string[] suggestions = []) {
        printError(error);

        if (suggestions.length > 0) {
            writeln();
            printInfo("Suggestions:");
            printList(suggestions, TermColor.YELLOW);
        }

        writeln();
    }

    /**
     * Display operation result
     */
    void displayResult(RepairResult result) {
        printHeader();

        if (result.success) {
            printStatus("Operation completed successfully!");
        } else {
            printStatus("Operation failed", true);
        }

        writeln();

        if (result.completedSteps.length > 0) {
            writeln(TermColor.BOLD ~ "Completed steps:" ~ TermColor.RESET);
            printList(result.completedSteps, TermColor.GREEN);
            writeln();
        }

        if (result.warnings.length > 0) {
            writeln(TermColor.BOLD ~ "Warnings:" ~ TermColor.RESET);
            printList(result.warnings, TermColor.YELLOW);
            writeln();
        }

        if (result.errors.length > 0) {
            writeln(TermColor.BOLD ~ "Errors:" ~ TermColor.RESET);
            printList(result.errors, TermColor.RED);
            writeln();
        }
    }

    /**
     * Create MenuOption array from simple strings
     */
    static MenuOption[] createSimpleMenu(string[] options) {
        MenuOption[] menuOptions;
        foreach (option; options) {
            menuOptions ~= MenuOption(option, "", true);
        }
        return menuOptions;
    }

    /**
     * Create menu with descriptions
     */
    static MenuOption[] createDescriptiveMenu(string[string] optionsWithDesc) {
        MenuOption[] menuOptions;
        foreach (text, desc; optionsWithDesc) {
            menuOptions ~= MenuOption(text, desc, true);
        }
        return menuOptions;
    }

    // Helper functions for bootloader enum
    private string bootLoaderToString(BootLoader bootloader) {
        final switch (bootloader) {
            case BootLoader.UNKNOWN:     return "Unknown";
            case BootLoader.GRUB:        return "GRUB";
            case BootLoader.REFIND:      return "rEFInd";
            case BootLoader.SYSTEMD_BOOT: return "systemd-boot";
        }
    }

    private string packageManagerToString(PackageManager pm) {
        final switch (pm) {
            case PackageManager.UNKNOWN: return "Unknown";
            case PackageManager.PACMAN:  return "pacman (Arch Linux)";
            case PackageManager.APT:     return "apt (Debian/Ubuntu)";
            case PackageManager.YUM:     return "yum (Red Hat/CentOS)";
            case PackageManager.DNF:     return "dnf (Fedora)";
            case PackageManager.ZYPPER:  return "zypper (openSUSE)";
        }
    }
}
