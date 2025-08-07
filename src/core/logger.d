module debork.core.logger;

import std.stdio;
import std.file;
import std.string;
import std.datetime;
import std.conv;
import std.path;
import std.format;
import std.array : join;
import debork.core.types;

class Logger {
    private static string logFile = Constants.LOG_FILE;
    private static bool debugMode = false;
    private static bool initialized = false;

    static void initialize(bool debugFlag = false) {
        debugMode = debugFlag;
        initialized = true;

        try {
            // Create log file and write header
            File log = File(logFile, "w");
            log.writeln("=== debork Boot Rescue Tool Log ===");
            log.writeln("Started: " ~ Clock.currTime().toString());
            log.writeln("Debug mode: " ~ (debugMode ? "enabled" : "disabled"));
            log.writeln("----------------------------------------");
            log.close();
        } catch (Exception e) {
            // If we can't write to log file, continue without it
            stderr.writeln("Warning: Could not initialize log file: " ~ e.msg);
        }
    }

    static void debugLog(string message, string file = __FILE__, int line = __LINE__) {
        if (debugMode) {
            writeLog(LogLevel.DEBUG, message, file, line);
        }
    }

    static void info(string message, string file = __FILE__, int line = __LINE__) {
        writeLog(LogLevel.INFO, message, file, line);
    }

    static void warning(string message, string file = __FILE__, int line = __LINE__) {
        writeLog(LogLevel.WARNING, message, file, line);
    }

    static void error(string message, string file = __FILE__, int line = __LINE__) {
        writeLog(LogLevel.ERROR, message, file, line);
    }

    private static void writeLog(LogLevel level, string message, string file, int line) {
        if (!initialized) {
            initialize();
        }

        string timestamp = Clock.currTime().toString();
        string levelStr = levelToString(level);
        string filename = baseName(file);

        // Format: [TIMESTAMP] LEVEL: message (file:line)
        string logMessage;
        if (debugMode) {
            logMessage = format("[%s] %s: %s (%s:%d)",
                               timestamp, levelStr, message, filename, line);
        } else {
            logMessage = format("[%s] %s: %s",
                               timestamp, levelStr, message);
        }

        // Write to console if appropriate level
        if (shouldWriteToConsole(level)) {
            string coloredMessage = colorizeLogLevel(level) ~ levelStr ~ TermColor.RESET ~ ": " ~ message;
            if (debugMode) {
                coloredMessage ~= format(" (%s:%d)", filename, line);
            }
            writeln(coloredMessage);
        }

        // Write to log file
        try {
            File log = File(logFile, "a");
            log.writeln(logMessage);
            log.close();
        } catch (Exception e) {
            // Silently continue if log file write fails
        }
    }

    private static string levelToString(LogLevel level) {
        final switch (level) {
            case LogLevel.DEBUG:   return "DEBUG";
            case LogLevel.INFO:    return "INFO";
            case LogLevel.WARNING: return "WARN";
            case LogLevel.ERROR:   return "ERROR";
        }
    }

    private static string colorizeLogLevel(LogLevel level) {
        final switch (level) {
            case LogLevel.DEBUG:   return TermColor.CYAN;
            case LogLevel.INFO:    return TermColor.BLUE;
            case LogLevel.WARNING: return TermColor.YELLOW;
            case LogLevel.ERROR:   return TermColor.RED;
        }
    }

    private static bool shouldWriteToConsole(LogLevel level) {
        if (debugMode) {
            return true; // Show all levels in debug mode
        }

        // In normal mode, only show warnings and errors to console
        return level == LogLevel.WARNING || level == LogLevel.ERROR;
    }

    // Utility functions for structured logging
    static void logCommand(string[] command, int exitCode, string output = "") {
        string cmdStr = command.join(" ");
        if (exitCode == 0) {
            debugLog("Command succeeded: " ~ cmdStr);
        } else {
            error(format("Command failed (exit %d): %s", exitCode, cmdStr));
            if (output.length > 0) {
                error("Command output: " ~ output);
            }
        }
    }

    static void logMount(string device, string mountPoint, bool success, string errorMsg = "") {
        if (success) {
            info(format("Mounted %s at %s", device, mountPoint));
        } else {
            error(format("Failed to mount %s at %s: %s", device, mountPoint, errorMsg));
        }
    }

    static void logDetection(string component, string result) {
        info(format("Detected %s: %s", component, result));
    }

    static void logStep(string step, bool success, string details = "") {
        if (success) {
            info("✓ " ~ step);
            if (details.length > 0) {
                debugLog("  " ~ details);
            }
        } else {
            error("✗ " ~ step);
            if (details.length > 0) {
                error("  " ~ details);
            }
        }
    }

    // Get log file path for external access
    static string getLogFile() {
        return logFile;
    }

    // Set custom log file path
    static void setLogFile(string path) {
        logFile = path;
    }

    // Enable/disable debug mode
    static void setDebugMode(bool enabled) {
        debugMode = enabled;
        if (initialized) {
            info("Debug mode " ~ (enabled ? "enabled" : "disabled"));
        }
    }

    // Check if debug mode is active
    static bool isDebugMode() {
        return debugMode;
    }

    // Flush any pending log writes
    static void flush() {
        stdout.flush();
    }
}
