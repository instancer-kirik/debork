const std = @import("std");
const posix = std.posix;
const tui = @import("tui.zig");
const system = @import("system.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var demo_mode = false;
    var debug_mode = false;
    var target_device: ?[]const u8 = null;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--demo") or std.mem.eql(u8, arg, "-d")) {
            demo_mode = true;
        } else if (std.mem.eql(u8, arg, "--debug")) {
            debug_mode = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printHelp();
            return;
        } else if (std.mem.startsWith(u8, arg, "/dev/")) {
            target_device = arg;
        }
    }

    const is_root = (posix.system.getuid() == 0);

    if (!is_root and !demo_mode) {
        const stdout = std.fs.File.stdout();
        _ = stdout.writeAll(tui.COLOR_AMBER ++ "⚠ Warning: debork requires root privileges to mount partitions and fix bootloaders!\n" ++
            tui.COLOR_TEXT ++ "Running with --demo mode to demonstrate the interface safely.\n" ++
            "To repair system partitions, run with: " ++ tui.COLOR_FUCHSIA ++ "sudo ./debork" ++ tui.RESET ++ "\n\n") catch {};
        demo_mode = true;
        std.Thread.sleep(1500 * std.time.ns_per_ms);
    }

    var app = tui.CuteTUI.init(allocator, demo_mode, debug_mode);
    defer app.deinit();

    if (target_device) |dev| {
        _ = try system.mountSystem(allocator, &app.sys_info, dev);
    }

    if (demo_mode) {
        app.setStatus("Running in Safe Demo Mode!", 0);
    }

    try app.run();
}

fn printHelp() void {
    const stdout = std.fs.File.stdout();
    _ = stdout.writeAll(
        \\debork v2.0 - Cross-Platform Linux Boot Rescue Tool (Zig Edition)
        \\
        \\Usage:
        \\  debork [OPTIONS] [DEVICE]
        \\
        \\Options:
        \\  --demo, -d      Run in interactive safe demo mode (no root required)
        \\  --debug         Enable debug logging to /tmp/debork.log
        \\  --help, -h      Display this help message
        \\
        \\Examples:
        \\  sudo debork             # Interactive rescue mode
        \\  sudo debork /dev/sda2   # Mount /dev/sda2 directly and start repair
        \\  debork --demo           # Test cute dark & fusian purple TUI safely
        \\
    ) catch {};
}
