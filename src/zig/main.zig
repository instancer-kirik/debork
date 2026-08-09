const std = @import("std");
const posix = std.posix;
const types = @import("core/types.zig");
const log = @import("core/logger.zig");
const mount = @import("filesystem/mount.zig");
const detection = @import("system/detection.zig");
const tui = @import("ui/tui.zig");

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

    log.init(debug_mode);

    const is_root = (posix.system.getuid() == 0);
    if (!is_root and !demo_mode) {
        const out = std.fs.File.stdout();
        _ = out.writeAll(tui.COLOR_AMBER ++ "Warning: root is required to mount partitions and fix bootloaders.\n" ++
            tui.COLOR_TEXT ++ "Starting in --demo mode. Run with sudo to repair.\n\n" ++ tui.RESET) catch {};
        demo_mode = true;
        std.Thread.sleep(1500 * std.time.ns_per_ms);
    }

    var app = tui.CuteTUI.init(allocator, demo_mode, debug_mode);
    defer app.deinit();

    if (target_device) |dev| {
        const ok = mount.mountSystem(allocator, &app.sys_info, dev) catch false;
        if (ok) {
            detection.detectBootLoader(allocator, &app.sys_info);
            detection.detectDistribution(allocator, &app.sys_info);
            detection.detectPackageManager(allocator, &app.sys_info);
            detection.scanKernels(allocator, &app.sys_info) catch {};
        }
    }

    if (demo_mode) app.setStatus("Running in Safe Demo Mode!", 0);

    try app.run();
}

fn printHelp() void {
    _ = std.fs.File.stdout().writeAll(
        \\debork v2.0 - Cross-Platform Linux Boot Rescue Tool
        \\
        \\Usage:
        \\  debork [OPTIONS] [DEVICE]
        \\
        \\Options:
        \\  --demo, -d    Run in demo mode (no root required)
        \\  --debug       Enable debug logging to /tmp/debork.log
        \\  --help, -h    Show this help
        \\
        \\Examples:
        \\  sudo debork               # Interactive rescue
        \\  sudo debork /dev/sda2     # Mount /dev/sda2 and start repair
        \\  debork --demo             # Test TUI safely
        \\
    ) catch {};
}
