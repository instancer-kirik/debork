const std = @import("std");
const types = @import("types.zig");

var debug_mode: bool = false;

pub fn init(enable_debug: bool) void {
    debug_mode = enable_debug;
    const file = std.fs.createFileAbsolute(types.LOG_FILE, .{}) catch return;
    defer file.close();
    file.writeAll("=== debork session log ===\n") catch {};
}

pub fn info(msg: []const u8) void {
    write("INFO", msg);
}
pub fn warn(msg: []const u8) void {
    write("WARN", msg);
}
pub fn err(msg: []const u8) void {
    write("ERROR", msg);
}
pub fn debug(msg: []const u8) void {
    write("DEBUG", msg);
}

fn write(level: []const u8, msg: []const u8) void {
    var line_buf: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "[{s}] {s}\n", .{ level, msg }) catch return;

    const file = std.fs.openFileAbsolute(types.LOG_FILE, .{ .mode = .write_only }) catch return;
    defer file.close();
    file.seekFromEnd(0) catch {};
    file.writeAll(line) catch {};

    if (debug_mode or std.mem.eql(u8, level, "ERROR") or std.mem.eql(u8, level, "WARN")) {
        std.fs.File.stderr().writeAll(line) catch {};
    }
}
