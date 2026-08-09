const std = @import("std");
const system = @import("system.zig");

pub fn scanKernels(allocator: std.mem.Allocator, sys: *system.SystemInfo) !void {
    // Clear old kernel list
    for (sys.kernels.items) |*k| k.deinit(allocator);
    sys.kernels.clearRetainingCapacity();

    const boot_path = if (sys.mounted)
        try std.fmt.allocPrint(allocator, "{s}/boot", .{sys.mount_point})
    else
        try allocator.dupe(u8, "/boot");
    defer allocator.free(boot_path);

    var dir = std.fs.cwd().openDir(boot_path, .{ .iterate = true }) catch |err| {
        std.log.warn("Could not open boot directory {s}: {}", .{ boot_path, err });
        return;
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        if (!std.mem.startsWith(u8, entry.name, "vmlinuz")) continue;

        const k_filename = entry.name;
        var k_version: []const u8 = "";

        if (std.mem.startsWith(u8, k_filename, "vmlinuz-")) {
            k_version = k_filename["vmlinuz-".len..];
        } else if (std.mem.eql(u8, k_filename, "vmlinuz")) {
            k_version = "linux";
        }

        // Look for corresponding initramfs
        var initrd_name: []const u8 = "";

        const candidate1 = try std.fmt.allocPrint(allocator, "initramfs-{s}.img", .{k_version});
        defer allocator.free(candidate1);
        const candidate2 = try std.fmt.allocPrint(allocator, "initrd.img-{s}", .{k_version});
        defer allocator.free(candidate2);
        const candidate3 = try std.fmt.allocPrint(allocator, "initramfs-{s}-fallback.img", .{k_version});
        defer allocator.free(candidate3);

        if (dirFileExists(dir, candidate1)) {
            initrd_name = try allocator.dupe(u8, candidate1);
        } else if (dirFileExists(dir, candidate2)) {
            initrd_name = try allocator.dupe(u8, candidate2);
        } else if (dirFileExists(dir, candidate3)) {
            initrd_name = try allocator.dupe(u8, candidate3);
        } else {
            initrd_name = try allocator.dupe(u8, "");
        }

        try sys.kernels.append(allocator, .{
            .version = try allocator.dupe(u8, k_version),
            .path = try allocator.dupe(u8, k_filename),
            .initrd = initrd_name,
            .exists = true,
        });
    }

    // Sort kernels alphabetically by version
    std.mem.sort(system.KernelInfo, sys.kernels.items, {}, sortKernelByVersion);
}

fn dirFileExists(dir: std.fs.Dir, filename: []const u8) bool {
    dir.access(filename, .{}) catch return false;
    return true;
}

fn sortKernelByVersion(_: void, a: system.KernelInfo, b: system.KernelInfo) bool {
    return std.mem.order(u8, a.version, b.version) == .lt;
}
