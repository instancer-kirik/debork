const std = @import("std");
const types = @import("../core/types.zig");
const log = @import("../core/logger.zig");

/// Shell preference order matching the D version.
const SHELLS = [_][]const u8{
    "/bin/bash",     "/usr/bin/bash",
    "/bin/sh",       "/usr/bin/sh",
    "/bin/dash",     "/bin/ash",
    "/usr/bin/zsh",  "/bin/zsh",
    "/usr/bin/fish",
};

/// Return the best available shell inside the mounted system.
/// Caller owns the returned string.
pub fn detectShell(allocator: std.mem.Allocator, sys: *types.SystemInfo) ![]const u8 {
    for (SHELLS) |sh| {
        const full = try std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, sh });
        defer allocator.free(full);
        if (types.fileExists(full)) return allocator.dupe(u8, sh);
    }
    return error.NoShellFound;
}

/// Spawn an interactive chroot shell and block until the user exits.
pub fn launchShell(allocator: std.mem.Allocator, sys: *types.SystemInfo) void {
    const sh = detectShell(allocator, sys) catch "/bin/bash";
    defer if (!std.mem.eql(u8, sh, "/bin/bash")) allocator.free(sh);

    var child = if (sys.mounted)
        std.process.Child.init(&.{ "chroot", sys.mount_point, sh, "-l" }, allocator)
    else
        std.process.Child.init(&.{"/bin/bash"}, allocator);

    _ = child.spawnAndWait() catch {};
}

/// Validate that the mounted path is a usable Linux root.
pub fn validateEnvironment(allocator_unused: std.mem.Allocator, sys: *types.SystemInfo) bool {
    _ = allocator_unused;
    if (!sys.mounted) return false;
    const required = [_][]const u8{ "bin", "usr/bin", "etc" };
    for (required) |rel| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, rel }) catch return false;
        if (!types.dirExists(p)) return false;
    }
    // Need lib or usr/lib
    const lib_ok = for ([_][]const u8{ "lib", "usr/lib" }) |rel| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
        if (types.dirExists(p)) break true;
    } else false;
    if (!lib_ok) return false;
    // At least one system marker
    const markers = [_][]const u8{ "etc/passwd", "usr/bin/ls", "bin/sh", "usr/bin/bash" };
    for (markers) |rel| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
        if (types.fileExists(p)) return true;
    }
    return false;
}

/// Regenerate initramfs using the first available tool: mkinitcpio → dracut → update-initramfs.
pub fn regenerateInitramfs(allocator: std.mem.Allocator, sys: *types.SystemInfo) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    const tools = [_]struct {
        bin: []const u8,
        argv: []const []const u8,
        label: []const u8,
    }{
        .{ .bin = "/usr/bin/mkinitcpio", .argv = &.{ "chroot", "_MP_", "mkinitcpio", "-P" }, .label = "mkinitcpio -P" },
        .{ .bin = "/usr/bin/dracut", .argv = &.{ "chroot", "_MP_", "dracut", "-f", "--regenerate-all" }, .label = "dracut" },
        .{ .bin = "/usr/sbin/update-initramfs", .argv = &.{ "chroot", "_MP_", "update-initramfs", "-u", "-k", "all" }, .label = "update-initramfs" },
    };

    for (tools) |tool| {
        var path_buf: [512]u8 = undefined;
        const bin = std.fmt.bufPrint(&path_buf, "{s}{s}", .{ sys.mount_point, tool.bin }) catch continue;
        if (!types.fileExists(bin)) continue;

        // Replace the "_MP_" placeholder with the real mount point
        var argv: std.ArrayListUnmanaged([]const u8) = .empty;
        defer argv.deinit(allocator);
        for (tool.argv) |arg| {
            if (std.mem.eql(u8, arg, "_MP_")) {
                try argv.append(allocator, sys.mount_point);
            } else {
                try argv.append(allocator, arg);
            }
        }

        const res = types.executeCmd(allocator, argv.items) catch |e| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "{s} failed: {}", .{ tool.label, e }) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);

        if (res.exit_code == 0) {
            return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "Initramfs regenerated via {s}!", .{tool.label}) };
        }
    }
    return .{ .success = false, .message = try allocator.dupe(u8, "No initramfs generator found in mounted system!") };
}

/// Update packages using the detected package manager.
pub fn updatePackages(allocator: std.mem.Allocator, sys: *types.SystemInfo) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    switch (sys.pkg_manager) {
        .pacman => return runChroot(allocator, sys, &.{ "pacman", "-Syu", "--noconfirm" }, "pacman"),
        .apt => {
            const r = try runChroot(allocator, sys, &.{ "apt-get", "update" }, "apt-get update");
            if (!r.success) return r;
            allocator.free(r.message);
            return runChroot(allocator, sys, &.{ "apt-get", "upgrade", "-y" }, "apt-get upgrade");
        },
        .dnf => return runChroot(allocator, sys, &.{ "dnf", "upgrade", "-y" }, "dnf"),
        .yum => return runChroot(allocator, sys, &.{ "yum", "update", "-y" }, "yum"),
        .zypper => return runChroot(allocator, sys, &.{ "zypper", "update", "-y" }, "zypper"),
        .unknown => return .{ .success = false, .message = try allocator.dupe(u8, "No supported package manager found!") },
    }
}

/// Patch /etc/mkinitcpio.conf: add required HOOKS and storage MODULES.
pub fn ensureMkinitcpioConfig(allocator: std.mem.Allocator, sys: *types.SystemInfo) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System not mounted!") };

    const config_path = try std.fmt.allocPrint(allocator, "{s}/etc/mkinitcpio.conf", .{sys.mount_point});
    defer allocator.free(config_path);

    if (!types.fileExists(config_path)) {
        return .{ .success = false, .message = try allocator.dupe(u8, "mkinitcpio.conf not found — not an Arch-based system?") };
    }

    const original = try std.fs.cwd().readFileAlloc(allocator, config_path, 512 * 1024);
    defer allocator.free(original);

    var patched = try allocator.dupe(u8, original);
    defer allocator.free(patched);

    var modified = false;

    // Patch HOOKS=(...)
    patched = try patchList(allocator, patched, "HOOKS=(", hooksRequired(sys), &modified);

    // Patch MODULES=(...)
    const storage_mods = try detectStorageModules(allocator);
    defer {
        for (storage_mods) |m| allocator.free(m);
        allocator.free(storage_mods);
    }
    var extra_mods: std.ArrayListUnmanaged([]const u8) = .empty;
    defer extra_mods.deinit(allocator);
    if (sys.is_btrfs) {
        try extra_mods.append(allocator, "btrfs");
        try extra_mods.append(allocator, "crc32c");
    }
    for (storage_mods) |m| try extra_mods.append(allocator, m);

    patched = try patchList(allocator, patched, "MODULES=(", extra_mods.items, &modified);

    if (!modified) {
        return .{ .success = true, .message = try allocator.dupe(u8, "mkinitcpio.conf already has all required hooks/modules") };
    }

    // Write backup
    const bak = try std.fmt.allocPrint(allocator, "{s}.bak", .{config_path});
    defer allocator.free(bak);
    std.fs.cwd().writeFile(.{ .sub_path = bak, .data = original }) catch {};

    // Write patched
    try std.fs.cwd().writeFile(.{ .sub_path = config_path, .data = patched });

    return .{ .success = true, .message = try allocator.dupe(u8, "mkinitcpio.conf updated with required hooks/modules") };
}

/// Fix stale pacman package cache temp dirs.
pub fn fixPacmanCache(allocator: std.mem.Allocator) !types.FixResult {
    const pkg_cache = "/var/cache/pacman/pkg";
    var removed: usize = 0;
    var errors: usize = 0;

    var dir = std.fs.openDirAbsolute(pkg_cache, .{ .iterate = true }) catch |e| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Cannot open {s}: {}", .{ pkg_cache, e }) };
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.startsWith(u8, entry.name, "download-")) continue;
        dir.deleteTree(entry.name) catch {
            errors += 1;
            continue;
        };
        removed += 1;
    }

    if (errors > 0) {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Removed {d} temp dirs, {d} failed", .{ removed, errors }) };
    }
    if (removed == 0) {
        return .{ .success = true, .message = try allocator.dupe(u8, "Pacman cache is already clean") };
    }
    return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "Removed {d} stale pacman temp dir(s)", .{removed}) };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn runChroot(allocator: std.mem.Allocator, sys: *types.SystemInfo, cmd: []const []const u8, label: []const u8) !types.FixResult {
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, "chroot");
    try argv.append(allocator, sys.mount_point);
    for (cmd) |a| try argv.append(allocator, a);

    const res = types.executeCmd(allocator, argv.items) catch |e| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "{s} failed: {}", .{ label, e }) };
    };
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    if (res.exit_code == 0) {
        return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "{s} completed successfully", .{label}) };
    }
    return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "{s} exited with code {d}", .{ label, res.exit_code }) };
}

fn hooksRequired(sys: *types.SystemInfo) []const []const u8 {
    if (sys.is_btrfs) {
        return &[_][]const u8{ "block", "fsck", "keyboard", "btrfs" };
    }
    return &[_][]const u8{ "block", "fsck", "keyboard" };
}

/// Find the `KEY=(...)` group in `src`, insert any missing `items`, return new string.
/// Sets `*modified` to true if anything changed. Caller owns the returned slice.
fn patchList(
    allocator: std.mem.Allocator,
    src: []u8,
    key: []const u8,
    items: []const []const u8,
    modified: *bool,
) ![]u8 {
    const start = std.mem.indexOf(u8, src, key) orelse return allocator.dupe(u8, src);
    const end = std.mem.indexOfPos(u8, src, start, ")") orelse return allocator.dupe(u8, src);

    const original_group = src[start .. end + 1];

    // Build new group
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, original_group);

    for (items) |item| {
        if (std.mem.indexOf(u8, buf.items, item) != null) continue;
        // Insert before closing ')'
        const close = std.mem.lastIndexOf(u8, buf.items, ")").?;
        // Determine separator (space or nothing if empty)
        const inner_start = std.mem.indexOf(u8, buf.items, "(").? + 1;
        const inner = std.mem.trim(u8, buf.items[inner_start..close], " \t");
        if (inner.len > 0) {
            try buf.insertSlice(allocator, close, " ");
            try buf.insertSlice(allocator, close + 1, item);
        } else {
            try buf.insertSlice(allocator, close, item);
        }
        modified.* = true;
    }

    if (std.mem.eql(u8, buf.items, original_group)) return allocator.dupe(u8, src);

    return std.mem.replaceOwned(u8, allocator, src, original_group, buf.items);
}

fn detectStorageModules(allocator: std.mem.Allocator) ![][]const u8 {
    var mods: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (mods.items) |m| allocator.free(m);
        mods.deinit(allocator);
    }

    const res = types.executeCmd(allocator, &.{ "lspci", "-k" }) catch
        return mods.toOwnedSlice(allocator);
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    if (res.exit_code != 0) return mods.toOwnedSlice(allocator);
    const out = res.stdout;

    if (std.ascii.indexOfIgnoreCase(out, "nvme") != null) try mods.append(allocator, try allocator.dupe(u8, "nvme"));
    if (std.ascii.indexOfIgnoreCase(out, "ahci") != null) try mods.append(allocator, try allocator.dupe(u8, "ahci"));
    if (std.ascii.indexOfIgnoreCase(out, "virtio") != null) {
        try mods.append(allocator, try allocator.dupe(u8, "virtio_blk"));
        try mods.append(allocator, try allocator.dupe(u8, "virtio_pci"));
    }

    return mods.toOwnedSlice(allocator);
}
