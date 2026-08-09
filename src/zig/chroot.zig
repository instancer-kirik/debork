const std = @import("std");
const system = @import("system.zig");
const bootloaders = @import("bootloaders.zig");

pub const FixResult = bootloaders.FixResult;

pub fn detectAvailableShell(allocator: std.mem.Allocator, sys: *system.SystemInfo) ![]const u8 {
    const shells = [_][]const u8{ "/bin/bash", "/bin/sh", "/usr/bin/bash", "/bin/dash", "/bin/ash" };

    for (shells) |sh| {
        const full_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, sh });
        defer allocator.free(full_path);

        if (fileExists(full_path)) {
            return try allocator.dupe(u8, sh);
        }
    }
    return error.NoShellFound;
}

pub fn regenerateInitramfs(allocator: std.mem.Allocator, sys: *system.SystemInfo) !FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    // Check mkinitcpio (Arch)
    const mkinit_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/mkinitcpio", .{sys.mount_point});
    defer allocator.free(mkinit_path);

    if (fileExists(mkinit_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "mkinitcpio", "-P" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "mkinitcpio failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);

        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Initramfs regenerated via mkinitcpio -P!") };
        }
    }

    // Check dracut (Fedora/RHEL)
    const dracut_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/dracut", .{sys.mount_point});
    defer allocator.free(dracut_path);

    if (fileExists(dracut_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "dracut", "-f", "--regenerate-all" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "dracut failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);

        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Initramfs regenerated via dracut!") };
        }
    }

    // Check update-initramfs (Debian/Ubuntu)
    const uinit_path = try std.fmt.allocPrint(allocator, "{s}/usr/sbin/update-initramfs", .{sys.mount_point});
    defer allocator.free(uinit_path);

    if (fileExists(uinit_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "update-initramfs", "-u", "-k", "all" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "update-initramfs failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);

        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Initramfs regenerated via update-initramfs!") };
        }
    }

    return .{ .success = false, .message = try allocator.dupe(u8, "No supported initramfs generator found in chroot!") };
}

pub fn updateSystemPackages(allocator: std.mem.Allocator, sys: *system.SystemInfo) !FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    const pacman_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/pacman", .{sys.mount_point});
    defer allocator.free(pacman_path);

    if (!fileExists(pacman_path)) {
        return .{ .success = false, .message = try allocator.dupe(u8, "pacman not found in mounted system!") };
    }

    const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "pacman", "-Syyu", "--noconfirm" }) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "pacman update failed: {}", .{err}) };
    };
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    if (res.exit_code == 0) {
        return .{ .success = true, .message = try allocator.dupe(u8, "Packages updated successfully via pacman -Syyu!") };
    } else {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "pacman returned exit code {}", .{res.exit_code}) };
    }
}

pub fn launchEmergencyShell(allocator: std.mem.Allocator, sys: *system.SystemInfo) void {
    const sh = detectAvailableShell(allocator, sys) catch "/bin/bash";
    defer if (!std.mem.eql(u8, sh, "/bin/bash")) allocator.free(sh);

    var child = if (sys.mounted)
        std.process.Child.init(&.{ "chroot", sys.mount_point, sh }, allocator)
    else
        std.process.Child.init(&.{"/bin/bash"}, allocator);

    _ = child.spawnAndWait() catch {};
}

/// Fix pacman package cache — removes stale download-XXXXXX temp dirs and
/// optionally clears old package files. Works on the live system (no chroot needed).
pub fn fixPacmanCache(allocator: std.mem.Allocator) !FixResult {
    const pkg_cache = "/var/cache/pacman/pkg";
    var removed: usize = 0;
    var errors: usize = 0;

    var dir = std.fs.openDirAbsolute(pkg_cache, .{ .iterate = true }) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Cannot open {s}: {}", .{ pkg_cache, err }) };
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
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Removed {d} stale pacman temp dir(s), {d} could not be removed (permission error?)", .{ removed, errors }) };
    }
    if (removed == 0) {
        return .{ .success = true, .message = try allocator.dupe(u8, "No stale pacman temp dirs found — cache is clean!") };
    }
    return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "Removed {d} stale pacman temp dir(s) from {s}", .{ removed, pkg_cache }) };
}

fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}
