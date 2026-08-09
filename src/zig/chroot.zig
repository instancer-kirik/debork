const std = @import("std");
const system = @import("system.zig");
const bootloaders = @import("bootloaders.zig");

pub const FixResult = bootloaders.FixResult;

pub fn detectAvailableShell(allocator: std.mem.Allocator, sys: *system.SystemInfo) ![]const u8 {
    const shells = [_][]const u8{
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        "/usr/bin/sh",
        "/bin/dash",
        "/bin/ash",
        "/usr/bin/zsh",
        "/bin/zsh",
        "/usr/bin/fish",
    };

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
    if (fileExists(pacman_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "pacman", "-Syu", "--noconfirm" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "pacman update failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Packages updated successfully via pacman!") };
        } else {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "pacman returned exit code {}", .{res.exit_code}) };
        }
    }

    const apt_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/apt", .{sys.mount_point});
    defer allocator.free(apt_path);
    if (fileExists(apt_path)) {
        const upd = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "apt-get", "update" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "apt-get update failed: {}", .{err}) };
        };
        defer allocator.free(upd.stdout);
        defer allocator.free(upd.stderr);

        const upg = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "apt-get", "upgrade", "-y" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "apt-get upgrade failed: {}", .{err}) };
        };
        defer allocator.free(upg.stdout);
        defer allocator.free(upg.stderr);
        if (upg.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Packages updated successfully via apt-get!") };
        } else {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "apt-get upgrade returned exit code {}", .{upg.exit_code}) };
        }
    }

    const dnf_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/dnf", .{sys.mount_point});
    defer allocator.free(dnf_path);
    if (fileExists(dnf_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "dnf", "upgrade", "-y" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "dnf upgrade failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Packages updated successfully via dnf!") };
        } else {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "dnf upgrade returned exit code {}", .{res.exit_code}) };
        }
    }

    const yum_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/yum", .{sys.mount_point});
    defer allocator.free(yum_path);
    if (fileExists(yum_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "yum", "update", "-y" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "yum update failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Packages updated successfully via yum!") };
        } else {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "yum update returned exit code {}", .{res.exit_code}) };
        }
    }

    const zypper_path = try std.fmt.allocPrint(allocator, "{s}/usr/bin/zypper", .{sys.mount_point});
    defer allocator.free(zypper_path);
    if (fileExists(zypper_path)) {
        const res = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "zypper", "update", "-y" }) catch |err| {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "zypper update failed: {}", .{err}) };
        };
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        if (res.exit_code == 0) {
            return .{ .success = true, .message = try allocator.dupe(u8, "Packages updated successfully via zypper!") };
        } else {
            return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "zypper update returned exit code {}", .{res.exit_code}) };
        }
    }

    return .{ .success = false, .message = try allocator.dupe(u8, "No recognized package manager found in mounted system!") };
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

/// Patch /etc/mkinitcpio.conf inside the chroot: ensure required hooks and
/// modules are present, add btrfs/storage modules as needed.
pub fn ensureMkinitcpioConfig(allocator: std.mem.Allocator, sys: *system.SystemInfo) !FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    const config_path = try std.fmt.allocPrint(allocator, "{s}/etc/mkinitcpio.conf", .{sys.mount_point});
    defer allocator.free(config_path);

    if (!fileExists(config_path)) {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "mkinitcpio.conf not found at {s}", .{config_path}) };
    }

    // Read the config file
    const original_content = std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 1024) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Failed to read mkinitcpio.conf: {}", .{err}) };
    };
    defer allocator.free(original_content);

    var content = try allocator.dupe(u8, original_content);
    defer allocator.free(content);

    var modified = false;

    // --- Patch HOOKS=(...) ---
    if (std.mem.indexOf(u8, content, "HOOKS=(")) |hooks_start| {
        if (std.mem.indexOfPos(u8, content, hooks_start, ")")) |hooks_end| {
            const hooks_line = content[hooks_start .. hooks_end + 1];

            // Build updated hooks line by appending missing hooks inside the parens
            var new_hooks: std.ArrayListUnmanaged(u8) = .empty;
            defer new_hooks.deinit(allocator);
            try new_hooks.appendSlice(allocator, hooks_line);

            const required_hooks = [_][]const u8{ "block", "fsck", "keyboard" };
            for (required_hooks) |hook| {
                if (std.mem.indexOf(u8, new_hooks.items, hook) == null) {
                    // Insert before closing paren
                    const close = std.mem.lastIndexOf(u8, new_hooks.items, ")").?;
                    try new_hooks.insertSlice(allocator, close, &[_]u8{' '});
                    try new_hooks.insertSlice(allocator, close + 1, hook);
                    modified = true;
                }
            }

            if (sys.is_btrfs) {
                if (std.mem.indexOf(u8, new_hooks.items, "btrfs") == null) {
                    const close = std.mem.lastIndexOf(u8, new_hooks.items, ")").?;
                    try new_hooks.insertSlice(allocator, close, " btrfs");
                    modified = true;
                }
            }

            if (!std.mem.eql(u8, new_hooks.items, hooks_line)) {
                // Replace the hooks line in content
                const new_content = try std.mem.replaceOwned(u8, allocator, content, hooks_line, new_hooks.items);
                allocator.free(content);
                content = new_content;
            }
        }
    }

    // --- Patch MODULES=(...) ---
    if (std.mem.indexOf(u8, content, "MODULES=(")) |mods_start| {
        if (std.mem.indexOfPos(u8, content, mods_start, ")")) |mods_end| {
            const mods_line = content[mods_start .. mods_end + 1];

            var new_mods: std.ArrayListUnmanaged(u8) = .empty;
            defer new_mods.deinit(allocator);
            try new_mods.appendSlice(allocator, mods_line);

            // btrfs modules
            if (sys.is_btrfs) {
                for ([_][]const u8{ "btrfs", "crc32c" }) |mod| {
                    if (std.mem.indexOf(u8, new_mods.items, mod) == null) {
                        try appendModule(allocator, &new_mods, mod);
                        modified = true;
                    }
                }
            }

            // Storage modules detected via lspci
            const storage_mods = detectStorageModules(allocator) catch &[_][]const u8{};
            defer {
                for (storage_mods) |m| allocator.free(m);
                allocator.free(storage_mods);
            }
            for (storage_mods) |mod| {
                if (std.mem.indexOf(u8, new_mods.items, mod) == null) {
                    try appendModule(allocator, &new_mods, mod);
                    modified = true;
                }
            }

            if (!std.mem.eql(u8, new_mods.items, mods_line)) {
                const new_content = try std.mem.replaceOwned(u8, allocator, content, mods_line, new_mods.items);
                allocator.free(content);
                content = new_content;
            }
        }
    }

    if (!modified) {
        return .{ .success = true, .message = try allocator.dupe(u8, "mkinitcpio.conf already has all required hooks and modules.") };
    }

    // Back up the original
    const backup_path = try std.fmt.allocPrint(allocator, "{s}/etc/mkinitcpio.conf.bak", .{sys.mount_point});
    defer allocator.free(backup_path);
    std.fs.cwd().writeFile(.{ .sub_path = backup_path, .data = original_content }) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Failed to write backup mkinitcpio.conf.bak: {}", .{err}) };
    };

    // Write the patched config
    std.fs.cwd().writeFile(.{ .sub_path = config_path, .data = content }) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Failed to write mkinitcpio.conf: {}", .{err}) };
    };

    return .{ .success = true, .message = try allocator.dupe(u8, "mkinitcpio.conf updated with required hooks and modules.") };
}

/// Returns true if the mounted path looks like a valid Linux root.
pub fn validateChrootEnvironment(allocator: std.mem.Allocator, sys: *system.SystemInfo) bool {
    if (!sys.mounted) return false;

    // Essential directories — require bin, usr/bin, etc, and lib or usr/lib
    const required_dirs = [_][]const u8{ "bin", "usr/bin", "etc" };
    for (required_dirs) |rel| {
        const full = std.fmt.allocPrint(allocator, "{s}/{s}", .{ sys.mount_point, rel }) catch return false;
        defer allocator.free(full);
        if (!dirExists(full)) return false;
    }

    // Need lib or usr/lib
    const lib_ok = blk: {
        for ([_][]const u8{ "lib", "usr/lib" }) |rel| {
            const full = std.fmt.allocPrint(allocator, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
            defer allocator.free(full);
            if (dirExists(full)) break :blk true;
        }
        break :blk false;
    };
    if (!lib_ok) return false;

    // At least one sign of a populated system
    const markers = [_][]const u8{ "etc/passwd", "usr/bin/ls", "bin/sh", "usr/bin/bash" };
    for (markers) |rel| {
        const full = std.fmt.allocPrint(allocator, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
        defer allocator.free(full);
        if (fileExists(full)) return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Append a module name into an ArrayList that holds the current "MODULES=(...)" string.
fn appendModule(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), mod: []const u8) !void {
    // Find last ')' and insert before it, with a leading space.
    const close = std.mem.lastIndexOf(u8, buf.items, ")") orelse return;
    // If the parens are empty "MODULES=()" just write the name, else prepend a space.
    const inner_start = std.mem.indexOf(u8, buf.items, "(").? + 1;
    const inner = std.mem.trim(u8, buf.items[inner_start..close], " \t");
    if (inner.len == 0) {
        try buf.insertSlice(allocator, close, mod);
    } else {
        var tmp: std.ArrayListUnmanaged(u8) = .empty;
        defer tmp.deinit(allocator);
        try tmp.append(allocator, ' ');
        try tmp.appendSlice(allocator, mod);
        try buf.insertSlice(allocator, close, tmp.items);
    }
}

/// Run `lspci -k` and infer which storage kernel modules are needed.
/// Caller owns the returned slice and each string within it.
fn detectStorageModules(allocator: std.mem.Allocator) ![][]const u8 {
    var mods: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (mods.items) |m| allocator.free(m);
        mods.deinit(allocator);
    }

    const lspci = system.executeCmd(allocator, &.{ "lspci", "-k" }) catch return mods.toOwnedSlice();
    defer allocator.free(lspci.stdout);
    defer allocator.free(lspci.stderr);

    if (lspci.exit_code != 0) return mods.toOwnedSlice(allocator);

    const output = lspci.stdout;

    // NVMe
    if (std.ascii.indexOfIgnoreCase(output, "nvme") != null) {
        try mods.append(allocator, try allocator.dupe(u8, "nvme"));
    }

    // AHCI / SATA
    if (std.ascii.indexOfIgnoreCase(output, "ahci") != null) {
        try mods.append(allocator, try allocator.dupe(u8, "ahci"));
    }

    // VirtIO
    if (std.ascii.indexOfIgnoreCase(output, "virtio") != null) {
        try mods.append(allocator, try allocator.dupe(u8, "virtio_blk"));
        try mods.append(allocator, try allocator.dupe(u8, "virtio_pci"));
    }

    return mods.toOwnedSlice(allocator);
}

fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn dirExists(path: []const u8) bool {
    var d = std.fs.openDirAbsolute(path, .{}) catch return false;
    d.close();
    return true;
}
