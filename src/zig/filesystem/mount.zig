const std = @import("std");
const types = @import("../core/types.zig");
const log = @import("../core/logger.zig");
const btrfs = @import("btrfs.zig");

/// Full system mount: fstype detection → mount (btrfs-aware) → bind mounts →
/// EFI partition → network config copy.
pub fn mountSystem(allocator: std.mem.Allocator, sys: *types.SystemInfo, device: []const u8) !bool {
    if (sys.mounted) return true;

    std.fs.cwd().makePath(sys.mount_point) catch {};

    // Detect filesystem type
    const fstype = detectFstype(allocator, device) orelse "";
    if (fstype.len > 0) {
        sys.fstype = try allocator.dupe(u8, fstype);
        sys.is_btrfs = std.mem.eql(u8, fstype, "btrfs");
    }

    // Mount root
    if (sys.is_btrfs) {
        var subvol: []const u8 = "";
        const ok = btrfs.mount(allocator, device, sys.mount_point, &subvol) catch false;
        if (!ok) return false;
        if (subvol.len > 0) sys.root_subvol = subvol;
    } else {
        const res = try types.executeCmd(allocator, &.{ "mount", device, sys.mount_point });
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        if (res.exit_code != 0) return false;
    }

    sys.device = try allocator.dupe(u8, device);
    sys.boot_dir = try std.fmt.allocPrint(allocator, "{s}/boot", .{sys.mount_point});
    sys.efi_dir = try allocator.dupe(u8, sys.boot_dir);
    sys.mounted = true;

    // UUID
    sys.uuid = detectUuid(allocator, device) orelse try allocator.dupe(u8, "");

    // Bind mount /dev /proc /sys /run
    const bind_dirs = [_][]const u8{ "/dev", "/proc", "/sys", "/run" };
    for (bind_dirs) |dir| {
        const target = try std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, dir });
        defer allocator.free(target);
        std.fs.cwd().makePath(target) catch {};
        const res = types.executeCmd(allocator, &.{ "mount", "--bind", dir, target }) catch continue;
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    }

    // EFI partition
    mountEfi(allocator, sys);

    // Network config for chroot package updates
    const net_files = [_][]const u8{ "resolv.conf", "hosts" };
    for (net_files) |f| {
        const src = std.fmt.allocPrint(allocator, "/etc/{s}", .{f}) catch continue;
        defer allocator.free(src);
        const dst = std.fmt.allocPrint(allocator, "{s}/etc/{s}", .{ sys.mount_point, f }) catch continue;
        defer allocator.free(dst);
        std.fs.cwd().copyFile(src, std.fs.cwd(), dst, .{}) catch {};
    }

    log.info("System mounted successfully");
    return true;
}

pub fn unmountSystem(allocator: std.mem.Allocator, sys: *types.SystemInfo) void {
    if (!sys.mounted) return;

    // Reverse order
    const bind_dirs = [_][]const u8{ "/run", "/sys", "/proc", "/dev" };
    for (bind_dirs) |dir| {
        const target = std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, dir }) catch continue;
        defer allocator.free(target);
        const res = types.executeCmd(allocator, &.{ "umount", target }) catch continue;
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    }

    // EFI
    if (!std.mem.eql(u8, sys.efi_dir, sys.boot_dir) and sys.efi_dir.len > 0) {
        const res = types.executeCmd(allocator, &.{ "umount", sys.efi_dir }) catch null;
        if (res) |r| {
            allocator.free(r.stdout);
            allocator.free(r.stderr);
        }
    }

    // Root — try normal then lazy
    const root_res = types.executeCmd(allocator, &.{ "umount", sys.mount_point }) catch null;
    if (root_res) |r| {
        defer allocator.free(r.stdout);
        defer allocator.free(r.stderr);
        if (r.exit_code != 0) {
            const lazy = types.executeCmd(allocator, &.{ "umount", "-l", sys.mount_point }) catch null;
            if (lazy) |lr| {
                allocator.free(lr.stdout);
                allocator.free(lr.stderr);
            }
        }
    }

    sys.mounted = false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn detectFstype(allocator: std.mem.Allocator, device: []const u8) ?[]const u8 {
    const res = types.executeCmd(allocator, &.{ "blkid", "-s", "TYPE", "-o", "value", device }) catch return null;
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);
    if (res.exit_code != 0) return null;
    const t = std.mem.trim(u8, res.stdout, " \t\r\n");
    if (t.len == 0) return null;
    // Return a static string so caller doesn't need to free
    if (std.mem.eql(u8, t, "btrfs")) return "btrfs";
    if (std.mem.eql(u8, t, "ext4")) return "ext4";
    if (std.mem.eql(u8, t, "ext3")) return "ext3";
    if (std.mem.eql(u8, t, "ext2")) return "ext2";
    if (std.mem.eql(u8, t, "xfs")) return "xfs";
    if (std.mem.eql(u8, t, "f2fs")) return "f2fs";
    return null;
}

fn detectUuid(allocator: std.mem.Allocator, device: []const u8) ?[]const u8 {
    const res = types.executeCmd(allocator, &.{ "blkid", "-s", "UUID", "-o", "value", device }) catch return null;
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);
    if (res.exit_code != 0) return null;
    const u = std.mem.trim(u8, res.stdout, " \t\r\n");
    if (u.len == 0) return null;
    return allocator.dupe(u8, u) catch null;
}

fn mountEfi(allocator: std.mem.Allocator, sys: *types.SystemInfo) void {
    const candidates = [_][]const u8{ "boot/efi", "efi", "boot/EFI" };
    for (candidates) |rel| {
        var buf: [512]u8 = undefined;
        const efi_path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
        if (!types.dirExists(efi_path)) continue;

        // Find the vfat EFI device via findmnt
        const fm = types.executeCmd(allocator, &.{ "findmnt", "-n", "-o", "SOURCE", "-t", "vfat", "/boot/efi" }) catch null;
        if (fm) |r| {
            defer allocator.free(r.stdout);
            defer allocator.free(r.stderr);
            const efi_dev = std.mem.trim(u8, r.stdout, " \t\r\n");
            if (r.exit_code == 0 and efi_dev.len > 0) {
                const mres = types.executeCmd(allocator, &.{ "mount", efi_dev, efi_path }) catch null;
                if (mres) |mr| {
                    defer allocator.free(mr.stdout);
                    defer allocator.free(mr.stderr);
                    if (mr.exit_code == 0) {
                        if (sys.efi_dir.len > 0) allocator.free(sys.efi_dir);
                        sys.efi_dir = allocator.dupe(u8, efi_path) catch sys.efi_dir;
                        return;
                    }
                }
            }
        }
        break;
    }
}
