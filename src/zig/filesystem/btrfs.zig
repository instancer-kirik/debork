const std = @import("std");
const types = @import("../core/types.zig");
const log = @import("../core/logger.zig");

/// Mount a btrfs device, auto-detecting the root subvolume.
/// Falls back to plain mount if detection fails.
pub fn mount(allocator: std.mem.Allocator, device: []const u8, mount_point: []const u8, root_subvol_out: *[]const u8) !bool {
    log.info("btrfs: detecting root subvolume");

    const subvol = detectRootSubvol(allocator, device) catch null;
    defer if (subvol) |s| allocator.free(s);

    if (subvol) |s| {
        log.info("btrfs: trying detected subvol");
        if (try tryMount(allocator, device, mount_point, s)) {
            root_subvol_out.* = try allocator.dupe(u8, s);
            try mountAdditionalSubvols(allocator, device, mount_point);
            return true;
        }
    }

    // Fallback: try "@" (CachyOS / Arch default)
    log.info("btrfs: trying @ subvol fallback");
    if (try tryMount(allocator, device, mount_point, "@")) {
        root_subvol_out.* = try allocator.dupe(u8, "@");
        try mountAdditionalSubvols(allocator, device, mount_point);
        return true;
    }

    // Last resort: plain mount, no subvol
    log.info("btrfs: plain mount fallback");
    const res = types.executeCmd(allocator, &.{ "mount", device, mount_point }) catch return false;
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);
    if (res.exit_code == 0) {
        root_subvol_out.* = "";
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/// Temp-mount the device read-only, list subvolumes, unmount, return best root.
/// Caller owns the returned string.
fn detectRootSubvol(allocator: std.mem.Allocator, device: []const u8) ![]const u8 {
    const tmp = types.BTRFS_DETECT_DIR;
    std.fs.cwd().makePath(tmp) catch {};
    defer {
        const r = types.executeCmd(allocator, &.{ "umount", "-l", tmp }) catch null;
        if (r) |rr| {
            allocator.free(rr.stdout);
            allocator.free(rr.stderr);
        }
    }

    const mres = types.executeCmd(allocator, &.{ "mount", "-o", "ro", device, tmp }) catch return error.MountFailed;
    defer allocator.free(mres.stdout);
    defer allocator.free(mres.stderr);
    if (mres.exit_code != 0) return error.MountFailed;

    const lres = types.executeCmd(allocator, &.{ "btrfs", "subvolume", "list", tmp }) catch return error.ListFailed;
    defer allocator.free(lres.stdout);
    defer allocator.free(lres.stderr);
    if (lres.exit_code != 0) return error.ListFailed;

    return pickRootSubvol(allocator, lres.stdout);
}

const SubvolEntry = struct { path: []const u8, top_level: u64 };

/// Three-pass heuristic matching the D version:
///   1. Exact name: @  root  rootfs  @rootfs  /
///   2. Contains "root" but not home/var/tmp/cache/log
///   3. top_level == 5
fn pickRootSubvol(allocator: std.mem.Allocator, list_output: []const u8) ![]const u8 {
    var entries: std.ArrayListUnmanaged(SubvolEntry) = .empty;
    defer entries.deinit(allocator);

    var lines = std.mem.splitScalar(u8, list_output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        // Format: "ID N gen N top level N path PATH"
        var toks = std.mem.tokenizeScalar(u8, line, ' ');
        var idx: usize = 0;
        var top_level: u64 = 0;
        var path: []const u8 = "";
        while (toks.next()) |tok| : (idx += 1) {
            if (idx == 4) top_level = std.fmt.parseInt(u64, tok, 10) catch 0;
            if (idx == 8) path = tok;
        }
        if (path.len > 0) try entries.append(allocator, .{ .path = path, .top_level = top_level });
    }

    const exact = [_][]const u8{ "@", "root", "rootfs", "@rootfs", "/" };
    for (entries.items) |e| {
        for (exact) |name| {
            if (std.mem.eql(u8, e.path, name)) return allocator.dupe(u8, e.path);
        }
    }

    const deny = [_][]const u8{ "home", "var", "tmp", "cache", "log", "srv" };
    for (entries.items) |e| {
        if (std.mem.indexOf(u8, e.path, "root") != null) {
            var blocked = false;
            for (deny) |d| {
                if (std.mem.indexOf(u8, e.path, d) != null) {
                    blocked = true;
                    break;
                }
            }
            if (!blocked) return allocator.dupe(u8, e.path);
        }
    }

    for (entries.items) |e| {
        if (e.top_level == 5) return allocator.dupe(u8, e.path);
    }

    return error.NoRootSubvol;
}

fn tryMount(allocator: std.mem.Allocator, device: []const u8, mount_point: []const u8, subvol: []const u8) !bool {
    const opt = try std.fmt.allocPrint(allocator, "subvol={s}", .{subvol});
    defer allocator.free(opt);

    const res = types.executeCmd(allocator, &.{ "mount", "-o", opt, device, mount_point }) catch return false;
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    if (res.exit_code != 0) return false;
    return validateLinuxRoot(mount_point);
}

fn validateLinuxRoot(mount_point: []const u8) bool {
    const markers = [_][]const u8{ "usr/bin", "etc", "bin" };
    for (markers) |rel| {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ mount_point, rel }) catch return false;
        if (!types.dirExists(path)) return false;
    }
    return true;
}

fn mountAdditionalSubvols(allocator: std.mem.Allocator, device: []const u8, mount_point: []const u8) !void {
    const extra = [_]struct { subvol: []const u8, dir: []const u8 }{
        .{ .subvol = "@home", .dir = "home" },
        .{ .subvol = "@srv", .dir = "srv" },
        .{ .subvol = "@cache", .dir = "var/cache" },
        .{ .subvol = "@tmp", .dir = "tmp" },
        .{ .subvol = "@log", .dir = "var/log" },
        .{ .subvol = "@var", .dir = "var" },
    };
    for (extra) |e| {
        var path_buf: [512]u8 = undefined;
        const target = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ mount_point, e.dir }) catch continue;
        if (!types.dirExists(target)) continue;
        const opt = std.fmt.allocPrint(allocator, "subvol={s}", .{e.subvol}) catch continue;
        defer allocator.free(opt);
        const res = types.executeCmd(allocator, &.{ "mount", "-o", opt, device, target }) catch continue;
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    }
}
