const std = @import("std");
const types = @import("../core/types.zig");
const log = @import("../core/logger.zig");

/// Scan for Linux partitions using lsblk JSON, falling back to blkid.
pub fn scanPartitions(allocator: std.mem.Allocator) ![]types.PartitionInfo {
    var list: std.ArrayListUnmanaged(types.PartitionInfo) = .empty;
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit(allocator);
    }

    const res = types.executeCmd(allocator, &.{
        "lsblk", "-J", "-o", "NAME,PATH,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINT",
    }) catch {
        return scanPartitionsBlkid(allocator);
    };
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    if (res.exit_code != 0 or res.stdout.len == 0) return scanPartitionsBlkid(allocator);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, res.stdout, .{}) catch {
        return scanPartitionsBlkid(allocator);
    };
    defer parsed.deinit();

    if (parsed.value != .object) return list.toOwnedSlice(allocator);
    const bd = parsed.value.object.get("blockdevices") orelse return list.toOwnedSlice(allocator);
    if (bd != .array) return list.toOwnedSlice(allocator);

    try parseBlockDevicesJson(allocator, bd.array.items, &list);
    return list.toOwnedSlice(allocator);
}

/// Scan kernels in {mount_point}/boot, return sorted newest-first.
pub fn scanKernels(allocator: std.mem.Allocator, sys: *types.SystemInfo) !void {
    // Free previous results
    for (sys.kernels.items) |*k| k.deinit(allocator);
    sys.kernels.clearRetainingCapacity();

    const boot_path = try std.fmt.allocPrint(allocator, "{s}/boot", .{sys.mount_point});
    defer allocator.free(boot_path);

    var boot_dir = std.fs.openDirAbsolute(boot_path, .{ .iterate = true }) catch return;
    defer boot_dir.close();

    var it = boot_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        if (!std.mem.startsWith(u8, entry.name, "vmlinuz")) continue;

        const version = if (std.mem.indexOfScalar(u8, entry.name, '-')) |i|
            try allocator.dupe(u8, entry.name[i + 1 ..])
        else
            try allocator.dupe(u8, entry.name);

        const path = try allocator.dupe(u8, entry.name);
        const initrd = findInitrd(allocator, boot_dir, version) catch try allocator.dupe(u8, "");

        try sys.kernels.append(allocator, .{
            .version = version,
            .path = path,
            .initrd = initrd,
            .exists = true,
        });
    }

    // Sort: newest version last via lexicographic descending
    std.mem.sort(types.KernelInfo, sys.kernels.items, {}, struct {
        fn lt(_: void, a: types.KernelInfo, b: types.KernelInfo) bool {
            return std.mem.order(u8, a.version, b.version) == .gt;
        }
    }.lt);
}

/// Detect which bootloader is installed by checking filesystem markers.
pub fn detectBootLoader(allocator_unused: std.mem.Allocator, sys: *types.SystemInfo) void {
    _ = allocator_unused;
    const root = sys.mount_point;

    const grub_paths = [_][]const u8{ "boot/grub", "boot/grub2" };
    for (grub_paths) |rel| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ root, rel }) catch continue;
        if (types.dirExists(p)) {
            sys.boot_loader = .grub;
            return;
        }
    }

    const refind_paths = [_][]const u8{ "boot/efi/EFI/refind", "boot/EFI/refind", "efi/EFI/refind" };
    for (refind_paths) |rel| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ root, rel }) catch continue;
        if (types.dirExists(p)) {
            sys.boot_loader = .refind;
            return;
        }
    }

    const sdb_paths = [_][]const u8{
        "boot/efi/EFI/systemd",
        "boot/loader/loader.conf",
        "efi/loader/loader.conf",
    };
    for (sdb_paths) |rel| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ root, rel }) catch continue;
        if (types.fileExists(p) or types.dirExists(p)) {
            sys.boot_loader = .systemd_boot;
            return;
        }
    }

    sys.boot_loader = .unknown;
}

/// Detect the Linux distribution by reading os-release and fallback files.
pub fn detectDistribution(allocator: std.mem.Allocator, sys: *types.SystemInfo) void {
    if (sys.distribution.len > 0) return;

    // Try /etc/os-release first
    const os_release = std.fmt.allocPrint(allocator, "{s}/etc/os-release", .{sys.mount_point}) catch return;
    defer allocator.free(os_release);

    if (std.fs.cwd().readFileAlloc(allocator, os_release, 64 * 1024)) |content| {
        defer allocator.free(content);
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, "PRETTY_NAME=")) continue;
            var val = line["PRETTY_NAME=".len..];
            val = std.mem.trim(u8, val, "\"' \t\r");
            if (val.len > 0) {
                sys.distribution = allocator.dupe(u8, val) catch return;
                return;
            }
        }
    } else |_| {}

    // Fallbacks
    const fallbacks = [_]struct { file: []const u8, distro: []const u8 }{
        .{ .file = "etc/arch-release", .distro = "Arch Linux" },
        .{ .file = "etc/debian_version", .distro = "Debian/Ubuntu" },
        .{ .file = "etc/SuSE-release", .distro = "openSUSE" },
    };
    for (fallbacks) |fb| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, fb.file }) catch continue;
        if (types.fileExists(p)) {
            sys.distribution = allocator.dupe(u8, fb.distro) catch return;
            return;
        }
    }
}

/// Detect which package manager is installed in the mounted system.
pub fn detectPackageManager(allocator: std.mem.Allocator, sys: *types.SystemInfo) void {
    const pms = [_]struct { bin: []const u8, pm: types.PackageManager }{
        .{ .bin = "usr/bin/pacman", .pm = .pacman },
        .{ .bin = "usr/bin/apt", .pm = .apt },
        .{ .bin = "usr/bin/dnf", .pm = .dnf },
        .{ .bin = "usr/bin/yum", .pm = .yum },
        .{ .bin = "usr/bin/zypper", .pm = .zypper },
    };
    for (pms) |entry| {
        var buf: [512]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, entry.bin }) catch continue;
        if (types.fileExists(p)) {
            sys.pkg_manager = entry.pm;
            _ = allocator; // suppress unused warning
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parseBlockDevicesJson(
    allocator: std.mem.Allocator,
    items: []const std.json.Value,
    list: *std.ArrayListUnmanaged(types.PartitionInfo),
) !void {
    const linux_fs = [_][]const u8{ "ext4", "ext3", "ext2", "btrfs", "xfs", "f2fs" };

    for (items) |dev| {
        if (dev != .object) continue;
        const obj = dev.object;

        const path = jsonStr(obj, "path");
        const fstype = jsonStr(obj, "fstype");
        const label = jsonStr(obj, "label");
        const uuid = jsonStr(obj, "uuid");
        const size = jsonStr(obj, "size");
        const mountpt = jsonStr(obj, "mountpoint");

        if (path.len > 0) {
            var is_linux = false;
            for (linux_fs) |fs| {
                if (std.mem.eql(u8, fstype, fs)) {
                    is_linux = true;
                    break;
                }
            }
            const is_vfat = std.mem.eql(u8, fstype, "vfat");

            if (is_linux or is_vfat) {
                try list.append(allocator, .{
                    .device = try allocator.dupe(u8, path),
                    .uuid = try allocator.dupe(u8, uuid),
                    .label = try allocator.dupe(u8, label),
                    .fstype = try allocator.dupe(u8, fstype),
                    .mountpoint = try allocator.dupe(u8, mountpt),
                    .size = try allocator.dupe(u8, size),
                    .is_linux_root = is_linux,
                });
            }
        }

        if (obj.get("children")) |children| {
            if (children == .array) {
                try parseBlockDevicesJson(allocator, children.array.items, list);
            }
        }
    }
}

fn scanPartitionsBlkid(allocator: std.mem.Allocator) ![]types.PartitionInfo {
    var list: std.ArrayListUnmanaged(types.PartitionInfo) = .empty;

    const res = types.executeCmd(allocator, &.{ "blkid", "-o", "export" }) catch
        return list.toOwnedSlice(allocator);
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    var cur_dev: []const u8 = "";
    var cur_uuid: []const u8 = "";
    var cur_label: []const u8 = "";
    var cur_type: []const u8 = "";

    var lines = std.mem.splitScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) {
            if (cur_dev.len > 0) {
                const is_linux = for ([_][]const u8{ "ext4", "ext3", "btrfs", "xfs", "f2fs" }) |fs| {
                    if (std.mem.eql(u8, cur_type, fs)) break true;
                } else false;
                try list.append(allocator, .{
                    .device = try allocator.dupe(u8, cur_dev),
                    .uuid = try allocator.dupe(u8, cur_uuid),
                    .label = try allocator.dupe(u8, cur_label),
                    .fstype = try allocator.dupe(u8, cur_type),
                    .mountpoint = try allocator.dupe(u8, ""),
                    .size = try allocator.dupe(u8, ""),
                    .is_linux_root = is_linux,
                });
            }
            cur_dev = "";
            cur_uuid = "";
            cur_label = "";
            cur_type = "";
            continue;
        }
        if (std.mem.startsWith(u8, line, "DEVNAME=")) cur_dev = line["DEVNAME=".len..];
        if (std.mem.startsWith(u8, line, "UUID=")) cur_uuid = line["UUID=".len..];
        if (std.mem.startsWith(u8, line, "LABEL=")) cur_label = line["LABEL=".len..];
        if (std.mem.startsWith(u8, line, "TYPE=")) cur_type = line["TYPE=".len..];
    }
    return list.toOwnedSlice(allocator);
}

fn findInitrd(allocator: std.mem.Allocator, boot_dir: std.fs.Dir, version: []const u8) ![]const u8 {
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    var b3: [256]u8 = undefined;
    var b4: [256]u8 = undefined;
    const names = [_][]const u8{
        std.fmt.bufPrint(&b1, "initramfs-{s}.img", .{version}) catch "",
        std.fmt.bufPrint(&b2, "initrd.img-{s}", .{version}) catch "",
        std.fmt.bufPrint(&b3, "initramfs-{s}-fallback.img", .{version}) catch "",
        std.fmt.bufPrint(&b4, "initrd-{s}.img", .{version}) catch "",
    };
    for (names) |name| {
        if (name.len == 0) continue;
        boot_dir.access(name, .{}) catch continue;
        return allocator.dupe(u8, name);
    }
    boot_dir.access("initramfs-linux.img", .{}) catch return allocator.dupe(u8, "");
    return allocator.dupe(u8, "initramfs-linux.img");
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return if (v == .string) v.string else "";
}
