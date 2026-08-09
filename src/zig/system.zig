const std = @import("std");

pub const BootLoader = enum {
    unknown,
    grub,
    refind,
    systemd_boot,

    pub fn name(self: BootLoader) []const u8 {
        return switch (self) {
            .unknown => "Unknown",
            .grub => "GRUB (GRUB2)",
            .refind => "rEFInd",
            .systemd_boot => "systemd-boot",
        };
    }
};

pub const KernelInfo = struct {
    version: []const u8,
    path: []const u8,
    initrd: []const u8,
    exists: bool,

    pub fn deinit(self: *KernelInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
        allocator.free(self.path);
        allocator.free(self.initrd);
    }
};

pub const PartitionInfo = struct {
    device: []const u8,
    uuid: []const u8,
    label: []const u8,
    fstype: []const u8,
    mountpoint: []const u8,
    size: []const u8,
    is_linux_root: bool,

    pub fn deinit(self: *PartitionInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.device);
        allocator.free(self.uuid);
        allocator.free(self.label);
        allocator.free(self.fstype);
        allocator.free(self.mountpoint);
        allocator.free(self.size);
    }
};

pub const SystemInfo = struct {
    device: []const u8 = "",
    uuid: []const u8 = "",
    mount_point: []const u8 = "/mnt/debork",
    boot_loader: BootLoader = .unknown,
    boot_dir: []const u8 = "",
    efi_dir: []const u8 = "",
    kernels: std.ArrayListUnmanaged(KernelInfo) = .empty,
    fstype: []const u8 = "",
    is_btrfs: bool = false,
    root_subvol: []const u8 = "",
    mounted: bool = false,
    distribution: []const u8 = "",
    pkg_manager: []const u8 = "",

    pub fn deinit(self: *SystemInfo, allocator: std.mem.Allocator) void {
        if (self.device.len > 0) allocator.free(self.device);
        if (self.uuid.len > 0) allocator.free(self.uuid);
        if (self.mount_point.len > 0 and !std.mem.eql(u8, self.mount_point, "/mnt/debork")) allocator.free(self.mount_point);
        if (self.boot_dir.len > 0) allocator.free(self.boot_dir);
        if (self.efi_dir.len > 0) allocator.free(self.efi_dir);
        if (self.fstype.len > 0) allocator.free(self.fstype);
        if (self.root_subvol.len > 0) allocator.free(self.root_subvol);
        if (self.distribution.len > 0) allocator.free(self.distribution);
        if (self.pkg_manager.len > 0) allocator.free(self.pkg_manager);

        for (self.kernels.items) |*k| {
            k.deinit(allocator);
        }
        self.kernels.deinit(allocator);
    }
};

pub fn executeCmd(allocator: std.mem.Allocator, argv: []const []const u8) !struct { exit_code: u8, stdout: []u8, stderr: []u8 } {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    var stdout_buf: std.ArrayListUnmanaged(u8) = .empty;
    var stderr_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer stdout_buf.deinit(allocator);
    defer stderr_buf.deinit(allocator);

    try child.collectOutput(allocator, &stdout_buf, &stderr_buf, 10 * 1024 * 1024);
    const term = try child.wait();

    const code: u8 = switch (term) {
        .Exited => |c| c,
        else => 255,
    };

    return .{
        .exit_code = code,
        .stdout = try stdout_buf.toOwnedSlice(allocator),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
    };
}

pub fn scanPartitions(allocator: std.mem.Allocator) ![]PartitionInfo {
    var list: std.ArrayListUnmanaged(PartitionInfo) = .empty;
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit(allocator);
    }

    const res = executeCmd(allocator, &.{ "lsblk", "-J", "-o", "NAME,PATH,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINT" }) catch |err| {
        std.log.warn("lsblk failed: {}, falling back to blkid", .{err});
        return try scanPartitionsBlkId(allocator);
    };
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    if (res.exit_code != 0 or res.stdout.len == 0) {
        return try scanPartitionsBlkId(allocator);
    }

    // Parse lsblk JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, res.stdout, .{}) catch {
        return try scanPartitionsBlkId(allocator);
    };
    defer parsed.deinit();

    if (parsed.value != .object) return list.toOwnedSlice(allocator);
    const blockdevices = parsed.value.object.get("blockdevices") orelse return list.toOwnedSlice(allocator);
    if (blockdevices != .array) return list.toOwnedSlice(allocator);

    try parseBlockDevices(allocator, blockdevices.array.items, &list);
    return list.toOwnedSlice(allocator);
}

fn parseBlockDevices(allocator: std.mem.Allocator, items: []const std.json.Value, list: *std.ArrayListUnmanaged(PartitionInfo)) !void {
    for (items) |dev| {
        if (dev != .object) continue;
        const obj = dev.object;

        const path = if (obj.get("path")) |v| (if (v == .string) v.string else "") else "";
        const fstype = if (obj.get("fstype")) |v| (if (v == .string) v.string else "") else "";
        const label = if (obj.get("label")) |v| (if (v == .string) v.string else "") else "";
        const uuid = if (obj.get("uuid")) |v| (if (v == .string) v.string else "") else "";
        const size = if (obj.get("size")) |v| (if (v == .string) v.string else "") else "";
        const mountpoint = if (obj.get("mountpoint")) |v| (if (v == .string) v.string else "") else "";

        if (path.len > 0 and (std.mem.eql(u8, fstype, "ext4") or std.mem.eql(u8, fstype, "ext3") or std.mem.eql(u8, fstype, "btrfs") or std.mem.eql(u8, fstype, "xfs") or std.mem.eql(u8, fstype, "f2fs") or std.mem.eql(u8, fstype, "vfat"))) {
            const is_root = std.mem.eql(u8, fstype, "ext4") or std.mem.eql(u8, fstype, "btrfs") or std.mem.eql(u8, fstype, "xfs") or std.mem.eql(u8, fstype, "f2fs");
            try list.append(allocator, PartitionInfo{
                .device = try allocator.dupe(u8, path),
                .uuid = try allocator.dupe(u8, uuid),
                .label = try allocator.dupe(u8, label),
                .fstype = try allocator.dupe(u8, fstype),
                .mountpoint = try allocator.dupe(u8, mountpoint),
                .size = try allocator.dupe(u8, size),
                .is_linux_root = is_root,
            });
        }

        if (obj.get("children")) |children| {
            if (children == .array) {
                try parseBlockDevices(allocator, children.array.items, list);
            }
        }
    }
}

fn scanPartitionsBlkId(allocator: std.mem.Allocator) ![]PartitionInfo {
    var list: std.ArrayListUnmanaged(PartitionInfo) = .empty;
    const res = executeCmd(allocator, &.{ "blkid", "-o", "export" }) catch return list.toOwnedSlice(allocator);
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    var lines = std.mem.splitSequence(u8, res.stdout, "\n");
    var cur_dev: []const u8 = "";
    var cur_uuid: []const u8 = "";
    var cur_label: []const u8 = "";
    var cur_type: []const u8 = "";

    while (lines.next()) |line| {
        if (line.len == 0) {
            if (cur_dev.len > 0) {
                const is_root = std.mem.eql(u8, cur_type, "ext4") or std.mem.eql(u8, cur_type, "btrfs") or std.mem.eql(u8, cur_type, "xfs");
                try list.append(allocator, .{
                    .device = try allocator.dupe(u8, cur_dev),
                    .uuid = try allocator.dupe(u8, cur_uuid),
                    .label = try allocator.dupe(u8, cur_label),
                    .fstype = try allocator.dupe(u8, cur_type),
                    .mountpoint = try allocator.dupe(u8, ""),
                    .size = try allocator.dupe(u8, ""),
                    .is_linux_root = is_root,
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

// Parsed representation of a single btrfs subvolume list entry.
const BtrfsSubvol = struct {
    top_level: u32,
    // Slice into the btrfs-list stdout buffer — valid for its lifetime.
    path: []const u8,
};

/// Parse one line of `btrfs subvolume list` output.
/// Expected format: "ID N gen N top level N path PATH"
/// Returns null if the line doesn't match.
fn parseBtrfsSubvolLine(line: []const u8) ?BtrfsSubvol {
    // Find " path " marker — everything after it is the subvolume path.
    const path_marker = " path ";
    const path_pos = std.mem.indexOf(u8, line, path_marker) orelse return null;
    const path = std.mem.trim(u8, line[path_pos + path_marker.len ..], " \t\r\n");
    if (path.len == 0) return null;

    // Extract "top level N" — the marker precedes " path ".
    const tl_marker = "top level ";
    const tl_pos = std.mem.indexOf(u8, line[0..path_pos], tl_marker) orelse return null;
    const tl_start = tl_pos + tl_marker.len;
    // The top-level number runs until the next space.
    const tl_end = std.mem.indexOfScalarPos(u8, line, tl_start, ' ') orelse path_pos;
    const top_level = std.fmt.parseUnsigned(u32, line[tl_start..tl_end], 10) catch return null;

    return .{ .top_level = top_level, .path = path };
}

/// Detect the root btrfs subvolume using a three-pass strategy.
/// Returns a duped string (caller owns) or null when nothing matched.
fn detectBtrfsRootSubvol(allocator: std.mem.Allocator, device: []const u8) !?[]const u8 {
    const temp_mount = "/tmp/debork_btrfs_detect";

    std.fs.cwd().makePath(temp_mount) catch {};

    // Temp-mount read-only so we can query subvolume list.
    const mnt_res = try executeCmd(allocator, &.{ "mount", "-o", "ro", device, temp_mount });
    defer allocator.free(mnt_res.stdout);
    defer allocator.free(mnt_res.stderr);

    if (mnt_res.exit_code != 0) {
        std.log.warn("btrfs temp-mount failed: {s}", .{mnt_res.stderr});
        return null;
    }

    // Always unmount the temp mount before returning.
    defer {
        const u = executeCmd(allocator, &.{ "umount", temp_mount }) catch null;
        if (u) |r| {
            allocator.free(r.stdout);
            allocator.free(r.stderr);
        }
    }

    const list_res = try executeCmd(allocator, &.{ "btrfs", "subvolume", "list", temp_mount });
    defer allocator.free(list_res.stdout);
    defer allocator.free(list_res.stderr);

    if (list_res.exit_code != 0 or list_res.stdout.len == 0) {
        return null;
    }

    // Collect all parsed subvolumes into a temporary list.
    var subvols: std.ArrayListUnmanaged(BtrfsSubvol) = .empty;
    defer subvols.deinit(allocator);

    var lines = std.mem.splitSequence(u8, list_res.stdout, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (parseBtrfsSubvolLine(trimmed)) |sv| {
            try subvols.append(allocator, sv);
        }
    }

    if (subvols.items.len == 0) return null;

    // --- Pass 1: exact name match ---
    const exact_patterns = [_][]const u8{ "@", "root", "rootfs", "@rootfs", "/" };
    for (exact_patterns) |pat| {
        for (subvols.items) |sv| {
            if (std.mem.eql(u8, sv.path, pat)) {
                return try allocator.dupe(u8, sv.path);
            }
        }
    }

    // --- Pass 2: path contains "root" but not "home", "var", "tmp", "cache", "log" ---
    for (subvols.items) |sv| {
        if (std.mem.indexOf(u8, sv.path, "root") != null and
            std.mem.indexOf(u8, sv.path, "home") == null and
            std.mem.indexOf(u8, sv.path, "var") == null and
            std.mem.indexOf(u8, sv.path, "tmp") == null and
            std.mem.indexOf(u8, sv.path, "cache") == null and
            std.mem.indexOf(u8, sv.path, "log") == null)
        {
            return try allocator.dupe(u8, sv.path);
        }
    }

    // --- Pass 3: top-level id == 5 ---
    for (subvols.items) |sv| {
        if (sv.top_level == 5 and sv.path.len > 0) {
            return try allocator.dupe(u8, sv.path);
        }
    }

    return null;
}

/// Try mounting with a specific btrfs subvolume option.
/// Returns true on success, false (and leaves mount_point clean) on failure.
fn tryBtfrsMount(allocator: std.mem.Allocator, device: []const u8, mount_point: []const u8, subvol: []const u8) !bool {
    const opt = try std.fmt.allocPrint(allocator, "subvol={s}", .{subvol});
    defer allocator.free(opt);
    const res = try executeCmd(allocator, &.{ "mount", "-o", opt, device, mount_point });
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);
    return res.exit_code == 0;
}

/// After a successful root mount, mount well-known additional btrfs subvolumes
/// when their target directories already exist inside the chroot.
fn mountAdditionalBtrfsSubvols(allocator: std.mem.Allocator, device: []const u8, mount_point: []const u8) void {
    const extra = [_][]const u8{ "@home", "@root", "@srv", "@cache", "@tmp", "@log", "@var" };
    for (extra) |subvol| {
        // Strip leading '@' to get the directory name.
        const dir_name = subvol[1..];
        const target = std.fmt.allocPrint(allocator, "{s}/{s}", .{ mount_point, dir_name }) catch continue;
        defer allocator.free(target);

        // Only mount if the directory exists inside the chroot.
        std.fs.cwd().access(target, .{}) catch continue;

        const opt = std.fmt.allocPrint(allocator, "subvol={s}", .{subvol}) catch continue;
        defer allocator.free(opt);

        const res = executeCmd(allocator, &.{ "mount", "-o", opt, device, target }) catch continue;
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    }
}

/// Detect and mount the EFI system partition into the chroot.
/// Updates sys.efi_dir when a suitable directory is found.
fn mountEfiPartition(allocator: std.mem.Allocator, sys: *SystemInfo) void {
    const candidates = [_][]const u8{ "boot/efi", "efi", "boot/EFI" };

    for (candidates) |rel| {
        const efi_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
        defer allocator.free(efi_path);

        std.fs.cwd().access(efi_path, .{}) catch continue;

        // Found a directory — update efi_dir.
        if (sys.efi_dir.len > 0) allocator.free(sys.efi_dir);
        sys.efi_dir = allocator.dupe(u8, efi_path) catch continue;

        // Try to find the EFI device via findmnt.
        const fm_res = executeCmd(allocator, &.{ "findmnt", "-n", "-o", "SOURCE", "-t", "vfat", "/boot/efi" }) catch continue;
        defer allocator.free(fm_res.stdout);
        defer allocator.free(fm_res.stderr);

        if (fm_res.exit_code == 0) {
            const efi_dev = std.mem.trim(u8, fm_res.stdout, " \t\r\n");
            if (efi_dev.len > 0) {
                const mnt_res = executeCmd(allocator, &.{ "mount", efi_dev, efi_path }) catch continue;
                allocator.free(mnt_res.stdout);
                allocator.free(mnt_res.stderr);
                // Whether or not mount succeeded the directory is set; stop searching.
            }
        }
        return;
    }
}

pub fn mountSystem(allocator: std.mem.Allocator, sys: *SystemInfo, device: []const u8) !bool {
    if (sys.mounted) return true;

    // Create mount point
    std.fs.cwd().makePath(sys.mount_point) catch {};

    // Get fstype
    const fstype_res = executeCmd(allocator, &.{ "blkid", "-s", "TYPE", "-o", "value", device }) catch null;
    if (fstype_res) |res| {
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        const trimmed = std.mem.trim(u8, res.stdout, " \t\r\n");
        if (trimmed.len > 0) {
            sys.fstype = try allocator.dupe(u8, trimmed);
            sys.is_btrfs = std.mem.eql(u8, trimmed, "btrfs");
        }
    }

    // --- btrfs: subvolume detection and mount ---
    if (sys.is_btrfs) {
        const detected = detectBtrfsRootSubvol(allocator, device) catch null;

        var mounted_with_subvol = false;

        if (detected) |subvol| {
            // Attempt mount with detected subvolume.
            const ok = tryBtfrsMount(allocator, device, sys.mount_point, subvol) catch false;
            if (ok) {
                sys.root_subvol = subvol; // transfer ownership
                mounted_with_subvol = true;
            } else {
                allocator.free(subvol);
            }
        }

        if (!mounted_with_subvol) {
            // Fallback: try "@" explicitly.
            const ok = tryBtfrsMount(allocator, device, sys.mount_point, "@") catch false;
            if (ok) {
                sys.root_subvol = try allocator.dupe(u8, "@");
                mounted_with_subvol = true;
            }
        }

        if (!mounted_with_subvol) {
            // Last resort: plain mount without any subvol option.
            const res = try executeCmd(allocator, &.{ "mount", device, sys.mount_point });
            defer allocator.free(res.stdout);
            defer allocator.free(res.stderr);
            if (res.exit_code != 0) return false;
        }

        // Mount additional well-known subvolumes if their dirs exist.
        mountAdditionalBtrfsSubvols(allocator, device, sys.mount_point);
    } else {
        // Non-btrfs: plain mount.
        const res = try executeCmd(allocator, &.{ "mount", device, sys.mount_point });
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        if (res.exit_code != 0) return false;
    }

    sys.device = try allocator.dupe(u8, device);
    sys.boot_dir = try std.fmt.allocPrint(allocator, "{s}/boot", .{sys.mount_point});
    sys.efi_dir = try allocator.dupe(u8, sys.boot_dir);
    sys.mounted = true;

    // Retrieve UUID
    const uuid_res = executeCmd(allocator, &.{ "blkid", "-s", "UUID", "-o", "value", device }) catch null;
    if (uuid_res) |res| {
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        const trimmed = std.mem.trim(u8, res.stdout, " \t\r\n");
        if (trimmed.len > 0) {
            sys.uuid = try allocator.dupe(u8, trimmed);
        }
    }

    // Bind mount essential system directories
    const bind_dirs = [_][]const u8{ "/dev", "/proc", "/sys", "/run" };
    for (bind_dirs) |dir| {
        const target = try std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, dir });
        defer allocator.free(target);
        std.fs.cwd().makePath(target) catch {};

        const bind_res = executeCmd(allocator, &.{ "mount", "--bind", dir, target }) catch continue;
        allocator.free(bind_res.stdout);
        allocator.free(bind_res.stderr);
    }

    // Detect and mount EFI partition
    mountEfiPartition(allocator, sys);

    // Copy network files for chroot package updates
    const network_files = [_][]const u8{ "/etc/resolv.conf", "/etc/hosts" };
    for (network_files) |src| {
        const dest = std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, src }) catch continue;
        defer allocator.free(dest);
        std.fs.cwd().copyFile(src, std.fs.cwd(), dest, .{}) catch {};
    }

    return true;
}

pub fn unmountSystem(allocator: std.mem.Allocator, sys: *SystemInfo) void {
    if (!sys.mounted) return;

    const bind_dirs = [_][]const u8{ "/run", "/sys", "/proc", "/dev" };
    for (bind_dirs) |dir| {
        const target = std.fmt.allocPrint(allocator, "{s}{s}", .{ sys.mount_point, dir }) catch continue;
        defer allocator.free(target);
        const res = executeCmd(allocator, &.{ "umount", "-l", target }) catch continue;
        allocator.free(res.stdout);
        allocator.free(res.stderr);
    }

    const root_res = executeCmd(allocator, &.{ "umount", "-l", sys.mount_point }) catch return;
    allocator.free(root_res.stdout);
    allocator.free(root_res.stderr);

    sys.mounted = false;
}

/// Detect the Linux distribution of the mounted system and store the result in
/// sys.distribution. Caller must ensure sys is mounted before calling.
pub fn detectDistribution(allocator: std.mem.Allocator, sys: *SystemInfo) void {
    if (!sys.mounted) return;

    // --- Primary: parse /etc/os-release ---
    const os_release_path = std.fmt.allocPrint(allocator, "{s}/etc/os-release", .{sys.mount_point}) catch return;
    defer allocator.free(os_release_path);

    read_os_release: {
        const file = std.fs.cwd().openFile(os_release_path, .{}) catch break :read_os_release;
        defer file.close();

        const content = file.readToEndAlloc(allocator, 256 * 1024) catch break :read_os_release;
        defer allocator.free(content);

        var it = std.mem.splitSequence(u8, content, "\n");
        while (it.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            if (!std.mem.startsWith(u8, trimmed, "PRETTY_NAME=")) continue;

            var value = trimmed["PRETTY_NAME=".len..];
            // Strip surrounding quotes if present.
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            } else if (value.len >= 1 and value[0] == '"') {
                value = value[1..];
            }
            if (value.len > 0) {
                if (sys.distribution.len > 0) allocator.free(sys.distribution);
                sys.distribution = allocator.dupe(u8, value) catch return;
                return;
            }
        }
    }

    // --- Fallback checks ---
    const FallbackEntry = struct { rel_path: []const u8, name: ?[]const u8 };
    const fallbacks = [_]FallbackEntry{
        .{ .rel_path = "etc/arch-release", .name = "Arch Linux" },
        .{ .rel_path = "etc/debian_version", .name = "Debian/Ubuntu" },
        .{ .rel_path = "etc/redhat-release", .name = null }, // read content
        .{ .rel_path = "etc/SuSE-release", .name = "openSUSE" },
    };

    for (fallbacks) |fb| {
        const full_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ sys.mount_point, fb.rel_path }) catch continue;
        defer allocator.free(full_path);

        std.fs.cwd().access(full_path, .{}) catch continue;

        if (fb.name) |static_name| {
            if (sys.distribution.len > 0) allocator.free(sys.distribution);
            sys.distribution = allocator.dupe(u8, static_name) catch return;
            return;
        }

        // Read first line of the release file as the distribution name.
        read_content: {
            const file = std.fs.cwd().openFile(full_path, .{}) catch break :read_content;
            defer file.close();
            const content = file.readToEndAlloc(allocator, 4096) catch break :read_content;
            defer allocator.free(content);
            const first_line = std.mem.trim(u8, blk: {
                const nl = std.mem.indexOfScalar(u8, content, '\n') orelse content.len;
                break :blk content[0..nl];
            }, " \t\r\n");
            if (first_line.len > 0) {
                if (sys.distribution.len > 0) allocator.free(sys.distribution);
                sys.distribution = allocator.dupe(u8, first_line) catch return;
                return;
            }
        }
    }
}

/// Detect the package manager available in the mounted system and store the
/// result in sys.pkg_manager. Caller must ensure sys is mounted before calling.
pub fn detectPackageManager(allocator: std.mem.Allocator, sys: *SystemInfo) void {
    if (!sys.mounted) return;

    const PmEntry = struct { bin: []const u8, name: []const u8 };
    const candidates = [_]PmEntry{
        .{ .bin = "usr/bin/pacman", .name = "pacman" },
        .{ .bin = "usr/bin/apt", .name = "apt" },
        .{ .bin = "usr/bin/dnf", .name = "dnf" },
        .{ .bin = "usr/bin/yum", .name = "yum" },
        .{ .bin = "usr/bin/zypper", .name = "zypper" },
    };

    for (candidates) |c| {
        const full_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ sys.mount_point, c.bin }) catch continue;
        defer allocator.free(full_path);

        std.fs.cwd().access(full_path, .{}) catch continue;

        if (sys.pkg_manager.len > 0) allocator.free(sys.pkg_manager);
        sys.pkg_manager = allocator.dupe(u8, c.name) catch return;
        return;
    }
}
