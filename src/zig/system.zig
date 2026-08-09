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

    pub fn deinit(self: *SystemInfo, allocator: std.mem.Allocator) void {
        if (self.device.len > 0) allocator.free(self.device);
        if (self.uuid.len > 0) allocator.free(self.uuid);
        if (self.mount_point.len > 0 and !std.mem.eql(u8, self.mount_point, "/mnt/debork")) allocator.free(self.mount_point);
        if (self.boot_dir.len > 0) allocator.free(self.boot_dir);
        if (self.efi_dir.len > 0) allocator.free(self.efi_dir);
        if (self.fstype.len > 0) allocator.free(self.fstype);
        if (self.root_subvol.len > 0) allocator.free(self.root_subvol);

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
            cur_dev = ""; cur_uuid = ""; cur_label = ""; cur_type = "";
            continue;
        }

        if (std.mem.startsWith(u8, line, "DEVNAME=")) cur_dev = line["DEVNAME=".len..];
        if (std.mem.startsWith(u8, line, "UUID=")) cur_uuid = line["UUID=".len..];
        if (std.mem.startsWith(u8, line, "LABEL=")) cur_label = line["LABEL=".len..];
        if (std.mem.startsWith(u8, line, "TYPE=")) cur_type = line["TYPE=".len..];
    }
    return list.toOwnedSlice(allocator);
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

    var mount_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer mount_args.deinit(allocator);

    try mount_args.append(allocator, "mount");

    if (sys.is_btrfs) {
        const subvol_res = executeCmd(allocator, &.{ "btrfs", "subvolume", "list", device }) catch null;
        if (subvol_res) |res| {
            defer allocator.free(res.stdout);
            defer allocator.free(res.stderr);
            if (std.mem.indexOf(u8, res.stdout, "@") != null) {
                try mount_args.append(allocator, "-o");
                try mount_args.append(allocator, "subvol=@");
                sys.root_subvol = try allocator.dupe(u8, "@");
            }
        }
    }

    try mount_args.append(allocator, device);
    try mount_args.append(allocator, sys.mount_point);

    const mount_res = try executeCmd(allocator, mount_args.items);
    defer allocator.free(mount_res.stdout);
    defer allocator.free(mount_res.stderr);

    if (mount_res.exit_code != 0) {
        return false;
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

    // Copy network resolv.conf for chroot package updates
    const resolv_dest = try std.fmt.allocPrint(allocator, "{s}/etc/resolv.conf", .{sys.mount_point});
    defer allocator.free(resolv_dest);
    std.fs.cwd().copyFile("/etc/resolv.conf", std.fs.cwd(), resolv_dest, .{}) catch {};

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
