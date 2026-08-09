const std = @import("std");

pub const MOUNT_POINT = "/mnt/debork";
pub const LOG_FILE = "/tmp/debork.log";
pub const BTRFS_DETECT_DIR = "/tmp/debork_btrfs_detect";

pub const BootLoader = enum {
    unknown,
    grub,
    refind,
    systemd_boot,

    pub fn name(self: BootLoader) []const u8 {
        return switch (self) {
            .unknown => "Unknown",
            .grub => "GRUB",
            .refind => "rEFInd",
            .systemd_boot => "systemd-boot",
        };
    }
};

pub const PackageManager = enum {
    unknown,
    pacman,
    apt,
    dnf,
    yum,
    zypper,

    pub fn name(self: PackageManager) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .pacman => "pacman",
            .apt => "apt",
            .dnf => "dnf",
            .yum => "yum",
            .zypper => "zypper",
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
    mount_point: []const u8 = MOUNT_POINT,
    boot_loader: BootLoader = .unknown,
    boot_dir: []const u8 = "",
    efi_dir: []const u8 = "",
    kernels: std.ArrayListUnmanaged(KernelInfo) = .empty,
    fstype: []const u8 = "",
    is_btrfs: bool = false,
    root_subvol: []const u8 = "",
    mounted: bool = false,
    distribution: []const u8 = "",
    pkg_manager: PackageManager = .unknown,

    pub fn deinit(self: *SystemInfo, allocator: std.mem.Allocator) void {
        if (self.device.len > 0) allocator.free(self.device);
        if (self.uuid.len > 0) allocator.free(self.uuid);
        if (self.boot_dir.len > 0) allocator.free(self.boot_dir);
        if (self.efi_dir.len > 0) allocator.free(self.efi_dir);
        if (self.fstype.len > 0) allocator.free(self.fstype);
        if (self.root_subvol.len > 0) allocator.free(self.root_subvol);
        if (self.distribution.len > 0) allocator.free(self.distribution);
        for (self.kernels.items) |*k| k.deinit(allocator);
        self.kernels.deinit(allocator);
    }
};

pub const FixResult = struct {
    success: bool,
    message: []const u8,
};

// ---------------------------------------------------------------------------
// Process execution — used everywhere, lives here to avoid circular imports
// ---------------------------------------------------------------------------

pub const CmdResult = struct {
    exit_code: u8,
    stdout: []u8,
    stderr: []u8,
};

pub fn executeCmd(allocator: std.mem.Allocator, argv: []const []const u8) !CmdResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    var err_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);
    defer err_buf.deinit(allocator);

    try child.collectOutput(allocator, &out, &err_buf, 10 * 1024 * 1024);
    const term = try child.wait();

    const code: u8 = switch (term) {
        .Exited => |c| c,
        else => 255,
    };

    return .{
        .exit_code = code,
        .stdout = try out.toOwnedSlice(allocator),
        .stderr = try err_buf.toOwnedSlice(allocator),
    };
}

pub fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

pub fn dirExists(path: []const u8) bool {
    var d = std.fs.openDirAbsolute(path, .{}) catch return false;
    d.close();
    return true;
}
