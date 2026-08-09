const std = @import("std");
const types = @import("../core/types.zig");
const log = @import("../core/logger.zig");
const chroot = @import("../system/chroot.zig");
const detection = @import("../system/detection.zig");

// ---------------------------------------------------------------------------
// Bootloader fixes
// ---------------------------------------------------------------------------

pub fn detectBootLoader(allocator: std.mem.Allocator, sys: *types.SystemInfo) void {
    detection.detectBootLoader(allocator, sys);
}

pub fn fixGrub(allocator: std.mem.Allocator, sys: *types.SystemInfo) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    // Regenerate grub config
    const mkconf = try types.executeCmd(allocator, &.{ "chroot", sys.mount_point, "grub-mkconfig", "-o", "/boot/grub/grub.cfg" });
    defer allocator.free(mkconf.stdout);
    defer allocator.free(mkconf.stderr);
    if (mkconf.exit_code != 0) {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "grub-mkconfig failed:\n{s}", .{mkconf.stderr}) };
    }

    // Try grub-install
    var install_note: []const u8 = try allocator.dupe(u8, "");
    defer allocator.free(install_note);

    const grub_install = blk: {
        var buf: [512]u8 = undefined;
        for ([_][]const u8{ "usr/bin/grub-install", "usr/sbin/grub-install" }) |rel| {
            const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ sys.mount_point, rel }) catch continue;
            if (types.fileExists(p)) break :blk true;
        }
        break :blk false;
    };

    if (grub_install) {
        // Try EFI first
        const efi_res = types.executeCmd(allocator, &.{
            "chroot",                    sys.mount_point,
            "grub-install",              "--target=x86_64-efi",
            "--efi-directory=/boot/efi", "--bootloader-id=GRUB",
            "--recheck",
        }) catch null;
        if (efi_res) |r| {
            defer allocator.free(r.stdout);
            defer allocator.free(r.stderr);
            if (r.exit_code == 0) {
                install_note = try allocator.dupe(u8, " + grub-install (EFI) OK");
            } else {
                // BIOS fallback — strip partition suffix from device
                const boot_dev = try stripPartitionSuffix(allocator, sys.device);
                defer allocator.free(boot_dev);
                const bios_res = types.executeCmd(allocator, &.{
                    "chroot", sys.mount_point, "grub-install", boot_dev,
                }) catch null;
                if (bios_res) |br| {
                    defer allocator.free(br.stdout);
                    defer allocator.free(br.stderr);
                    if (br.exit_code == 0) {
                        install_note = try allocator.dupe(u8, " + grub-install (BIOS) OK");
                    }
                }
            }
        }
    }

    const msg = try std.fmt.allocPrint(allocator, "GRUB config updated{s}", .{install_note});
    return .{ .success = true, .message = msg };
}

pub fn fixRefind(allocator: std.mem.Allocator, sys: *types.SystemInfo, kernel_idx: usize) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };
    if (sys.kernels.items.len == 0) return .{ .success = false, .message = try allocator.dupe(u8, "No kernels found in /boot!") };

    const idx = if (kernel_idx < sys.kernels.items.len) kernel_idx else 0;
    const k = sys.kernels.items[idx];

    // Find the right refind dir (EFI partition or boot/efi fallback)
    var rd1: [512]u8 = undefined;
    var rd2: [512]u8 = undefined;
    var rd3: [512]u8 = undefined;
    const refind_candidates = [_][]const u8{
        std.fmt.bufPrint(&rd1, "{s}/boot/efi/EFI/refind", .{sys.mount_point}) catch "",
        std.fmt.bufPrint(&rd2, "{s}/efi/EFI/refind", .{sys.mount_point}) catch "",
        std.fmt.bufPrint(&rd3, "{s}/boot/EFI/refind", .{sys.mount_point}) catch "",
    };
    var refind_dir: []const u8 = "";
    for (refind_candidates) |candidate| {
        if (candidate.len > 0 and types.dirExists(candidate)) {
            refind_dir = candidate;
            break;
        }
    }
    var rd_fallback: [512]u8 = undefined;
    if (refind_dir.len == 0) {
        refind_dir = std.fmt.bufPrint(&rd_fallback, "{s}/boot/efi/EFI/refind", .{sys.mount_point}) catch "";
        std.fs.cwd().makePath(refind_dir) catch {};
    }

    const conf_path = try std.fmt.allocPrint(allocator, "{s}/refind_linux.conf", .{refind_dir});
    defer allocator.free(conf_path);

    const initrd_opt = if (k.initrd.len > 0)
        try std.fmt.allocPrint(allocator, " initrd={s}", .{k.initrd})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(initrd_opt);

    // Build options — add btrfs rootflags if needed
    const btrfs_flags = if (sys.is_btrfs and sys.root_subvol.len > 0)
        try std.fmt.allocPrint(allocator, " rootflags=subvol={s}", .{sys.root_subvol})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(btrfs_flags);

    var content_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer content_buf.deinit(allocator);
    const writer = content_buf.writer(allocator);

    try writer.print("\"Boot Linux {s}\" \"{s} root=UUID={s} rw{s}{s}\"\n", .{ k.version, k.path, sys.uuid, btrfs_flags, initrd_opt });

    // Fallback entry with subvol=@ if different
    if (sys.is_btrfs and sys.root_subvol.len > 0 and !std.mem.eql(u8, sys.root_subvol, "@")) {
        try writer.print("\"Boot Linux {s} (@ fallback)\" \"{s} root=UUID={s} rw rootflags=subvol=@{s}\"\n", .{ k.version, k.path, sys.uuid, initrd_opt });
    }

    const file = std.fs.cwd().createFile(conf_path, .{}) catch |e| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Cannot write refind_linux.conf: {}", .{e}) };
    };
    defer file.close();
    try file.writeAll(content_buf.items);

    return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "rEFInd config written for kernel {s}", .{k.version}) };
}

pub fn fixSystemdBoot(allocator: std.mem.Allocator, sys: *types.SystemInfo) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    const loader_dir = try std.fmt.allocPrint(allocator, "{s}/boot/loader", .{sys.mount_point});
    defer allocator.free(loader_dir);
    const entries_dir = try std.fmt.allocPrint(allocator, "{s}/entries", .{loader_dir});
    defer allocator.free(entries_dir);

    std.fs.cwd().makePath(entries_dir) catch {};

    // loader.conf
    const loader_conf = try std.fmt.allocPrint(allocator, "{s}/loader.conf", .{loader_dir});
    defer allocator.free(loader_conf);
    if (std.fs.cwd().createFile(loader_conf, .{})) |f| {
        defer f.close();
        f.writeAll("default arch.conf\ntimeout 4\nconsole-mode max\neditor no\n") catch {};
    } else |_| {}

    // Per-kernel entries
    for (sys.kernels.items) |k| {
        if (!k.exists) continue;
        const entry_path = try std.fmt.allocPrint(allocator, "{s}/{s}.conf", .{ entries_dir, k.version });
        defer allocator.free(entry_path);

        const initrd_line = if (k.initrd.len > 0)
            try std.fmt.allocPrint(allocator, "initrd  /{s}\n", .{k.initrd})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(initrd_line);

        const btrfs_opt = if (sys.is_btrfs and sys.root_subvol.len > 0)
            try std.fmt.allocPrint(allocator, " rootflags=subvol={s}", .{sys.root_subvol})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(btrfs_opt);

        const content = try std.fmt.allocPrint(allocator, "title   Linux ({s})\nlinux   /{s}\n{s}options root=UUID={s} rw{s}\n", .{ k.version, k.path, initrd_line, sys.uuid, btrfs_opt });
        defer allocator.free(content);

        if (std.fs.cwd().createFile(entry_path, .{})) |f| {
            defer f.close();
            f.writeAll(content) catch {};
        } else |_| {}
    }

    return .{ .success = true, .message = try allocator.dupe(u8, "systemd-boot entries updated") };
}

// ---------------------------------------------------------------------------
// Full auto-repair sequence
// ---------------------------------------------------------------------------

pub fn performAutoRepair(allocator: std.mem.Allocator, sys: *types.SystemInfo) !types.FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System is not mounted!") };

    detection.detectDistribution(allocator, sys);
    detection.detectPackageManager(allocator, sys);
    detection.detectBootLoader(allocator, sys);

    var errors: std.ArrayListUnmanaged(u8) = .empty;
    defer errors.deinit(allocator);
    const ew = errors.writer(allocator);

    // 1. Patch mkinitcpio if present
    const mkinit = try chroot.ensureMkinitcpioConfig(allocator, sys);
    allocator.free(mkinit.message);

    // 2. Regenerate initramfs
    const initrd = try chroot.regenerateInitramfs(allocator, sys);
    defer allocator.free(initrd.message);
    if (!initrd.success) try ew.print("initramfs: {s}\n", .{initrd.message});

    // 3. Fix bootloader
    const boot_res = switch (sys.boot_loader) {
        .grub => try fixGrub(allocator, sys),
        .refind => try fixRefind(allocator, sys, 0),
        .systemd_boot => try fixSystemdBoot(allocator, sys),
        .unknown => types.FixResult{ .success = false, .message = try allocator.dupe(u8, "Unknown bootloader") },
    };
    defer allocator.free(boot_res.message);
    if (!boot_res.success) try ew.print("bootloader: {s}\n", .{boot_res.message});

    if (errors.items.len > 0) {
        return .{ .success = false, .message = try errors.toOwnedSlice(allocator) };
    }
    return .{ .success = true, .message = try allocator.dupe(u8, "Auto-repair completed successfully") };
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn stripPartitionSuffix(allocator: std.mem.Allocator, device: []const u8) ![]const u8 {
    // nvme0n1p2 → nvme0n1
    if (std.mem.indexOf(u8, device, "nvme") != null) {
        var i = device.len;
        while (i > 0 and std.ascii.isDigit(device[i - 1])) i -= 1;
        if (i > 0 and device[i - 1] == 'p') i -= 1;
        return allocator.dupe(u8, device[0..i]);
    }
    // sda2 → sda
    var i = device.len;
    while (i > 0 and std.ascii.isDigit(device[i - 1])) i -= 1;
    return allocator.dupe(u8, device[0..i]);
}
