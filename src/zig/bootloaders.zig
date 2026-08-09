const std = @import("std");
const system = @import("system.zig");

pub const FixResult = struct { success: bool, message: []const u8 };

pub fn detectBootLoader(allocator: std.mem.Allocator, sys: *system.SystemInfo) void {
    const root = if (sys.mounted) sys.mount_point else "";

    // Check GRUB
    const grub_path1 = std.fmt.allocPrint(allocator, "{s}/boot/grub", .{root}) catch return;
    defer allocator.free(grub_path1);
    const grub_path2 = std.fmt.allocPrint(allocator, "{s}/boot/grub2", .{root}) catch return;
    defer allocator.free(grub_path2);

    if (fileExists(grub_path1) or fileExists(grub_path2)) {
        sys.boot_loader = .grub;
        return;
    }

    // Check rEFInd
    const refind_path1 = std.fmt.allocPrint(allocator, "{s}/boot/efi/EFI/refind", .{root}) catch return;
    defer allocator.free(refind_path1);
    const refind_path2 = std.fmt.allocPrint(allocator, "{s}/boot/EFI/refind", .{root}) catch return;
    defer allocator.free(refind_path2);

    if (fileExists(refind_path1) or fileExists(refind_path2)) {
        sys.boot_loader = .refind;
        return;
    }

    // Check systemd-boot
    const sdb_path1 = std.fmt.allocPrint(allocator, "{s}/boot/efi/EFI/systemd", .{root}) catch return;
    defer allocator.free(sdb_path1);
    const sdb_path2 = std.fmt.allocPrint(allocator, "{s}/boot/loader/loader.conf", .{root}) catch return;
    defer allocator.free(sdb_path2);

    if (fileExists(sdb_path1) or fileExists(sdb_path2)) {
        sys.boot_loader = .systemd_boot;
        return;
    }

    sys.boot_loader = .unknown;
}

pub fn fixGrub(allocator: std.mem.Allocator, sys: *system.SystemInfo) !FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System partition is not mounted!") };

    // Run grub-mkconfig
    const res1 = system.executeCmd(allocator, &.{ "chroot", sys.mount_point, "grub-mkconfig", "-o", "/boot/grub/grub.cfg" }) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "grub-mkconfig execution failed: {}", .{err}) };
    };
    defer allocator.free(res1.stdout);
    defer allocator.free(res1.stderr);

    if (res1.exit_code != 0) {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "grub-mkconfig failed: {s}", .{res1.stderr}) };
    }

    return .{ .success = true, .message = try allocator.dupe(u8, "GRUB configuration updated successfully!") };
}

pub fn fixRefind(allocator: std.mem.Allocator, sys: *system.SystemInfo, selected_kernel_idx: usize) !FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System partition is not mounted!") };
    if (sys.kernels.items.len == 0) return .{ .success = false, .message = try allocator.dupe(u8, "No kernels found in /boot!") };

    const idx = if (selected_kernel_idx < sys.kernels.items.len) selected_kernel_idx else 0;
    const k = sys.kernels.items[idx];

    // Find refind config directory
    const refind_dir = try std.fmt.allocPrint(allocator, "{s}/boot/efi/EFI/refind", .{sys.mount_point});
    defer allocator.free(refind_dir);

    std.fs.cwd().makePath(refind_dir) catch {};

    const conf_path = try std.fmt.allocPrint(allocator, "{s}/refind_linux.conf", .{refind_dir});
    defer allocator.free(conf_path);

    const initrd_opt = if (k.initrd.len > 0)
        try std.fmt.allocPrint(allocator, " initrd={s}", .{k.initrd})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(initrd_opt);

    const content = try std.fmt.allocPrint(allocator,
        \\"Boot Linux with {s}" "{s} root=UUID={s} rw{s}"
        \\
    , .{ k.version, k.path, sys.uuid, initrd_opt });
    defer allocator.free(content);

    const file = std.fs.cwd().createFile(conf_path, .{}) catch |err| {
        return .{ .success = false, .message = try std.fmt.allocPrint(allocator, "Could not write refind_linux.conf: {}", .{err}) };
    };
    defer file.close();

    try file.writeAll(content);

    return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "rEFInd config created for kernel {s}!", .{k.version}) };
}

pub fn fixSystemdBoot(allocator: std.mem.Allocator, sys: *system.SystemInfo) !FixResult {
    if (!sys.mounted) return .{ .success = false, .message = try allocator.dupe(u8, "System partition is not mounted!") };

    const loader_dir = try std.fmt.allocPrint(allocator, "{s}/boot/loader", .{sys.mount_point});
    defer allocator.free(loader_dir);
    const entries_dir = try std.fmt.allocPrint(allocator, "{s}/boot/loader/entries", .{sys.mount_point});
    defer allocator.free(entries_dir);

    std.fs.cwd().makePath(entries_dir) catch {};

    // Write loader.conf
    const loader_conf_path = try std.fmt.allocPrint(allocator, "{s}/loader.conf", .{loader_dir});
    defer allocator.free(loader_conf_path);

    if (std.fs.cwd().createFile(loader_conf_path, .{})) |file| {
        defer file.close();
        file.writeAll("default arch.conf\ntimeout 4\nconsole-mode max\neditor no\n") catch {};
    } else |_| {}

    // Write entry configs
    for (sys.kernels.items) |k| {
        if (!k.exists) continue;

        const entry_path = try std.fmt.allocPrint(allocator, "{s}/{s}.conf", .{ entries_dir, k.version });
        defer allocator.free(entry_path);

        const initrd_line = if (k.initrd.len > 0)
            try std.fmt.allocPrint(allocator, "initrd  /{s}\n", .{k.initrd})
        else
            try allocator.dupe(u8, "");
        defer allocator.free(initrd_line);

        const content = try std.fmt.allocPrint(allocator,
            \\title   Linux ({s})
            \\linux   /{s}
            \\{s}options root=UUID={s} rw
            \\
        , .{ k.version, k.path, initrd_line, sys.uuid });
        defer allocator.free(content);

        if (std.fs.cwd().createFile(entry_path, .{})) |file| {
            defer file.close();
            file.writeAll(content) catch {};
        } else |_| {}
    }

    return .{ .success = true, .message = try allocator.dupe(u8, "systemd-boot entries updated successfully!") };
}

fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}
