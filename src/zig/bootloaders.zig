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

    // Detect boot device by stripping partition suffix from sys.device
    const dev = sys.device;
    var boot_dev: []const u8 = dev;
    // nvme devices end in pN (e.g. /dev/nvme0n1p2 -> /dev/nvme0n1)
    if (std.mem.indexOf(u8, dev, "nvme") != null) {
        var i: usize = dev.len;
        while (i > 0 and std.ascii.isDigit(dev[i - 1])) : (i -= 1) {}
        if (i > 0 and dev[i - 1] == 'p') i -= 1;
        boot_dev = dev[0..i];
    } else {
        var i: usize = dev.len;
        while (i > 0 and std.ascii.isDigit(dev[i - 1])) : (i -= 1) {}
        boot_dev = dev[0..i];
    }

    // Check if grub-install is available inside the chroot
    const gi_usr = try std.fmt.allocPrint(allocator, "{s}/usr/bin/grub-install", .{sys.mount_point});
    defer allocator.free(gi_usr);
    const gi_sbin = try std.fmt.allocPrint(allocator, "{s}/usr/sbin/grub-install", .{sys.mount_point});
    defer allocator.free(gi_sbin);

    var install_msg: []const u8 = try allocator.dupe(u8, "");
    defer allocator.free(install_msg);

    if (fileExists(gi_usr) or fileExists(gi_sbin)) {
        // Try EFI install first
        const efi_res = system.executeCmd(allocator, &.{
            "chroot",                    sys.mount_point,
            "grub-install",              "--target=x86_64-efi",
            "--efi-directory=/boot/efi", "--bootloader-id=GRUB",
            "--recheck",
        }) catch null;
        if (efi_res) |r| {
            defer allocator.free(r.stdout);
            defer allocator.free(r.stderr);
            if (r.exit_code == 0) {
                allocator.free(install_msg);
                install_msg = try allocator.dupe(u8, " grub-install(EFI): OK.");
            } else {
                // EFI failed — fallback to BIOS
                const bios_res = system.executeCmd(allocator, &.{ "grub-install", boot_dev }) catch null;
                if (bios_res) |br| {
                    defer allocator.free(br.stdout);
                    defer allocator.free(br.stderr);
                    allocator.free(install_msg);
                    install_msg = if (br.exit_code == 0)
                        try allocator.dupe(u8, " grub-install(BIOS): OK.")
                    else
                        try std.fmt.allocPrint(allocator, " grub-install(BIOS) failed: {s}", .{br.stderr});
                }
            }
        }
    }

    return .{ .success = true, .message = try std.fmt.allocPrint(allocator, "GRUB configuration updated successfully!{s}", .{install_msg}) };
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

    var content: []const u8 = undefined;
    if (sys.is_btrfs and sys.root_subvol.len > 0) {
        const subvol = sys.root_subvol;
        const main_line = try std.fmt.allocPrint(allocator,
            \\"{s}" "{s} root=UUID={s} rw rootflags=subvol={s}{s}"
            \\
        , .{ k.version, k.path, sys.uuid, subvol, initrd_opt });
        defer allocator.free(main_line);
        // Add fallback with subvol=@ if it differs from the detected subvol
        if (!std.mem.eql(u8, subvol, "@")) {
            const fallback_line = try std.fmt.allocPrint(allocator,
                \\"Boot Linux with {s} (fallback subvol)" "{s} root=UUID={s} rw rootflags=subvol=@{s}"
                \\
            , .{ k.version, k.path, sys.uuid, initrd_opt });
            defer allocator.free(fallback_line);
            content = try std.mem.concat(allocator, u8, &.{ main_line, fallback_line });
        } else {
            content = try allocator.dupe(u8, main_line);
        }
    } else {
        content = try std.fmt.allocPrint(allocator,
            \\"{s}" "{s} root=UUID={s} rw{s}"
            \\
        , .{ k.version, k.path, sys.uuid, initrd_opt });
    }
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
