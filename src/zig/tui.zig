const std = @import("std");
const posix = std.posix;
const system = @import("system.zig");
const kernels = @import("kernels.zig");
const bootloaders = @import("bootloaders.zig");
const chroot = @import("chroot.zig");

// Terminal control ANSI sequences
pub const ESC = "\x1b";
pub const CSI = "\x1b[";
pub const RESET = CSI ++ "0m";
pub const BOLD = CSI ++ "1m";
pub const DIM = CSI ++ "2m";
pub const HIDE_CURSOR = CSI ++ "?25l";
pub const SHOW_CURSOR = CSI ++ "?25h";
pub const ALT_SCREEN = CSI ++ "?1049h";
pub const NORM_SCREEN = CSI ++ "?1049l";
pub const CLEAR = CSI ++ "2J" ++ CSI ++ "H";

// Dark & Fusian Purple Truecolor Palette
pub const COLOR_CYBER_BG = CSI ++ "48;2;18;9;26m"; // #12091A
pub const COLOR_PANEL_BG = CSI ++ "48;2;30;16;42m"; // #1E102A
pub const COLOR_SEL_BG = CSI ++ "48;2;90;15;65m"; // #5A0F41

pub const COLOR_FUSIAN = CSI ++ "38;2;224;17;95m"; // #E0115F Fusian Purple
pub const COLOR_FUCHSIA = CSI ++ "38;2;255;0;127m"; // #FF007F Neon Fuchsia
pub const COLOR_VIOLET = CSI ++ "38;2;157;0;255m"; // #9D00FF Electric Violet
pub const COLOR_CYAN = CSI ++ "38;2;0;245;255m"; // #00F5FF Cyber Cyan
pub const COLOR_AMBER = CSI ++ "38;2;255;176;0m"; // #FFB000 Glow Amber
pub const COLOR_MINT = CSI ++ "38;2;0;255;170m"; // #00FFAA Glow Mint
pub const COLOR_TEXT = CSI ++ "38;2;240;230;255m"; // #F0E6FF Silver-White
pub const COLOR_DIM = CSI ++ "38;2;138;123;156m"; // #8A7B9C Muted Violet
pub const COLOR_ERR = CSI ++ "38;2;255;50;100m"; // Error Red-Fuchsia

pub const CuteTUI = struct {
    allocator: std.mem.Allocator,
    sys_info: system.SystemInfo,
    selected_menu: usize = 0,
    running: bool = true,
    demo_mode: bool = false,
    debug_mode: bool = false,
    status_msg: [512]u8 = [_]u8{0} ** 512,
    status_len: usize = 0,
    status_type: u8 = 0, // 0: info, 1: success, 2: err, 3: warn
    frame_count: u64 = 0,
    original_termios: ?posix.termios = null,
    raw_mode: bool = false,
    term_width: u16 = 80,
    term_height: u16 = 24,

    pub fn init(allocator: std.mem.Allocator, demo_mode: bool, debug_mode: bool) CuteTUI {
        return .{
            .allocator = allocator,
            .sys_info = .{},
            .demo_mode = demo_mode,
            .debug_mode = debug_mode,
        };
    }

    pub fn deinit(self: *CuteTUI) void {
        self.sys_info.deinit(self.allocator);
    }

    pub fn enableRawMode(self: *CuteTUI) !void {
        if (self.raw_mode) return;
        const stdin_fd = posix.STDIN_FILENO;
        self.original_termios = try posix.tcgetattr(stdin_fd);

        var raw = self.original_termios.?;
        raw.iflag.BRKINT = false;
        raw.iflag.ICRNL = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.IXON = false;
        // OPOST left enabled so \n -> \r\n translation still works
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.IEXTEN = false;
        raw.lflag.ISIG = false;
        raw.cc[@intFromEnum(posix.V.MIN)] = 0;
        raw.cc[@intFromEnum(posix.V.TIME)] = 1;

        try posix.tcsetattr(stdin_fd, .FLUSH, raw);
        self.raw_mode = true;
    }

    pub fn disableRawMode(self: *CuteTUI) void {
        if (!self.raw_mode or self.original_termios == null) return;
        posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, self.original_termios.?) catch {};
        self.raw_mode = false;
    }

    pub fn updateTerminalSize(self: *CuteTUI) void {
        var winsz: posix.winsize = undefined;
        const err = posix.system.ioctl(posix.STDOUT_FILENO, posix.T.IOCGWINSZ, @intFromPtr(&winsz));
        if (err == 0 and winsz.col > 0 and winsz.row > 0) {
            self.term_width = winsz.col;
            self.term_height = winsz.row;
        }
    }

    pub fn setStatus(self: *CuteTUI, msg: []const u8, stype: u8) void {
        const len = @min(msg.len, self.status_msg.len - 1);
        @memcpy(self.status_msg[0..len], msg[0..len]);
        self.status_msg[len] = 0;
        self.status_len = len;
        self.status_type = stype;
    }

    // Shared menu data — single source of truth used by both render modes.
    const menu_items = [_][]const u8{
        "Fix My System (Auto-Repair)",
        "Emergency Shell (Manual)",
        "Regenerate Initramfs",
        "Fix Boot Configuration",
        "Show System Information",
        "Fix Pacman Cache",
        "Exit",
    };
    const menu_icons = [_]u8{ '!', '$', '*', '@', 'i', 'x', '>' };

    pub fn render(self: *CuteTUI) !void {
        var buf_arr: std.ArrayListUnmanaged(u8) = .empty;
        defer buf_arr.deinit(self.allocator);
        const writer = buf_arr.writer(self.allocator);

        try writer.writeAll(CSI ++ "1;1H");

        if (self.term_width >= 56 and self.term_height >= 22) {
            try self.renderFull(writer);
        } else {
            try self.renderCompact(writer);
        }

        // Erase stale content from previous larger renders.
        try writer.writeAll(RESET ++ CSI ++ "J");

        const stdout = std.fs.File.stdout();
        try stdout.writeAll(buf_arr.items);
    }

    // Full layout: banner + box + subtitle. Requires >= 56x22.
    fn renderFull(self: *CuteTUI, writer: anytype) !void {

        // Box geometry: 48 cols inner width between │ chars.
        // Banner rows (48 inner):
        //   " - debork  -  v2.0 (Zig Rewrite)              " = 48
        //   "   Cosmopolitan Linux Boot Fixer               " = 48
        //
        // Menu rows (48 inner):
        //   " ▶ I item(43)  " = 1+1+1+1+1+43+1 = 48 (all chars 1-wide)

        // Banner box — inner width 48
        // ╭ + 48×─ + ╮
        try writer.print("    {s}╭────────────────────────────────────────────────╮{s}\r\n", .{ COLOR_VIOLET, COLOR_CYBER_BG });
        // " - debork  -  v2.0 (Zig Rewrite)              " (48 cols)
        try writer.print("    {s}│{s} - {s}debork {s} -  {s}v2.0 (Zig Rewrite){s}              {s}│{s}\r\n", .{
            COLOR_VIOLET, COLOR_FUCHSIA, COLOR_TEXT, COLOR_FUCHSIA, COLOR_MINT, COLOR_VIOLET, COLOR_DIM, COLOR_CYBER_BG,
        });
        // "   Cosmopolitan Linux Boot Fixer               " (48 cols)
        try writer.print("    {s}│{s}   Cosmopolitan Linux Boot Fixer               {s}│{s}\r\n", .{
            COLOR_VIOLET, COLOR_FUSIAN, COLOR_VIOLET, COLOR_CYBER_BG,
        });
        try writer.print("    {s}╰────────────────────────────────────────────────╯{s}\r\n", .{ COLOR_VIOLET, COLOR_CYBER_BG });

        // Subtitle — standalone, no box alignment
        try writer.print("    {s}~ ~ ~  {s}Dark & Fusian Cyber Recovery{s}  ~ ~ ~\r\n\r\n", .{ COLOR_FUSIAN, COLOR_FUCHSIA, RESET });

        // Menu box — inner width 48
        // Row: " " sel(1) " " icon(1) " " item(42) " " = 48
        try writer.print("    {s}╭────────────────────────────────────────────────╮{s}\r\n", .{ COLOR_PANEL_BG ++ COLOR_FUSIAN, COLOR_CYBER_BG });
        for (menu_items, 0..) |item, i| {
            if (i == self.selected_menu) {
                try writer.print("    {s}│ {s}▶ {c} {s}{s:<42}{s} │{s}\r\n", .{
                    COLOR_SEL_BG ++ COLOR_FUCHSIA, COLOR_AMBER ++ BOLD,
                    menu_icons[i],                 COLOR_TEXT ++ BOLD,
                    item,                          COLOR_FUCHSIA,
                    COLOR_CYBER_BG,
                });
            } else {
                try writer.print("    {s}│ {s}  {c} {s}{s:<42}{s} │{s}\r\n", .{
                    COLOR_PANEL_BG ++ COLOR_VIOLET, COLOR_DIM,
                    menu_icons[i],                  COLOR_TEXT ++ DIM,
                    item,                           COLOR_VIOLET,
                    COLOR_CYBER_BG,
                });
            }
        }
        try writer.print("    {s}╰────────────────────────────────────────────────╯{s}\r\n", .{ COLOR_PANEL_BG ++ COLOR_FUSIAN, COLOR_CYBER_BG });

        try self.renderStatusAndFooter(writer);
    }

    // Compact layout: no banner box, minimal chrome. Works down to ~30x10.
    // For terminals shorter than the menu, shows a scrolling window of items.
    fn renderCompact(self: *CuteTUI, writer: anytype) !void {
        const w = self.term_width;
        const h = self.term_height;

        // Header — one line, truncated to terminal width
        const demo_tag: []const u8 = if (self.demo_mode) " [demo]" else "";
        if (w >= 24) {
            try writer.print("{s}debork v2.0{s}{s}\r\n", .{ COLOR_FUCHSIA ++ BOLD, COLOR_DIM, demo_tag });
        } else {
            try writer.print("{s}debork{s}\r\n", .{ COLOR_FUCHSIA ++ BOLD, RESET });
        }

        // Status line (only if we have room)
        if (h > 6) {
            const bl = self.sys_info.boot_loader.name();
            const mnt: []const u8 = if (self.sys_info.mounted) "+" else "-";
            const mnt_color: []const u8 = if (self.sys_info.mounted) COLOR_MINT else COLOR_ERR;
            try writer.print("{s}[{s}{s}{s}] {s}{s}\r\n", .{ COLOR_DIM, mnt_color, mnt, COLOR_DIM, COLOR_CYAN, bl });
        }

        // How many rows can we give to the menu?
        // Reserve: 1 header + 1 status + 1 footer + 1 notification = 4
        const reserved: u16 = if (h > 6) 4 else 2;
        const menu_rows = if (h > reserved) h - reserved else 1;
        const n_items: usize = menu_items.len;

        // Scroll window: keep selected item visible
        const visible: usize = @min(n_items, menu_rows);
        const scroll_start: usize = blk: {
            if (self.selected_menu < visible) break :blk 0;
            break :blk self.selected_menu - visible + 1;
        };
        const scroll_end: usize = @min(scroll_start + visible, n_items);

        // Scroll indicator top
        if (scroll_start > 0) {
            try writer.print("{s}  ^ {d} more\r\n", .{ COLOR_DIM, scroll_start });
        }

        // Max item label width: terminal width minus prefix ("▶ x " = 4) and 1 padding
        const label_width: usize = if (w > 6) w - 5 else 1;

        for (scroll_start..scroll_end) |i| {
            const item = menu_items[i];
            // Truncate label to fit
            const label = if (item.len > label_width) item[0..label_width] else item;
            if (i == self.selected_menu) {
                try writer.print("{s}▶ {c} {s}{s}{s}\r\n", .{
                    COLOR_FUCHSIA ++ BOLD, menu_icons[i], COLOR_TEXT ++ BOLD, label, RESET,
                });
            } else {
                try writer.print("{s}  {c} {s}{s}{s}\r\n", .{
                    COLOR_DIM, menu_icons[i], COLOR_TEXT, label, RESET,
                });
            }
        }

        // Scroll indicator bottom
        if (scroll_end < n_items) {
            try writer.print("{s}  v {d} more\r\n", .{ COLOR_DIM, n_items - scroll_end });
        }

        try self.renderStatusAndFooter(writer);
    }

    // Status + notification + footer — shared by both render modes.
    fn renderStatusAndFooter(self: *CuteTUI, writer: anytype) !void {
        if (self.status_len > 0) {
            const icon: []const u8 = switch (self.status_type) {
                1 => COLOR_MINT ++ "+ ",
                2 => COLOR_ERR ++ "x ",
                3 => COLOR_AMBER ++ "! ",
                else => COLOR_CYAN ++ "> ",
            };
            try writer.print("{s}{s}{s}\r\n", .{ icon, COLOR_TEXT, self.status_msg[0..self.status_len] });
        }
        try writer.print("{s}[j/k/Enter/q]{s}\r\n", .{ COLOR_DIM, RESET });
    }

    pub fn handleInput(self: *CuteTUI) !void {
        var buf: [8]u8 = undefined;
        const stdin = std.fs.File.stdin();
        const read_bytes = stdin.read(&buf) catch return;
        if (read_bytes == 0) return;

        const c = buf[0];
        const menu_count: usize = 7;

        if (c == '\x1b') {
            if (read_bytes >= 3 and buf[1] == '[') {
                switch (buf[2]) {
                    'A' => { // Up
                        if (self.selected_menu > 0) self.selected_menu -= 1 else self.selected_menu = menu_count - 1;
                    },
                    'B' => { // Down
                        self.selected_menu = (self.selected_menu + 1) % menu_count;
                    },
                    else => {},
                }
            }
        } else switch (c) {
            'k' => {
                if (self.selected_menu > 0) self.selected_menu -= 1 else self.selected_menu = menu_count - 1;
            },
            'j' => {
                self.selected_menu = (self.selected_menu + 1) % menu_count;
            },
            '\r', '\n' => {
                try self.executeSelectedMenu();
            },
            'q', 'Q' => {
                self.running = false;
            },
            else => {},
        }
    }

    fn executeSelectedMenu(self: *CuteTUI) !void {
        switch (self.selected_menu) {
            0 => { // Fix System (Auto-Repair)
                self.setStatus("Starting system auto-repair...", 0);
                try self.render();

                if (!self.sys_info.mounted and !self.demo_mode) {
                    try self.interactiveSelectPartition();
                }

                if (self.demo_mode) {
                    self.setStatus("Demo Mode: System repair simulated cleanly!", 1);
                    return;
                }

                system.detectDistribution(self.allocator, &self.sys_info);
                system.detectPackageManager(self.allocator, &self.sys_info);
                bootloaders.detectBootLoader(self.allocator, &self.sys_info);

                // Patch mkinitcpio.conf hooks/modules before regenerating initramfs
                const mkinit_res = chroot.ensureMkinitcpioConfig(self.allocator, &self.sys_info) catch null;
                if (mkinit_res) |r| {
                    defer self.allocator.free(r.message);
                    if (!r.success) self.setStatus(r.message, 3);
                }

                const boot_res = switch (self.sys_info.boot_loader) {
                    .grub => try bootloaders.fixGrub(self.allocator, &self.sys_info),
                    .refind => try bootloaders.fixRefind(self.allocator, &self.sys_info, 0),
                    .systemd_boot => try bootloaders.fixSystemdBoot(self.allocator, &self.sys_info),
                    .unknown => bootloaders.FixResult{ .success = false, .message = try self.allocator.dupe(u8, "Unknown bootloader type!") },
                };
                defer self.allocator.free(boot_res.message);

                const init_res = try chroot.regenerateInitramfs(self.allocator, &self.sys_info);
                defer self.allocator.free(init_res.message);

                if (boot_res.success) {
                    self.setStatus(boot_res.message, 1);
                } else {
                    self.setStatus(boot_res.message, 2);
                }
            },
            1 => { // Emergency Shell
                if (self.demo_mode) {
                    self.setStatus("Demo Mode: Emergency shell skipped.", 3);
                    return;
                }
                self.disableRawMode();
                const stdout = std.fs.File.stdout();
                _ = stdout.writeAll(CLEAR ++ SHOW_CURSOR ++ COLOR_AMBER ++ "=== Emergency Shell Mode ===\nType 'exit' to return to debork TUI.\n\n" ++ RESET) catch {};

                chroot.launchEmergencyShell(self.allocator, &self.sys_info);

                try self.enableRawMode();
                _ = stdout.writeAll(ALT_SCREEN ++ HIDE_CURSOR) catch {};
                self.setStatus("Returned from emergency shell.", 0);
            },
            2 => { // Regenerate Initramfs
                if (self.demo_mode) {
                    self.setStatus("Demo Mode: Initramfs regeneration simulated!", 1);
                    return;
                }
                const res = try chroot.regenerateInitramfs(self.allocator, &self.sys_info);
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            3 => { // Fix Boot Configuration
                if (self.demo_mode) {
                    self.setStatus("Demo Mode: Bootloader repair simulated!", 1);
                    return;
                }
                bootloaders.detectBootLoader(self.allocator, &self.sys_info);
                const res = switch (self.sys_info.boot_loader) {
                    .grub => try bootloaders.fixGrub(self.allocator, &self.sys_info),
                    .refind => try bootloaders.fixRefind(self.allocator, &self.sys_info, 0),
                    .systemd_boot => try bootloaders.fixSystemdBoot(self.allocator, &self.sys_info),
                    .unknown => bootloaders.FixResult{ .success = false, .message = try self.allocator.dupe(u8, "Could not detect bootloader type!") },
                };
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            4 => { // Show System Information
                try self.showSystemInfoScreen();
            },
            5 => { // Fix Pacman Cache
                if (self.demo_mode) {
                    self.setStatus("Demo Mode: Pacman cache fix simulated!", 1);
                    return;
                }
                const res = try chroot.fixPacmanCache(self.allocator);
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            6 => { // Exit
                self.running = false;
            },
            else => {},
        }
    }

    fn interactiveSelectPartition(self: *CuteTUI) !void {
        const parts = try system.scanPartitions(self.allocator);
        defer {
            for (parts) |*p| p.deinit(self.allocator);
            self.allocator.free(parts);
        }

        if (parts.len == 0) {
            self.setStatus("No suitable Linux root partitions found!", 2);
            return;
        }

        // Leave raw/alt-screen mode so we can print normally
        self.disableRawMode();
        const stdout = std.fs.File.stdout();
        _ = stdout.writeAll(NORM_SCREEN ++ SHOW_CURSOR ++ CLEAR) catch {};

        // Print header
        _ = stdout.writeAll(COLOR_FUCHSIA ++ BOLD ++ "Select Target Partition:\n" ++ RESET) catch {};

        // List partitions
        for (parts, 0..) |p, i| {
            const uuid_short = if (p.uuid.len >= 8) p.uuid[0..8] else p.uuid;
            var line_buf: [256]u8 = undefined;
            const label_part = if (p.label.len > 0)
                std.fmt.bufPrint(&line_buf, "  {d})  {s}  {s}  {s}  {s}...  [{s}]\n", .{ i + 1, p.device, p.fstype, p.size, uuid_short, p.label }) catch ""
            else
                std.fmt.bufPrint(&line_buf, "  {d})  {s}  {s}  {s}  {s}...\n", .{ i + 1, p.device, p.fstype, p.size, uuid_short }) catch "";
            _ = stdout.writeAll(COLOR_TEXT) catch {};
            _ = stdout.writeAll(label_part) catch {};
        }

        // Prompt
        _ = stdout.writeAll(COLOR_CYAN) catch {};
        var prompt_buf: [64]u8 = undefined;
        const prompt = std.fmt.bufPrint(&prompt_buf, "Enter number (1-{d}) or 0 to cancel: ", .{parts.len}) catch "Enter number or 0 to cancel: ";
        _ = stdout.writeAll(prompt) catch {};
        _ = stdout.writeAll(RESET) catch {};

        // Read from /dev/tty (stdin may be broken under sudo)
        var chosen_idx: ?usize = null;
        if (std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_only })) |tty| {
            defer tty.close();
            var line_buf2: [32]u8 = undefined;
            const n = tty.read(&line_buf2) catch 0;
            if (n > 0) {
                const trimmed = std.mem.trim(u8, line_buf2[0..n], &std.ascii.whitespace);
                if (std.fmt.parseInt(usize, trimmed, 10)) |num| {
                    if (num >= 1 and num <= parts.len) {
                        chosen_idx = num - 1;
                    }
                    // 0 means cancel
                } else |_| {}
            }
        } else |_| {}

        // Restore raw mode and alt screen
        self.enableRawMode() catch {};
        _ = stdout.writeAll(ALT_SCREEN ++ HIDE_CURSOR) catch {};

        const idx = chosen_idx orelse {
            self.setStatus("Cancelled", 3);
            return;
        };

        const chosen_dev = parts[idx].device;
        const mounted_ok = try system.mountSystem(self.allocator, &self.sys_info, chosen_dev);
        if (mounted_ok) {
            self.setStatus("System partition mounted successfully!", 1);
            bootloaders.detectBootLoader(self.allocator, &self.sys_info);
            kernels.scanKernels(self.allocator, &self.sys_info) catch {};
        } else {
            self.setStatus("Failed to mount target partition!", 2);
        }
    }

    fn showSystemInfoScreen(self: *CuteTUI) !void {
        if (!self.demo_mode and self.sys_info.mounted) {
            bootloaders.detectBootLoader(self.allocator, &self.sys_info);
            kernels.scanKernels(self.allocator, &self.sys_info) catch {};
        }

        const stdout = std.fs.File.stdout();
        _ = stdout.writeAll(CLEAR ++ CSI ++ "1;1H" ++ COLOR_FUCHSIA ++ BOLD ++ "=== System Information ===\n\n" ++ RESET) catch {};

        var buf: [1024]u8 = undefined;
        const info_str = try std.fmt.bufPrint(&buf,
            \\Device: {s}
            \\UUID: {s}
            \\Mount Point: {s}
            \\Bootloader: {s}
            \\Filesystem: {s} (btrfs: {})
            \\Kernels Found: {}
            \\
            \\Press any key to return to menu...
            \\
        , .{
            self.sys_info.device,
            self.sys_info.uuid,
            self.sys_info.mount_point,
            self.sys_info.boot_loader.name(),
            self.sys_info.fstype,
            self.sys_info.is_btrfs,
            self.sys_info.kernels.items.len,
        });

        _ = stdout.writeAll(COLOR_TEXT) catch {};
        _ = stdout.writeAll(info_str) catch {};

        var key: [1]u8 = undefined;
        const stdin = std.fs.File.stdin();
        while (true) {
            const n = stdin.read(&key) catch 0;
            if (n > 0) break;
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    pub fn run(self: *CuteTUI) !void {
        const stdout = std.fs.File.stdout();
        try stdout.writeAll(ALT_SCREEN ++ HIDE_CURSOR ++ CLEAR);
        try self.enableRawMode();
        defer {
            self.disableRawMode();
            _ = stdout.writeAll(SHOW_CURSOR ++ NORM_SCREEN ++ RESET) catch {};
        }

        while (self.running) {
            self.updateTerminalSize();
            try self.render();
            try self.handleInput();
            self.frame_count += 1;
            std.Thread.sleep(16 * std.time.ns_per_ms); // ~60 FPS
        }
    }
};
