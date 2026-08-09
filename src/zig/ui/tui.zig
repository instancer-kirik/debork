const std = @import("std");
const posix = std.posix;
const types = @import("../core/types.zig");
const detection = @import("../system/detection.zig");
const mount = @import("../filesystem/mount.zig");
const chroot = @import("../system/chroot.zig");
const ops = @import("../repair/operations.zig");

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------
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

pub const COLOR_CYBER_BG = CSI ++ "48;2;18;9;26m";
pub const COLOR_PANEL_BG = CSI ++ "48;2;30;16;42m";
pub const COLOR_SEL_BG = CSI ++ "48;2;90;15;65m";

pub const COLOR_FUCHSIA = CSI ++ "38;2;255;0;127m";
pub const COLOR_FUSIAN = CSI ++ "38;2;224;17;95m";
pub const COLOR_VIOLET = CSI ++ "38;2;157;0;255m";
pub const COLOR_CYAN = CSI ++ "38;2;0;245;255m";
pub const COLOR_AMBER = CSI ++ "38;2;255;176;0m";
pub const COLOR_MINT = CSI ++ "38;2;0;255;170m";
pub const COLOR_TEXT = CSI ++ "38;2;240;230;255m";
pub const COLOR_DIM = CSI ++ "38;2;138;123;156m";
pub const COLOR_ERR = CSI ++ "38;2;255;50;100m";

// ---------------------------------------------------------------------------
// TUI state
// ---------------------------------------------------------------------------
pub const CuteTUI = struct {
    allocator: std.mem.Allocator,
    sys_info: types.SystemInfo = .{},
    selected_menu: usize = 0,
    running: bool = true,
    demo_mode: bool = false,
    debug_mode: bool = false,
    status_msg: [256]u8 = undefined,
    status_len: usize = 0,
    status_type: u8 = 0,
    frame_count: u64 = 0,
    original_termios: ?posix.termios = null,
    raw_mode: bool = false,
    term_width: u16 = 80,
    term_height: u16 = 24,

    pub fn init(allocator: std.mem.Allocator, demo: bool, debug: bool) CuteTUI {
        return .{ .allocator = allocator, .demo_mode = demo, .debug_mode = debug };
    }

    pub fn deinit(self: *CuteTUI) void {
        self.sys_info.deinit(self.allocator);
    }

    pub fn setStatus(self: *CuteTUI, msg: []const u8, kind: u8) void {
        const n = @min(msg.len, self.status_msg.len);
        @memcpy(self.status_msg[0..n], msg[0..n]);
        self.status_len = n;
        self.status_type = kind;
    }

    // -----------------------------------------------------------------------
    // Terminal raw mode
    // -----------------------------------------------------------------------
    pub fn enableRawMode(self: *CuteTUI) !void {
        if (self.raw_mode) return;
        self.original_termios = try posix.tcgetattr(posix.STDIN_FILENO);
        var raw = self.original_termios.?;
        raw.iflag.BRKINT = false;
        raw.iflag.ICRNL = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.IXON = false;
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.IEXTEN = false;
        raw.lflag.ISIG = false;
        raw.cc[@intFromEnum(posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(posix.V.TIME)] = 1;
        try posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, raw);
        self.raw_mode = true;
    }

    pub fn disableRawMode(self: *CuteTUI) void {
        if (!self.raw_mode or self.original_termios == null) return;
        posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, self.original_termios.?) catch {};
        self.raw_mode = false;
    }

    pub fn updateTerminalSize(self: *CuteTUI) void {
        var ws: posix.winsize = undefined;
        if (std.os.linux.ioctl(posix.STDOUT_FILENO, posix.T.IOCGWINSZ, @intFromPtr(&ws)) == 0) {
            if (ws.col > 0) self.term_width = ws.col;
            if (ws.row > 0) self.term_height = ws.row;
        }
    }

    // -----------------------------------------------------------------------
    // Menu
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // Render
    // -----------------------------------------------------------------------
    pub fn render(self: *CuteTUI) !void {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);

        try w.writeAll(CSI ++ "1;1H");

        if (self.term_width >= 56 and self.term_height >= 22) {
            try self.renderFull(w);
        } else {
            try self.renderCompact(w);
        }
        try w.writeAll(RESET ++ CSI ++ "J");

        try std.fs.File.stdout().writeAll(buf.items);
    }

    fn renderFull(self: *CuteTUI, w: anytype) !void {
        try w.print("{s}{s}", .{ COLOR_CYBER_BG, COLOR_VIOLET });
        try w.writeAll("    " ++ COLOR_VIOLET ++ "+-------------------------------------------------+\r\n");
        try w.print("    {s}|{s} - {s}debork {s} -  {s}v2.0 (Zig){s}                {s}|{s}\r\n", .{
            COLOR_VIOLET, COLOR_FUCHSIA, COLOR_TEXT,     COLOR_FUCHSIA, COLOR_MINT,
            COLOR_VIOLET, COLOR_DIM,     COLOR_CYBER_BG,
        });
        try w.print("    {s}|{s}   Cosmopolitan Linux Boot Rescue               {s}|{s}\r\n", .{
            COLOR_VIOLET, COLOR_FUSIAN, COLOR_VIOLET, COLOR_CYBER_BG,
        });
        try w.writeAll("    " ++ COLOR_VIOLET ++ "+-------------------------------------------------+\r\n");
        try w.print("    {s}~ ~ ~  {s}Dark & Fusian Cyber Recovery{s}  ~ ~ ~\r\n\r\n", .{
            COLOR_FUSIAN, COLOR_FUCHSIA, RESET,
        });

        try w.print("    {s}+-------------------------------------------------+{s}\r\n", .{
            COLOR_PANEL_BG ++ COLOR_FUSIAN, COLOR_CYBER_BG,
        });
        for (menu_items, 0..) |item, i| {
            if (i == self.selected_menu) {
                try w.print("    {s}| {s}> {c} {s}{s:<43}{s} |{s}\r\n", .{
                    COLOR_SEL_BG ++ COLOR_FUCHSIA,
                    COLOR_AMBER ++ BOLD,
                    menu_icons[i],
                    COLOR_TEXT ++ BOLD,
                    item,
                    COLOR_FUCHSIA,
                    COLOR_CYBER_BG,
                });
            } else {
                try w.print("    {s}|   {c} {s}{s:<43}{s} |{s}\r\n", .{
                    COLOR_PANEL_BG ++ COLOR_DIM, menu_icons[i],
                    COLOR_TEXT ++ DIM,           item,
                    COLOR_VIOLET,                COLOR_CYBER_BG,
                });
            }
        }
        try w.print("    {s}+-------------------------------------------------+{s}\r\n", .{
            COLOR_PANEL_BG ++ COLOR_FUSIAN, COLOR_CYBER_BG,
        });

        try self.renderStatusAndFooter(w);
    }

    fn renderCompact(self: *CuteTUI, w: anytype) !void {
        const demo_tag: []const u8 = if (self.demo_mode) " [demo]" else "";
        try w.print("{s}debork v2.0{s}{s}\r\n", .{ COLOR_FUCHSIA ++ BOLD, COLOR_DIM, demo_tag });

        if (self.term_height > 6) {
            const bl = self.sys_info.boot_loader.name();
            const mnt: []const u8 = if (self.sys_info.mounted) "+" else "-";
            const mc: []const u8 = if (self.sys_info.mounted) COLOR_MINT else COLOR_ERR;
            try w.print("{s}[{s}{s}{s}] {s}{s}\r\n", .{ COLOR_DIM, mc, mnt, COLOR_DIM, COLOR_CYAN, bl });
        }

        const reserved: u16 = if (self.term_height > 6) 4 else 2;
        const menu_rows = if (self.term_height > reserved) self.term_height - reserved else 1;
        const n = menu_items.len;
        const visible: usize = @min(n, menu_rows);
        const scroll_start: usize = if (self.selected_menu < visible) 0 else self.selected_menu - visible + 1;
        const scroll_end = @min(scroll_start + visible, n);

        if (scroll_start > 0)
            try w.print("{s}  ^ {d} more\r\n", .{ COLOR_DIM, scroll_start });

        const label_width: usize = if (self.term_width > 6) self.term_width - 5 else 1;
        for (scroll_start..scroll_end) |i| {
            const item = menu_items[i];
            const label = if (item.len > label_width) item[0..label_width] else item;
            if (i == self.selected_menu) {
                try w.print("{s}> {c} {s}{s}{s}\r\n", .{
                    COLOR_FUCHSIA ++ BOLD, menu_icons[i], COLOR_TEXT ++ BOLD, label, RESET,
                });
            } else {
                try w.print("{s}  {c} {s}{s}{s}\r\n", .{
                    COLOR_DIM, menu_icons[i], COLOR_TEXT, label, RESET,
                });
            }
        }

        if (scroll_end < n)
            try w.print("{s}  v {d} more\r\n", .{ COLOR_DIM, n - scroll_end });

        try self.renderStatusAndFooter(w);
    }

    fn renderStatusAndFooter(self: *CuteTUI, w: anytype) !void {
        if (self.status_len > 0) {
            const icon: []const u8 = switch (self.status_type) {
                1 => COLOR_MINT ++ "+ ",
                2 => COLOR_ERR ++ "x ",
                3 => COLOR_AMBER ++ "! ",
                else => COLOR_CYAN ++ "> ",
            };
            try w.print("{s}{s}{s}\r\n", .{ icon, COLOR_TEXT, self.status_msg[0..self.status_len] });
        }
        try w.print("{s}[j/k/Enter/q]{s}\r\n", .{ COLOR_DIM, RESET });
    }

    // -----------------------------------------------------------------------
    // Input
    // -----------------------------------------------------------------------
    pub fn handleInput(self: *CuteTUI) !void {
        var key: [1]u8 = undefined;
        const n = std.fs.File.stdin().read(&key) catch 0;
        if (n == 0) return;

        const menu_count = menu_items.len;
        if (key[0] == 27) {
            var seq: [2]u8 = undefined;
            const sn = std.fs.File.stdin().read(&seq) catch 0;
            if (sn == 2 and seq[0] == '[') {
                switch (seq[1]) {
                    'A' => {
                        if (self.selected_menu > 0) self.selected_menu -= 1 else self.selected_menu = menu_count - 1;
                    },
                    'B' => {
                        self.selected_menu = (self.selected_menu + 1) % menu_count;
                    },
                    else => {},
                }
            }
        } else switch (key[0]) {
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

    // -----------------------------------------------------------------------
    // Menu actions
    // -----------------------------------------------------------------------
    fn executeSelectedMenu(self: *CuteTUI) !void {
        switch (self.selected_menu) {
            0 => { // Auto-Repair
                if (self.demo_mode) {
                    self.setStatus("Demo: repair simulated", 1);
                    return;
                }
                if (!self.sys_info.mounted) try self.selectPartition();
                if (!self.sys_info.mounted) return;

                const res = try ops.performAutoRepair(self.allocator, &self.sys_info);
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            1 => { // Emergency Shell
                if (self.demo_mode) {
                    self.setStatus("Demo: shell skipped", 3);
                    return;
                }
                self.disableRawMode();
                const out = std.fs.File.stdout();
                _ = out.writeAll(CLEAR ++ SHOW_CURSOR ++ COLOR_AMBER ++
                    "=== Emergency Shell — type 'exit' to return ===\n\n" ++ RESET) catch {};
                chroot.launchShell(self.allocator, &self.sys_info);
                try self.enableRawMode();
                _ = out.writeAll(ALT_SCREEN ++ HIDE_CURSOR) catch {};
                self.setStatus("Returned from emergency shell.", 0);
            },
            2 => { // Regenerate Initramfs
                if (self.demo_mode) {
                    self.setStatus("Demo: initramfs simulated", 1);
                    return;
                }
                const res = try chroot.regenerateInitramfs(self.allocator, &self.sys_info);
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            3 => { // Fix Boot Config
                if (self.demo_mode) {
                    self.setStatus("Demo: bootloader simulated", 1);
                    return;
                }
                ops.detectBootLoader(self.allocator, &self.sys_info);
                const res = switch (self.sys_info.boot_loader) {
                    .grub => try ops.fixGrub(self.allocator, &self.sys_info),
                    .refind => try ops.fixRefind(self.allocator, &self.sys_info, 0),
                    .systemd_boot => try ops.fixSystemdBoot(self.allocator, &self.sys_info),
                    .unknown => types.FixResult{ .success = false, .message = try self.allocator.dupe(u8, "Could not detect bootloader") },
                };
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            4 => {
                try self.showSysInfoScreen();
            },
            5 => { // Fix Pacman Cache
                if (self.demo_mode) {
                    self.setStatus("Demo: pacman cache simulated", 1);
                    return;
                }
                const res = try chroot.fixPacmanCache(self.allocator);
                defer self.allocator.free(res.message);
                self.setStatus(res.message, if (res.success) 1 else 2);
            },
            6 => {
                self.running = false;
            },
            else => {},
        }
    }

    // -----------------------------------------------------------------------
    // Interactive partition selector — reads from /dev/tty to survive sudo
    // -----------------------------------------------------------------------
    fn selectPartition(self: *CuteTUI) !void {
        const parts = try detection.scanPartitions(self.allocator);
        defer {
            for (parts) |*p| p.deinit(self.allocator);
            self.allocator.free(parts);
        }

        if (parts.len == 0) {
            self.setStatus("No Linux partitions found!", 2);
            return;
        }

        self.disableRawMode();
        const out = std.fs.File.stdout();
        _ = out.writeAll(CLEAR ++ SHOW_CURSOR ++ COLOR_FUCHSIA ++ BOLD ++
            "=== Select Target Partition ===\n\n" ++ RESET) catch {};

        for (parts, 0..) |p, i| {
            const uuid_short = if (p.uuid.len >= 8) p.uuid[0..8] else p.uuid;
            const label_part = if (p.label.len > 0) p.label else "-";
            var row_buf: [256]u8 = undefined;
            const row = std.fmt.bufPrint(&row_buf, "  {d}) {s:<16} {s:<6} {s:<8} {s}  {s}\n", .{ i + 1, p.device, p.fstype, p.size, uuid_short, label_part }) catch continue;
            _ = out.writeAll(row) catch {};
        }

        _ = out.writeAll("\nEnter number (0 to cancel): ") catch {};

        // Read from /dev/tty — survives sudo
        var tty = std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_only }) catch {
            try self.enableRawMode();
            self.setStatus("Cannot open /dev/tty", 2);
            return;
        };
        defer tty.close();

        var line_buf: [16]u8 = undefined;
        var line_len: usize = 0;
        while (line_len < line_buf.len) {
            var ch: [1]u8 = undefined;
            const rn = tty.read(&ch) catch break;
            if (rn == 0 or ch[0] == '\n' or ch[0] == '\r') break;
            line_buf[line_len] = ch[0];
            line_len += 1;
        }

        try self.enableRawMode();
        _ = out.writeAll(ALT_SCREEN ++ HIDE_CURSOR) catch {};

        const choice = std.fmt.parseInt(usize, std.mem.trim(u8, line_buf[0..line_len], " \t"), 10) catch {
            self.setStatus("Cancelled.", 3);
            return;
        };
        if (choice == 0 or choice > parts.len) {
            self.setStatus("Cancelled.", 3);
            return;
        }

        const dev = parts[choice - 1].device;
        const ok = try mount.mountSystem(self.allocator, &self.sys_info, dev);
        if (ok) {
            detection.detectBootLoader(self.allocator, &self.sys_info);
            detection.detectDistribution(self.allocator, &self.sys_info);
            detection.detectPackageManager(self.allocator, &self.sys_info);
            detection.scanKernels(self.allocator, &self.sys_info) catch {};
            self.setStatus("Partition mounted!", 1);
        } else {
            self.setStatus("Mount failed!", 2);
        }
    }

    // -----------------------------------------------------------------------
    // System info screen
    // -----------------------------------------------------------------------
    fn showSysInfoScreen(self: *CuteTUI) !void {
        if (!self.demo_mode and self.sys_info.mounted) {
            ops.detectBootLoader(self.allocator, &self.sys_info);
            detection.scanKernels(self.allocator, &self.sys_info) catch {};
        }

        const out = std.fs.File.stdout();
        _ = out.writeAll(CLEAR ++ CSI ++ "1;1H" ++ COLOR_FUCHSIA ++ BOLD ++
            "=== System Information ===\n\n" ++ RESET) catch {};

        var buf: [1024]u8 = undefined;
        const s = std.fmt.bufPrint(&buf,
            \\Device:       {s}
            \\UUID:         {s}
            \\Mount Point:  {s}
            \\Distribution: {s}
            \\Bootloader:   {s}
            \\Filesystem:   {s} (btrfs: {})
            \\Pkg Manager:  {s}
            \\Kernels:      {}
            \\
            \\Press any key to return...
            \\
        , .{
            self.sys_info.device,
            self.sys_info.uuid,
            self.sys_info.mount_point,
            self.sys_info.distribution,
            self.sys_info.boot_loader.name(),
            self.sys_info.fstype,
            self.sys_info.is_btrfs,
            self.sys_info.pkg_manager.name(),
            self.sys_info.kernels.items.len,
        }) catch buf[0..0];

        _ = out.writeAll(COLOR_TEXT) catch {};
        _ = out.writeAll(s) catch {};

        var key: [1]u8 = undefined;
        while (true) {
            const n = std.fs.File.stdin().read(&key) catch 0;
            if (n > 0) break;
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    // -----------------------------------------------------------------------
    // Main loop
    // -----------------------------------------------------------------------
    pub fn run(self: *CuteTUI) !void {
        const out = std.fs.File.stdout();
        try out.writeAll(ALT_SCREEN ++ HIDE_CURSOR ++ CLEAR);
        try self.enableRawMode();
        defer {
            self.disableRawMode();
            _ = out.writeAll(SHOW_CURSOR ++ NORM_SCREEN ++ RESET) catch {};
        }

        while (self.running) {
            self.updateTerminalSize();
            try self.render();
            try self.handleInput();
            self.frame_count += 1;
            std.Thread.sleep(16 * std.time.ns_per_ms);
        }
    }
};
