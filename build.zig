const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "debork",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zig/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run debork rescue tool");
    run_step.dependOn(&run_cmd.step);

    // Static build target for rescue environment
    const static_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
    });

    const static_exe = b.addExecutable(.{
        .name = "debork-static",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zig/main.zig"),
            .target = static_target,
            .optimize = .ReleaseSmall,
        }),
    });

    const install_static = b.addInstallArtifact(static_exe, .{});
    const static_step = b.step("static", "Build zero-dependency static rescue binary (x86_64-linux-musl)");
    static_step.dependOn(&install_static.step);
}
