const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Optimization mode",
    ) orelse .ReleaseSmall;

    const exe = b.addExecutable(.{
        .name = "bip39",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Unit tests (internal function-level)
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    // End-to-end CLI tests
    const e2e_step = b.step("test-e2e", "Run end-to-end CLI tests");
    addE2eTests(b, e2e_step, exe);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(e2e_step);
}

const StdIoCheck = std.Build.Step.Run.StdIo.Check;

fn expectStdoutContains(run: *std.Build.Step.Run, needle: []const u8) void {
    run.addCheck(.{ .expect_stdout_match = run.step.owner.dupe(needle) });
}

fn expectStderrContains(run: *std.Build.Step.Run, needle: []const u8) void {
    run.addCheck(.{ .expect_stderr_match = run.step.owner.dupe(needle) });
}

fn addE2eTests(b: *std.Build, e2e_step: *std.Build.Step, exe: *std.Build.Step.Compile) void {
    {
        const run = b.addRunArtifact(exe);
        run.addArg("help");
        expectStdoutContains(run, "Usage: bip39");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        expectStdoutContains(run, "Usage: bip39");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArg("generate");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "generate", "24" });
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "generate", "12" });
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "generate", "99" });
        expectStderrContains(run, "Invalid word count");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "validate", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about" });
        expectStdoutContains(run, "Valid BIP39 mnemonic phrase.");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "validate", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "vote" });
        expectStdoutContains(run, "Valid BIP39 mnemonic phrase.");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "validate", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon" });
        expectStdoutContains(run, "Invalid BIP39 mnemonic phrase.");
        run.expectExitCode(1);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ "validate", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "notaword" });
        expectStdoutContains(run, "Invalid BIP39 mnemonic phrase.");
        run.expectExitCode(1);
        e2e_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(exe);
        run.addArg("validate");
        expectStderrContains(run, "No mnemonic phrase provided");
        run.expectExitCode(0);
        e2e_step.dependOn(&run.step);
    }
}
