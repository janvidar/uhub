const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "uhub",
        .target = target,
        .optimize = optimize,
    });

    exe.addIncludePath(.{ .cwd_relative = "src" });

    exe.addCSourceFiles(.{
        .files = &.{
            "src/adc/message.c",
            "src/adc/sid.c",
            "src/core/auth.c",
            "src/core/command_parser.c",
            "src/core/commands.c",
            "src/core/config.c",
            "src/core/eventqueue.c",
            "src/core/hub.c",
            "src/core/hubevent.c",
            "src/core/inf.c",
            "src/core/ioqueue.c",
            "src/core/main.c",
            "src/core/netevent.c",
            "src/core/plugincallback.c",
            "src/core/plugininvoke.c",
            "src/core/pluginloader.c",
            "src/core/probe.c",
            "src/core/route.c",
            "src/core/user.c",
            "src/core/usermanager.c",
            "src/network/backend.c",
            "src/network/connection.c",
            "src/network/dnsresolver.c",
            "src/network/epoll.c",
            "src/network/ipcalc.c",
            "src/network/kqueue.c",
            "src/network/network.c",
            "src/network/notify.c",
            "src/network/openssl.c",
            "src/network/select.c",
            "src/network/timeout.c",
            "src/network/timer.c",
            "src/util/cbuffer.c",
            "src/util/credentials.c",
            "src/util/config_token.c",
            "src/util/floodctl.c",
            "src/util/getopt.c",
            "src/util/list.c",
            "src/util/log.c",
            "src/util/memory.c",
            "src/util/misc.c",
            "src/util/rbtree.c",
            "src/util/threads.c",
            "src/util/tiger.c",
        },
        .flags = &.{
            "-std=gnu23",
            "-pedantic",
            "-Wall",
            "-W",
        },
    });

    exe.linkLibC();
    b.installArtifact(exe);

    const mod_auth_simple = b.addSharedLibrary(.{ .name = "mod_auth_simple", .target = target, .optimize = optimize });
    mod_auth_simple.addCSourceFiles(.{ .files = &.{"src/plugins/mod_auth_simple.c"} });
    mod_auth_simple.addIncludePath(.{ .cwd_relative = "src" });
    mod_auth_simple.linkLibC();
    b.installArtifact(mod_auth_simple);

    const mod_auth_sqlite = b.addSharedLibrary(.{ .name = "mod_auth_sqlite", .target = target, .optimize = optimize });
    mod_auth_sqlite.addCSourceFiles(.{ .files = &.{"src/plugins/mod_auth_sqlite.c"} });
    mod_auth_sqlite.addIncludePath(.{ .cwd_relative = "src" });
    mod_auth_sqlite.linkLibC();
    b.installArtifact(mod_auth_sqlite);

    const mod_chat_history = b.addSharedLibrary(.{ .name = "mod_chat_history", .target = target, .optimize = optimize });
    mod_chat_history.addCSourceFiles(.{ .files = &.{"src/plugins/mod_chat_history.c"} });
    mod_chat_history.addIncludePath(.{ .cwd_relative = "src" });
    mod_chat_history.linkLibC();
    b.installArtifact(mod_chat_history);

    //const mod_chat_is_privileged = b.addSharedLibrary(.{ .name = "mod_chat_is_privileged", .target = target, .optimize = optimize });
    //mod_chat_is_privileged.addCSourceFiles(.{ .files = &.{"src/plugins/mod_chat_is_privileged.c"} });
    //mod_chat_is_privileged.addIncludePath(.{ .cwd_relative = "src" });
    //mod_chat_is_privileged.linkLibC();
    //b.installArtifact(mod_chat_is_privileged);

    const mod_logging = b.addSharedLibrary(.{ .name = "mod_logging", .target = target, .optimize = optimize });
    mod_logging.addCSourceFiles(.{ .files = &.{"src/plugins/mod_logging.c"} });
    mod_logging.addIncludePath(.{ .cwd_relative = "src" });
    mod_logging.linkLibC();
    b.installArtifact(mod_logging);

    const mod_no_guest_downloads = b.addSharedLibrary(.{ .name = "mod_no_guest_downloads", .target = target, .optimize = optimize });
    mod_no_guest_downloads.addCSourceFiles(.{ .files = &.{"src/plugins/mod_no_guest_downloads.c"} });
    mod_no_guest_downloads.addIncludePath(.{ .cwd_relative = "src" });
    mod_no_guest_downloads.linkLibC();
    b.installArtifact(mod_no_guest_downloads);

    const mod_topic = b.addSharedLibrary(.{ .name = "mod_topic", .target = target, .optimize = optimize });
    mod_topic.addCSourceFiles(.{ .files = &.{"src/plugins/mod_topic.c"} });
    mod_topic.addIncludePath(.{ .cwd_relative = "src" });
    mod_topic.linkLibC();
    b.installArtifact(mod_topic);

    const mod_welcome = b.addSharedLibrary(.{ .name = "mod_welcome", .target = target, .optimize = optimize });
    mod_welcome.addCSourceFiles(.{ .files = &.{"src/plugins/mod_welcome.c"} });
    mod_welcome.addIncludePath(.{ .cwd_relative = "src" });
    mod_welcome.linkLibC();
    b.installArtifact(mod_welcome);

    const run_step = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_step.addArgs(args);
    }

    const run_cmd = b.step("run", "Run uhub");
    run_cmd.dependOn(&run_step.step);
}
