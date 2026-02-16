const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    exe_mod.addIncludePath(b.path("src"));
    exe_mod.addCSourceFiles(.{
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

    const exe = b.addExecutable(.{
        .name = "uhub",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    inline for (.{
        "mod_auth_simple",
        "mod_auth_sqlite",
        "mod_chat_history",
        //"mod_chat_is_privileged",
        "mod_logging",
        "mod_no_guest_downloads",
        "mod_topic",
        "mod_welcome",
    }) |plugin_name| {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addIncludePath(b.path("src"));
        mod.addCSourceFiles(.{ .files = &.{"src/plugins/" ++ plugin_name ++ ".c"} });

        const lib = b.addLibrary(.{
            .linkage = .dynamic,
            .name = plugin_name,
            .root_module = mod,
        });
        b.installArtifact(lib);
    }

    const run_step = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_step.addArgs(args);
    }

    const run_cmd = b.step("run", "Run uhub");
    run_cmd.dependOn(&run_step.step);
}
