const std = @import("std");

// Keep these in sync with CMakeLists.txt (UHUB_VERSION_*).
const version_major = 0;
const version_minor = 6;
const version_patch = 1;

// Shared source sets, mirroring the static libraries CMakeLists.txt builds
// (adc / network / utils). They are compiled once into a single static
// library and linked into every artifact below.
const util_sources = [_][]const u8{
    "src/util/cbuffer.c",
    "src/util/config_token.c",
    "src/util/credentials.c",
    "src/util/floodctl.c",
    "src/util/getopt.c",
    "src/util/list.c",
    "src/util/log.c",
    "src/util/memory.c",
    "src/util/misc.c",
    "src/util/rbtree.c",
    "src/util/threads.c",
    "src/util/tiger.c",
};

const network_sources = [_][]const u8{
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
};

const adc_sources = [_][]const u8{
    "src/adc/message.c",
    "src/adc/sid.c",
};

// All of src/core/*.c except gen_config.c (a generator) and main.c (the entry
// point, added explicitly to uhub only). Shared between uhub and autotest-bin.
const core_sources = [_][]const u8{
    "src/core/auth.c",
    "src/core/command_parser.c",
    "src/core/commands.c",
    "src/core/config.c",
    "src/core/eventqueue.c",
    "src/core/hbri.c",
    "src/core/hub.c",
    "src/core/hubevent.c",
    "src/core/inf.c",
    "src/core/ioqueue.c",
    "src/core/netevent.c",
    "src/core/plugincallback.c",
    "src/core/plugininvoke.c",
    "src/core/pluginloader.c",
    "src/core/probe.c",
    "src/core/regserver.c",
    "src/core/route.c",
    "src/core/user.c",
    "src/core/usermanager.c",
};

// autotest/test_*.tcc sources, sorted, mirroring the `file(GLOB ...)` +
// `list(SORT ...)` in CMakeLists.txt. Kept as an explicit list (like the C
// source sets above) rather than globbed at build time; add a new .tcc here.
const tcc_sources = [_][]const u8{
    "test_auth.tcc",
    "test_commands.tcc",
    "test_config.tcc",
    "test_credentials.tcc",
    "test_eventqueue.tcc",
    "test_hbri.tcc",
    "test_hub.tcc",
    "test_inf.tcc",
    "test_ipfilter.tcc",
    "test_list.tcc",
    "test_memory.tcc",
    "test_message.tcc",
    "test_misc.tcc",
    "test_netbackend.tcc",
    "test_rbtree.tcc",
    "test_regserver.tcc",
    "test_sid.tcc",
    "test_tiger.tcc",
    "test_timer.tcc",
    "test_tokenizer.tcc",
    "test_usermanager.tcc",
};

const Plugin = struct {
    name: []const u8,
    sqlite: bool = false,
};

// Mirrors the add_library(... MODULE ...) plugin list in CMakeLists.txt.
// mod_logging needs adc/sid.c, which already lives in the shared library.
const plugins = [_]Plugin{
    .{ .name = "mod_example" },
    .{ .name = "mod_welcome" },
    .{ .name = "mod_logging" },
    .{ .name = "mod_auth_simple" },
    .{ .name = "mod_auth_sqlite", .sqlite = true },
    .{ .name = "mod_chat_history" },
    .{ .name = "mod_chat_history_sqlite", .sqlite = true },
    .{ .name = "mod_chat_only" },
    .{ .name = "mod_topic" },
    .{ .name = "mod_no_guest_downloads" },
    .{ .name = "mod_flood" },
};

const Ctx = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cflags: []const []const u8,
    systemd: bool,
    common: *std.Build.Step.Compile,
    version_h: *std.Build.Step.ConfigHeader,
    system_h: *std.Build.Step.ConfigHeader,
    // The bundled LibreSSL dependency, or null when -Dsystem-ssl links the host's.
    libressl: ?*std.Build.Dependency,
    // The bundled SQLite dependency (build.zig.zon), used by uhub-passwd and the
    // sqlite-backed plugins.
    sqlite3: *std.Build.Dependency,

    // A fresh module carrying the include paths, generated headers and libc
    // that every C target in this build needs.
    fn module(ctx: *const Ctx) *std.Build.Module {
        const m = ctx.b.createModule(.{
            .target = ctx.target,
            .optimize = ctx.optimize,
            .link_libc = true,
            // Match CMake: it never enables the C UB sanitizer, and the code
            // relies on a handful of signed-shift / overflow behaviours.
            .sanitize_c = .off,
        });
        m.addIncludePath(ctx.b.path("src"));
        m.addConfigHeader(ctx.version_h);
        m.addConfigHeader(ctx.system_h);
        return m;
    }

    fn addSources(ctx: *const Ctx, m: *std.Build.Module, files: []const []const u8) void {
        m.addCSourceFiles(.{ .files = files, .flags = ctx.cflags });
    }

    // Link the bundled SQLite (a zig dependency, see build.zig.zon). CMake links
    // a system sqlite3; building it from the package keeps the zig build
    // self-contained. Linking the artifact propagates <sqlite3.h> to the
    // consumer, and the port defaults to SQLITE_THREADSAFE=1 (SQLite's own
    // default), matching what the in-tree amalgamation was compiled with.
    fn addSqlite(ctx: *const Ctx, m: *std.Build.Module) void {
        m.linkLibrary(ctx.sqlite3.artifact("sqlite3"));
    }

    // Generate the autotest driver (autotest/test.c) from the *.tcc sources
    // with the exotic Perl script, mirroring the add_custom_command in
    // CMakeLists.txt. This replaces the manual autotest/update.sh step:
    // editing or adding a .tcc re-runs exotic on the next build. The captured
    // stdout is compiled into the module; exotic embeds each .tcc as
    // #include "<basename>", so the autotest dir goes on the include path.
    fn addAutotest(ctx: *const Ctx, m: *std.Build.Module) void {
        const b = ctx.b;
        const exotic = b.addSystemCommand(&.{ b.findProgram(&.{"perl"}, &.{}) catch "perl", "exotic" });
        exotic.setCwd(b.path("autotest"));
        exotic.addFileInput(b.path("autotest/exotic"));

        // Feed exotic the sorted test_*.tcc list (see tcc_sources), matching
        // the `file(GLOB ...)` + `list(SORT ...)` in CMakeLists.txt.
        for (tcc_sources) |name| {
            exotic.addArg(name);
            exotic.addFileInput(b.path(b.fmt("autotest/{s}", .{name})));
        }

        // exotic writes the driver to stdout; capture it, then copy to a .c
        // basename so Zig classifies it as a C source (the captured file is
        // otherwise named "stdout" with no extension).
        const wf = b.addWriteFiles();
        const test_c = wf.addCopyFile(exotic.captureStdOut(.{}), "test.c");
        m.addCSourceFile(.{ .file = test_c, .flags = ctx.cflags });
        m.addIncludePath(b.path("autotest"));
    }

    // Link the TLS libraries (ssl + crypto) into a module. This also makes
    // <openssl/*.h> findable: linking the bundled LibreSSL artifacts propagates
    // their installed headers to the consumer, and linkSystemLibrary pulls the
    // host's include path via pkg-config.
    fn linkTls(ctx: *const Ctx, m: *std.Build.Module) void {
        if (ctx.libressl) |dep| {
            m.linkLibrary(dep.artifact("ssl"));
            m.linkLibrary(dep.artifact("crypto"));
        } else {
            m.linkSystemLibrary("ssl", .{});
            m.linkSystemLibrary("crypto", .{});
        }
    }

    fn linkExternal(ctx: *const Ctx, m: *std.Build.Module) void {
        ctx.linkTls(m);
        if (ctx.systemd) {
            m.linkSystemLibrary("systemd", .{});
        }
    }
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options mirroring CMakeLists.txt. TLS is mandatory, so there is no
    // ssl toggle: ssl/crypto are always linked (OpenSSL or LibreSSL).
    const release = b.option(bool, "release", "Release build; disables the DEBUG define when on") orelse true;
    const systemd = b.option(bool, "systemd", "Enable systemd notify and journal logging") orelse false;
    const adc_stress = b.option(bool, "adc-stress", "Build the adcrush stress-tester client") orelse false;
    const lowlevel_debug = b.option(bool, "lowlevel-debug", "Enable low level debug messages") orelse false;
    // TLS is mandatory. By default we build the bundled LibreSSL (a zig
    // dependency, see build.zig.zon), which makes the build self-contained and
    // avoids needing the system OpenSSL headers on the include path (keg-only
    // on Homebrew macOS). -Dsystem-ssl links the host's ssl/crypto instead.
    const system_ssl = b.option(bool, "system-ssl", "Link the host OpenSSL/LibreSSL instead of the bundled LibreSSL") orelse false;

    // Assemble the common C flags applied to every translation unit.
    var flags = std.array_list.Managed([]const u8).init(b.allocator);
    flags.appendSlice(&.{ "-std=gnu23", "-pedantic", "-Wall", "-W", "-D_GNU_SOURCE" }) catch @panic("OOM");
    if (!release) flags.append("-DDEBUG") catch @panic("OOM");
    if (lowlevel_debug) flags.append("-DLOWLEVEL_DEBUG") catch @panic("OOM");
    if (systemd) flags.append("-DSYSTEMD") catch @panic("OOM");
    if (target.result.cpu.arch.endian() == .big) flags.append("-DARCH_BIGENDIAN") catch @panic("OOM");
    const cflags = flags.toOwnedSlice() catch @panic("OOM");

    // Generate version.h and system.h from the CMake templates, replacing
    // CMake's configure_file().
    const git_version = gitVersion(b);
    const version_h = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/version.h.in") },
        .include_path = "version.h",
    }, .{
        .UHUB_VERSION_MAJOR = version_major,
        .UHUB_VERSION_MINOR = version_minor,
        .UHUB_VERSION_PATCH = version_patch,
        .UHUB_GIT_VERSION = git_version,
    });

    const is_windows = target.result.os.tag == .windows;
    const system_h = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/system.h.in") },
        .include_path = "system.h",
    }, .{
        // CMake probes these with check_symbol_exists / check_include_file.
        // They hold on every POSIX target uhub supports; Windows uses the
        // in-header fallbacks.
        .HAVE_SYS_TYPES_H = !is_windows,
        .HAVE_STDINT_H = true,
        .HAVE_SSIZE_T = !is_windows,
        .HAVE_STRNDUP = !is_windows,
        .HAVE_MEMMEM = !is_windows,
        .HAVE_SYS_UIO_H = !is_windows,
        .HAVE_FUNC_WRITEV = !is_windows,
    });

    // The bundled LibreSSL (default) or null when -Dsystem-ssl links the host's
    // ssl/crypto. Building it ourselves keeps the build self-contained and
    // carries the TLS headers, so no system include path is required.
    const libressl: ?*std.Build.Dependency = if (system_ssl) null else b.dependency("libressl", .{
        .target = target,
        .optimize = optimize,
    });

    // SQLite, built from the package dependency (used by uhub-passwd and the
    // sqlite-backed plugins). Always bundled, as the in-tree amalgamation was.
    // Force ReleaseFast regardless of our own optimize mode: it is third-party C
    // we never debug into, and a Debug build of the port emits __ubsan_handle_*
    // references that our sanitize_c=off consumers do not resolve.
    const sqlite3 = b.dependency("sqlite3", .{
        .target = target,
        .optimize = .ReleaseFast,
    });

    // The shared static library (adc + network + utils). Built PIC so it can
    // be linked into the plugin shared objects.
    const common_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = .off,
    });
    common_mod.pic = true;
    common_mod.addIncludePath(b.path("src"));
    common_mod.addConfigHeader(version_h);
    common_mod.addConfigHeader(system_h);
    common_mod.addCSourceFiles(.{ .files = &util_sources, .flags = cflags });
    common_mod.addCSourceFiles(.{ .files = &network_sources, .flags = cflags });
    common_mod.addCSourceFiles(.{ .files = &adc_sources, .flags = cflags });
    // openssl.c (in network_sources) includes <openssl/*.h>, so this archive
    // needs the TLS headers at compile time. Linking the bundled LibreSSL
    // static artifacts here propagates their installed headers (and the link
    // dependency flows transitively to the final artifacts). With -Dsystem-ssl
    // the host include path is used instead and only the final artifacts link
    // ssl/crypto via linkExternal -- linking the host's shared libs into this
    // static archive would embed a bogus .so member.
    if (libressl) |dep| {
        common_mod.linkLibrary(dep.artifact("ssl"));
        common_mod.linkLibrary(dep.artifact("crypto"));
    }
    const common = b.addLibrary(.{
        .linkage = .static,
        .name = "uhub_common",
        .root_module = common_mod,
    });

    const ctx = Ctx{
        .b = b,
        .target = target,
        .optimize = optimize,
        .cflags = cflags,
        .systemd = systemd,
        .common = common,
        .version_h = version_h,
        .system_h = system_h,
        .libressl = libressl,
        .sqlite3 = sqlite3,
    };

    // uhub
    const uhub_mod = ctx.module();
    ctx.addSources(uhub_mod, &core_sources);
    ctx.addSources(uhub_mod, &.{"src/core/main.c"});
    uhub_mod.linkLibrary(common);
    ctx.linkExternal(uhub_mod);
    const uhub = b.addExecutable(.{ .name = "uhub", .root_module = uhub_mod });
    uhub.rdynamic = true; // export symbols for dlopen'd plugins
    b.installArtifact(uhub);

    // autotest-bin
    const autotest_mod = ctx.module();
    ctx.addSources(autotest_mod, &core_sources);
    ctx.addAutotest(autotest_mod);
    autotest_mod.linkLibrary(common);
    ctx.linkExternal(autotest_mod);
    const autotest = b.addExecutable(.{ .name = "autotest-bin", .root_module = autotest_mod });
    autotest.rdynamic = true;
    b.installArtifact(autotest);

    // uhub-passwd (needs SQLite for the password database)
    const passwd_mod = ctx.module();
    ctx.addSources(passwd_mod, &.{"src/tools/uhub-passwd.c"});
    ctx.addSqlite(passwd_mod);
    passwd_mod.linkLibrary(common);
    ctx.linkExternal(passwd_mod);
    const passwd = b.addExecutable(.{ .name = "uhub-passwd", .root_module = passwd_mod });
    b.installArtifact(passwd);

    // UNIX-only tools (CMake guards these with if(UNIX)).
    if (!is_windows) {
        const admin_mod = ctx.module();
        ctx.addSources(admin_mod, &.{
            "src/tools/admin.c",
            "src/tools/adcclient.c",
            "src/core/ioqueue.c",
        });
        admin_mod.linkLibrary(common);
        ctx.linkExternal(admin_mod);
        const admin = b.addExecutable(.{ .name = "uhub-admin", .root_module = admin_mod });
        b.installArtifact(admin);

        if (adc_stress) {
            const adcrush_mod = ctx.module();
            ctx.addSources(adcrush_mod, &.{
                "src/tools/adcrush.c",
                "src/tools/adcclient.c",
                "src/core/ioqueue.c",
            });
            adcrush_mod.linkLibrary(common);
            ctx.linkExternal(adcrush_mod);
            const adcrush = b.addExecutable(.{ .name = "adcrush", .root_module = adcrush_mod });
            b.installArtifact(adcrush);
        }
    }

    // Plugins -> mod_*.so (CMake sets PREFIX "" so there is no "lib" prefix).
    for (plugins) |plugin| {
        const mod = ctx.module();
        mod.addCSourceFiles(.{
            .files = &.{b.fmt("src/plugins/{s}.c", .{plugin.name})},
            .flags = cflags,
        });
        if (plugin.sqlite) ctx.addSqlite(mod);
        mod.linkLibrary(common);
        ctx.linkExternal(mod);
        const lib = b.addLibrary(.{
            .linkage = .dynamic,
            .name = plugin.name,
            .root_module = mod,
        });
        const install = b.addInstallFileWithDir(
            lib.getEmittedBin(),
            .lib,
            b.fmt("{s}.so", .{plugin.name}),
        );
        b.getInstallStep().dependOn(&install.step);
    }

    // `zig build run` -> launch uhub.
    const run_step = b.addRunArtifact(uhub);
    if (b.args) |args| run_step.addArgs(args);
    b.step("run", "Run uhub").dependOn(&run_step.step);

    // `zig build test` -> run the autotest suite.
    const test_run = b.addRunArtifact(autotest);
    b.step("test", "Run the autotest suite").dependOn(&test_run.step);
}

// Reproduce CMake's git-revision lookup: "git-<short hash>", or "release"
// when not in a git checkout.
fn gitVersion(b: *std.Build) []const u8 {
    const fallback = b.fmt("{d}.{d}.{d}-release", .{ version_major, version_minor, version_patch });
    var code: u8 = undefined;
    const stdout = b.runAllowFail(
        &.{ "git", "show", "-s", "--pretty=format:%h" },
        &code,
        .ignore,
    ) catch return fallback;
    const hash = std.mem.trim(u8, stdout, " \t\r\n");
    if (hash.len == 0) return fallback;
    return b.fmt("{d}.{d}.{d}-git-{s}", .{ version_major, version_minor, version_patch, hash });
}
