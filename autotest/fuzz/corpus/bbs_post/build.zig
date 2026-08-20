const std = @import("std");

// Keep these in sync with CMakeLists.txt (UHUB_VERSION_*).
const version_major = 0;
const version_minor = 8;
const version_patch = 0;

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
    "src/util/tth.c",
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
    "src/core/bbs.c",
    "src/core/bbs_index.c",
    "src/core/command_parser.c",
    "src/core/commands.c",
    "src/core/config.c",
    "src/core/eventqueue.c",
    "src/core/hbri.c",
    "src/core/hub.c",
    "src/core/hubevent.c",
    "src/core/inf.c",
    "src/core/ioqueue.c",
    "src/core/ipcount.c",
    "src/core/link.c",
    "src/core/metrics.c",
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

// All of src/seeder/*.c: the hub-agnostic half of the blob/seed cache, on its
// way out into a separate uhub-seeder daemon. Built alongside core_sources for
// as long as the hub still calls into it.
// The uhub-seeder daemon. The hub links none of these -- that is the point of
// the split. autotest-bin takes them all bar main.c.
const seeder_sources = [_][]const u8{
    "src/seeder/embed.c",
    "src/seeder/fetch.c",
    "src/seeder/http.c",
    "src/seeder/post.c",
    "src/seeder/sniff.c",
    "src/seeder/url.c",
};

// The rest of the daemon; main.c is excluded from autotest-bin, which has its
// own.
const seeder_daemon_sources = [_][]const u8{
    "src/seeder/bbs.c",
    "src/seeder/cache.c",
    "src/seeder/cc.c",
    "src/seeder/commands.c",
    "src/seeder/config.c",
    "src/seeder/grant.c",
    "src/seeder/hubconn.c",
    "src/seeder/ingest.c",
};

// autotest/test_*.tcc sources, sorted, mirroring the `file(GLOB ...)` +
// `list(SORT ...)` in CMakeLists.txt. Kept as an explicit list (like the C
// source sets above) rather than globbed at build time; add a new .tcc here.
const tcc_sources = [_][]const u8{
    "test_auth.tcc",
    "test_bbs.tcc",
    "test_bbs_board.tcc",
    "test_bbs_index.tcc",
    "test_cbuffer.tcc",
    "test_commands.tcc",
    "test_condead.tcc",
    "test_config.tcc",
    "test_connect.tcc",
    "test_credentials.tcc",
    "test_eventqueue.tcc",
    "test_hbri.tcc",
    "test_help_rtf0.tcc",
    "test_hub.tcc",
    "test_inf.tcc",
    "test_ipfilter.tcc",
    "test_keepalive.tcc",
    "test_link.tcc",
    "test_list.tcc",
    "test_memory.tcc",
    "test_message.tcc",
    "test_metrics.tcc",
    "test_misc.tcc",
    "test_mod_auth_sqlite.tcc",
    "test_netbackend.tcc",
    "test_probe.tcc",
    "test_rbtree.tcc",
    "test_regserver.tcc",
    "test_route.tcc",
    "test_rtf0.tcc",
    "test_seedbbs.tcc",
    "test_seedcache.tcc",
    "test_seedcc.tcc",
    "test_seedcommands.tcc",
    "test_seedconfig.tcc",
    "test_seedembed.tcc",
    "test_seedfetch.tcc",
    "test_seedgrant.tcc",
    "test_seedhttp.tcc",
    "test_seedhub.tcc",
    "test_seedingest.tcc",
    "test_seedpost.tcc",
    "test_seedsniff.tcc",
    "test_seedurl.tcc",
    "test_sid.tcc",
    "test_tiger.tcc",
    "test_timer.tcc",
    "test_tls.tcc",
    "test_testutil_user.tcc",
    "test_tokenizer.tcc",
    "test_tth.tcc",
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
    .{ .name = "mod_selfregister" },
    .{ .name = "mod_chat_history" },
    .{ .name = "mod_chat_history_sqlite", .sqlite = true },
    .{ .name = "mod_chat_only" },
    .{ .name = "mod_chat_is_privileged" },
    .{ .name = "mod_topic" },
    .{ .name = "mod_ucmd" },
    .{ .name = "mod_no_guest_downloads" },
    .{ .name = "mod_flood" },
};

const Ctx = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cflags: []const []const u8,
    systemd: bool,
    strip: ?bool,
    common: *std.Build.Step.Compile,
    version_h: *std.Build.Step.ConfigHeader,
    system_h: *std.Build.Step.ConfigHeader,
    // The bundled LibreSSL dependency, or null when -Dsystem-ssl links the host's.
    libressl: ?*std.Build.Dependency,
    // The bundled SQLite dependency (build.zig.zon), used by uhub-passwd and the
    // sqlite-backed plugins.
    sqlite3: *std.Build.Step.Compile,

    // A fresh module carrying the include paths, generated headers and libc
    // that every C target in this build needs.
    fn module(ctx: *const Ctx) *std.Build.Module {
        const m = ctx.b.createModule(.{
            .target = ctx.target,
            .optimize = ctx.optimize,
            .link_libc = true,
            .strip = ctx.strip,
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

    // Link the vendored SQLite (third_party/sqlite3, built into ctx.sqlite3) and
    // put its header on the consumer's include path -- the amalgamation defaults
    // to SQLITE_THREADSAFE=1 (SQLite's own default). CMake links a system
    // sqlite3 instead; this is the zig build's copy.
    fn addSqlite(ctx: *const Ctx, m: *std.Build.Module) void {
        m.linkLibrary(ctx.sqlite3);
        m.addIncludePath(ctx.b.path("third_party/sqlite3"));
    }

    // Build the autotest driver from the *.tcc sources, mirroring the
    // exotic_add_tests() call in CMakeLists.txt. This is exotic's MODE AUTO:
    // each .tcc is its own translation unit and the constructor emitted by
    // EXO_TEST self-registers the test, so nothing is generated and Perl is not
    // involved. exotic itself (third_party/exotic, a git submodule) supplies the
    // runtime and the main().
    fn addAutotest(ctx: *const Ctx, m: *std.Build.Module) void {
        const b = ctx.b;

        // exotic's runtime and its main(). Both include "autotest.h" relative to
        // their own directory, so upstream's configure_file() mirror to
        // <exotic/exotic.h> is not reproduced here -- the header is force-included
        // below straight from src/ instead. VERSION is what upstream's CMake
        // passes via target_compile_definitions; autotest.c needs it for
        // --version, so bump it when the submodule is bumped. -w because this is
        // upstream code and the build is -Wall -W -Werror.
        m.addCSourceFiles(.{
            .root = b.path("third_party/exotic/src"),
            .files = &.{ "autotest.c", "exotic_main.c" },
            .flags = &.{ "-w", "-DVERSION=\"0.6.0\"" },
        });
        m.addIncludePath(b.path("third_party/exotic/src"));

        // The .tcc files do not include the exotic header themselves, so it is
        // force-included, as exotic_add_tests() does in CMake. The path must be
        // absolute: with a relative -include, zig cannot resolve the header when
        // hashing the compilation's inputs and fails the cache check.
        // (".tcc" is a C++ header extension to clang, but `.language = .c`
        // below already makes zig pass -x c, so that needs no flag here.)
        // UHUB_TEST_DIR is the absolute path to autotest/, so tests can find the
        // checked-in fixtures (the TLS certificate) whatever the cwd is. Matches
        // the target_compile_definitions() in CMakeLists.txt.
        const tcc_flags = std.mem.concat(b.allocator, []const u8, &.{
            ctx.cflags,
            &.{
                "-include", b.pathFromRoot("third_party/exotic/src/autotest.h"),
                b.fmt("-DUHUB_TEST_DIR=\"{s}\"", .{b.pathFromRoot("autotest")}),
            },
        }) catch @panic("OOM");
        m.addCSourceFiles(.{
            .root = b.path("autotest"),
            .files = &tcc_sources,
            .flags = tcc_flags,
            .language = .c,
        });
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
    const javascript = b.option(bool, "javascript", "Build the mod_javascript plugin (embeds QuickJS, a git submodule)") orelse false;
    // TLS is mandatory. By default we build the bundled LibreSSL (a zig
    // dependency, see build.zig.zon), which makes the build self-contained and
    // avoids needing the system OpenSSL headers on the include path (keg-only
    // on Homebrew macOS). -Dsystem-ssl links the host's ssl/crypto instead.
    const system_ssl = b.option(bool, "system-ssl", "Link the host OpenSSL/LibreSSL instead of the bundled LibreSSL") orelse false;
    // Only autotest-bin needs the exotic submodule, so default -Dtests to
    // whether it is actually present. This mirrors UHUB_TESTS in CMakeLists.txt
    // and keeps `zig build` working in a source tree that arrived without
    // submodules -- an unpacked GitHub "Source code" archive, say, which cannot
    // contain them. Asking for tests explicitly still fails loudly.
    const exotic_present = blk: {
        b.build_root.handle.access(b.graph.io, "third_party/exotic/src/autotest.c", .{}) catch break :blk false;
        break :blk true;
    };
    // Left null by default so zig applies its per-optimize-mode default. The
    // binary distributions pass -Dstrip=true: DWARF is most of an unstripped
    // ELF's size and nobody debugging a release build has the sources anyway.
    const strip = b.option(bool, "strip", "Strip debug info from the produced binaries");
    const tests = b.option(bool, "tests", "Build autotest-bin (needs the third_party/exotic submodule)") orelse exotic_present;
    if (tests and !exotic_present) {
        std.debug.panic(
            "the exotic test framework is missing from third_party/exotic.\n" ++
                "Run: git submodule update --init third_party/exotic\n" ++
                "If this tree was unpacked from GitHub's auto-generated source archive, it\n" ++
                "cannot contain uhub's submodules; use the uhub-<version>-src.tar.gz attached\n" ++
                "to the release, or clone with --recursive. Otherwise build with -Dtests=false.",
            .{},
        );
    }

    // Assemble the common C flags applied to every translation unit.
    var flags = std.array_list.Managed([]const u8).init(b.allocator);
    // -Wall -W -Werror, matching the CMake warning set. Deliberately no
    // -pedantic: with -Werror it would promote strict-ISO-C diagnostics to hard
    // errors, and the plugin loader's dlsym() void*->function-pointer conversion
    // (among others) cannot be expressed in strict ISO C without ugly hacks.
    flags.appendSlice(&.{ "-std=gnu23", "-Wall", "-W", "-Werror", "-D_GNU_SOURCE" }) catch @panic("OOM");
    // Binary hardening, mirroring CMakeLists.txt: a stack canary always,
    // stack-clash probing where the target implements it, and _FORTIFY_SOURCE
    // when optimizing (the fortified libc checks compile in only under
    // optimization, so it is inert -- and warns -- in a Debug build). RELRO,
    // BIND_NOW and a non-executable stack are the Zig linker defaults; PIE is
    // set per-executable below.
    flags.append("-fstack-protector-strong") catch @panic("OOM");
    // -fstack-clash-protection is only implemented for ELF targets (Linux/BSD).
    // On Darwin and Windows clang emits "argument unused" -- which -Werror would
    // turn into a build failure -- so add it only there. CMake achieves the same
    // via a compiler probe.
    switch (target.result.os.tag) {
        .macos, .windows => {},
        else => flags.append("-fstack-clash-protection") catch @panic("OOM"),
    }
    if (optimize != .Debug) flags.append("-D_FORTIFY_SOURCE=2") catch @panic("OOM");
    // Give defined behaviour to the two things the code relies on that are
    // otherwise UB: signed overflow (-fwrapv) and cast-based type punning
    // (-fno-strict-aliasing). This is what makes sanitize_c=off below safe --
    // the code no longer depends on the compiler declining to exploit the UB.
    flags.appendSlice(&.{ "-fwrapv", "-fno-strict-aliasing" }) catch @panic("OOM");
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

    // SQLite, compiled from the vendored amalgamation in third_party/sqlite3
    // (used by uhub-passwd and the sqlite-backed plugins). CMake links the
    // system libsqlite3 instead. Force ReleaseFast regardless of our own
    // optimize mode: it is third-party C we never debug into, and a Debug build
    // emits __ubsan_handle_* references that our sanitize_c=off consumers do not
    // resolve. PIC so it can link into the plugin shared objects.
    const sqlite3_mod = b.createModule(.{
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = true,
        .sanitize_c = .off,
    });
    sqlite3_mod.pic = true;
    sqlite3_mod.addCSourceFile(.{ .file = b.path("third_party/sqlite3/sqlite3.c"), .flags = &.{} });
    const sqlite3 = b.addLibrary(.{
        .linkage = .static,
        .name = "sqlite3",
        .root_module = sqlite3_mod,
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
        .strip = strip,
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
    // src/core/bbs_index.c keeps the BBS0 bulletin board index in SQLite, so
    // the hub itself links it -- not only the sqlite-backed plugins.
    ctx.addSqlite(uhub_mod);
    uhub_mod.linkLibrary(common);
    ctx.linkExternal(uhub_mod);
    const uhub = b.addExecutable(.{ .name = "uhub", .root_module = uhub_mod });
    uhub.rdynamic = true; // export symbols for dlopen'd plugins
    uhub.pie = true; // ASLR for the executable itself, not just the PIC libs
    b.installArtifact(uhub);

    // autotest-bin. The suite drives POSIX socket-fd semantics (socketpair, and
    // write()/close() on socket descriptors) that do not map onto WinSock, and
    // there is no Windows test runner, so it is not built for Windows.
    const autotest: ?*std.Build.Step.Compile = if (is_windows or !tests) null else blk: {
        const autotest_mod = ctx.module();
        ctx.addSources(autotest_mod, &core_sources);
        ctx.addSources(autotest_mod, &seeder_sources);
        ctx.addSources(autotest_mod, &seeder_daemon_sources);
        // hubconn.c is built on the ADC client; ioqueue.c already comes in via
        // core_sources, so only adcclient.c is added here.
        ctx.addSources(autotest_mod, &.{"src/tools/adcclient.c"});
        // mod_auth_sqlite.c is compiled in (not just built as a loadable
        // module) so test_mod_auth_sqlite.tcc can drive its auth functions
        // directly via plugin_register(); it pulls in SQLite, hence addSqlite.
        ctx.addSources(autotest_mod, &.{"src/plugins/mod_auth_sqlite.c"});
        ctx.addSqlite(autotest_mod);
        ctx.addAutotest(autotest_mod);
        autotest_mod.linkLibrary(common);
        ctx.linkExternal(autotest_mod);
        const exe = b.addExecutable(.{ .name = "autotest-bin", .root_module = autotest_mod });
        exe.rdynamic = true;
        exe.pie = true;
        b.installArtifact(exe);
        break :blk exe;
    };

    // uhub-passwd (needs SQLite for the password database)
    const passwd_mod = ctx.module();
    ctx.addSources(passwd_mod, &.{"src/tools/uhub-passwd.c"});
    ctx.addSqlite(passwd_mod);
    passwd_mod.linkLibrary(common);
    ctx.linkExternal(passwd_mod);
    const passwd = b.addExecutable(.{ .name = "uhub-passwd", .root_module = passwd_mod });
    passwd.pie = true;
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
        admin.pie = true;
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
            adcrush.pie = true;
            b.installArtifact(adcrush);
        }
    }

    // Plugins -> mod_*.{so,dll} (CMake sets PREFIX "" so there is no "lib"
    // prefix, and produces the platform-native suffix -- .dll on Windows).
    const plugin_ext = if (is_windows) "dll" else "so";
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
            b.fmt("{s}.{s}", .{ plugin.name, plugin_ext }),
        );
        b.getInstallStep().dependOn(&install.step);
    }

    // Optional mod_javascript plugin, embedding the QuickJS engine from the
    // third_party/quickjs git submodule (quickjs-ng). Mirrors the
    // JAVASCRIPT_SUPPORT block in CMakeLists.txt. QuickJS is built as its own
    // module with warnings off (-w): it is third-party and does not pass the
    // project's strict flags. If the submodule is not checked out, the build
    // fails on the missing source below -- run:
    //   git submodule update --init third_party/quickjs
    if (javascript) {
        const qjs_mod = b.createModule(.{
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = true,
            .sanitize_c = .off,
            .pic = true,
        });
        qjs_mod.addCSourceFiles(.{
            .files = &.{
                "third_party/quickjs/quickjs.c",
                "third_party/quickjs/libregexp.c",
                "third_party/quickjs/libunicode.c",
                "third_party/quickjs/dtoa.c",
            },
            .flags = &.{ "-w", "-D_GNU_SOURCE" },
        });
        qjs_mod.addIncludePath(b.path("third_party/quickjs"));
        const quickjs = b.addLibrary(.{
            .linkage = .static,
            .name = "quickjs",
            .root_module = qjs_mod,
        });

        const mod = ctx.module();
        mod.addCSourceFiles(.{
            .files = &.{"src/plugins/mod_javascript.c"},
            .flags = cflags,
        });
        mod.addIncludePath(b.path("third_party/quickjs"));
        mod.linkLibrary(quickjs);
        mod.linkLibrary(common);
        ctx.linkExternal(mod);
        if (!is_windows) mod.linkSystemLibrary("m", .{});
        const lib = b.addLibrary(.{
            .linkage = .dynamic,
            .name = "mod_javascript",
            .root_module = mod,
        });
        const install = b.addInstallFileWithDir(
            lib.getEmittedBin(),
            .lib,
            b.fmt("mod_javascript.{s}", .{plugin_ext}),
        );
        b.getInstallStep().dependOn(&install.step);
    }

    // `zig build run` -> launch uhub.
    const run_step = b.addRunArtifact(uhub);
    if (b.args) |args| run_step.addArgs(args);
    b.step("run", "Run uhub").dependOn(&run_step.step);

    // `zig build test` -> run the autotest suite (POSIX targets only).
    if (autotest) |t| {
        const test_run = b.addRunArtifact(t);
        b.step("test", "Run the autotest suite").dependOn(&test_run.step);
    }
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
