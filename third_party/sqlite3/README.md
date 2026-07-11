# Vendored SQLite amalgamation

`sqlite3.c`, `sqlite3.h` and `sqlite3ext.h` are the official SQLite
**amalgamation**, version **3.53.2**, from <https://sqlite.org/2026/sqlite-amalgamation-3530200.zip>.

Only the `build.zig` build uses these (compiled into a small static library);
the CMake build links the system `libsqlite3` via `find_package(SQLite3)`.

They are vendored (rather than fetched by the zig package manager) because zig's
`.zip`-URL dependency fetch fails on Windows, which broke the Windows CI build.

## Updating

Download a newer amalgamation zip from sqlite.org and replace `sqlite3.c`,
`sqlite3.h` and `sqlite3ext.h` (leave out `shell.c` — the CLI is not built).
No `build.zig` change is needed unless SQLite adds/renames files.
