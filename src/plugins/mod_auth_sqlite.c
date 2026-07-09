/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "plugin_api/command_api.h"
#include "plugin_api/handle.h"
#include "util/cbuffer.h"
#include "util/config_token.h"
#include "util/memory.h"
#include "util/misc.h"
#include <sqlite3.h>

static void set_error_message(struct plugin_handle *plugin, const char *msg) {
    plugin->error_msg = msg;
}

struct sql_data {
    int exclusive;
    int self_register;
    sqlite3 *db;
    struct plugin_command_handle *cmd_regme;
    struct plugin_command_handle *cmd_passwd;
};

static struct sql_data *parse_config(const char *line, struct plugin_handle *plugin) {
    struct sql_data *data = (struct sql_data *)hub_malloc_zero(sizeof(struct sql_data));
    struct cfg_tokens *tokens = cfg_tokenize(line);
    char *token = cfg_token_get_first(tokens);

    if (!data)
        return 0;

    while (token) {
        struct cfg_settings *setting = cfg_settings_split(token);

        if (!setting) {
            set_error_message(plugin, "Unable to parse startup parameters");
            cfg_tokens_free(tokens);
            hub_free(data);
            return 0;
        }

        if (strcmp(cfg_settings_get_key(setting), "file") == 0) {
            if (!data->db) {
                if (sqlite3_open(cfg_settings_get_value(setting), &data->db)) {
                    cfg_tokens_free(tokens);
                    cfg_settings_free(setting);
                    hub_free(data);
                    set_error_message(plugin, "Unable to open database file");
                    return 0;
                }
            }
        } else if (strcmp(cfg_settings_get_key(setting), "exclusive") == 0) {
            if (!string_to_boolean(cfg_settings_get_value(setting), &data->exclusive))
                data->exclusive = 1;
        } else if (strcmp(cfg_settings_get_key(setting), "self_register") == 0) {
            if (!string_to_boolean(cfg_settings_get_value(setting), &data->self_register))
                data->self_register = 1;
        } else {
            set_error_message(plugin, "Unknown startup parameters given");
            cfg_tokens_free(tokens);
            cfg_settings_free(setting);
            hub_free(data);
            return 0;
        }

        cfg_settings_free(setting);
        token = cfg_token_get_next(tokens);
    }
    cfg_tokens_free(tokens);

    if (!data->db) {
        set_error_message(plugin, "No database file is given, use file=<database>");
        hub_free(data);
        return 0;
    }

    /* Defensively ensure a case-insensitive UNIQUE index on the nick exists, so
       databases created before the schema carried COLLATE NOCASE also reject
       nicks that differ only by case -- matching the case-insensitive lookups.
       Best-effort: it fails on a table that does not exist yet or that already
       holds case-duplicate rows; warn (so the operator can clean up) and carry
       on rather than refuse to load and break an existing hub. */
    {
        char* err = 0;
        if (sqlite3_exec(data->db,
                "CREATE UNIQUE INDEX IF NOT EXISTS uhub_users_nickname_nocase "
                "ON users (nickname COLLATE NOCASE);",
                NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "mod_auth_sqlite: case-insensitive nickname uniqueness "
                "not enforced (%s); resolve any case-duplicate nicks in the database.\n",
                err ? err : "unknown error");
            sqlite3_free(err);
        }
    }

    /* Ban storage. Unlike the users table (provisioned by uhub-passwd), the bans
       table is created here so an existing hub gains ban persistence on upgrade
       without a manual migration. */
    {
        char* err = 0;
        if (sqlite3_exec(data->db,
                "CREATE TABLE IF NOT EXISTS bans ("
                "cid TEXT NOT NULL DEFAULT '', nickname TEXT NOT NULL DEFAULT '', "
                "expiry INTEGER NOT NULL DEFAULT 0);"
                "CREATE INDEX IF NOT EXISTS uhub_bans_cid ON bans (cid);"
                "CREATE INDEX IF NOT EXISTS uhub_bans_nick ON bans (nickname COLLATE NOCASE);",
                NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "mod_auth_sqlite: could not create bans table (%s)\n",
                err ? err : "unknown error");
            sqlite3_free(err);
        }
        /* Add the expiry column to a bans table created before timed bans
           existed. Best-effort: fails harmlessly if the column already exists. */
        err = 0;
        sqlite3_exec(data->db, "ALTER TABLE bans ADD COLUMN expiry INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, &err);
        sqlite3_free(err);
    }

    return data;
}

static plugin_st get_user(struct plugin_handle *plugin, const char *nickname, struct auth_info *data) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    int rc;
    int found = 0;

    memset(data, 0, sizeof(struct auth_info));

    /* Match the nick case-insensitively (COLLATE NOCASE): otherwise a guest
       logging in as "boss" would miss the registered "Boss" account, dodge the
       password challenge, and get online impersonating that identity. */
    rc = sqlite3_prepare_v2(sql->db, "SELECT nickname, password, credentials FROM users WHERE nickname=? COLLATE NOCASE;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return st_default;
    }

    sqlite3_bind_text(stmt, 1, nickname, -1, SQLITE_STATIC);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *nick = (const char *)sqlite3_column_text(stmt, 0);
        const char *pass = (const char *)sqlite3_column_text(stmt, 1);
        const char *cred = (const char *)sqlite3_column_text(stmt, 2);

        if (nick) {
            strncpy(data->nickname, nick, MAX_NICK_LEN);
            data->nickname[MAX_NICK_LEN] = '\0';
        }

        if (pass) {
            strncpy(data->password, pass, MAX_PASS_LEN);
            data->password[MAX_PASS_LEN] = '\0';
        }

        if (cred) {
            auth_string_to_cred(cred, &data->credentials);
            found = 1;
        }
    }

    sqlite3_finalize(stmt);

    if (found)
        return st_allow;
    return st_default;
}

static plugin_st register_user(struct plugin_handle *plugin, struct auth_info *user) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    const char *cred = auth_cred_to_string(user->credentials);
    int rc;

    rc = sqlite3_prepare_v2(sql->db, "INSERT INTO users (nickname, password, credentials) VALUES(?, ?, ?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to add user \"%s\": %s\n", user->nickname, sqlite3_errmsg(sql->db));
        return st_deny;
    }

    sqlite3_bind_text(stmt, 1, user->nickname, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, cred, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Unable to add user \"%s\"\n", user->nickname);
        return st_deny;
    }
    return st_allow;
}

static plugin_st update_user(struct plugin_handle *plugin, struct auth_info *user) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    const char *cred = auth_cred_to_string(user->credentials);
    int rc;

    /* Case-insensitive nick match, consistent with get_user/delete_user (L-8):
       updating "boss" must find the registered "Boss". */
    rc = sqlite3_prepare_v2(sql->db, "UPDATE users SET password=?, credentials=? WHERE nickname=? COLLATE NOCASE;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to update user \"%s\": %s\n", user->nickname, sqlite3_errmsg(sql->db));
        return st_deny;
    }

    sqlite3_bind_text(stmt, 1, user->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cred, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user->nickname, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Unable to update user \"%s\"\n", user->nickname);
        return st_deny;
    }
    return st_allow;
}

static plugin_st delete_user(struct plugin_handle *plugin, struct auth_info *user) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    int rc;

    if (sql->exclusive)
        return st_deny;

    /* Match the nick case-insensitively, consistent with get_user (L-8): a
       nick's identity does not depend on case, so deleting "boss" must remove a
       registered "Boss" rather than silently leave it in place. */
    rc = sqlite3_prepare_v2(sql->db, "DELETE FROM users WHERE nickname=? COLLATE NOCASE;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to delete user \"%s\": %s\n", user->nickname, sqlite3_errmsg(sql->db));
        return st_deny;
    }

    sqlite3_bind_text(stmt, 1, user->nickname, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Unable to delete user \"%s\"\n", user->nickname);
        return st_deny;
    }
    return st_allow;
}

/* Persist a ban. The hub calls this write-through from !ban / hub_apply_ban. A
   record stores the CID and/or nick present in the ban (empty string when a
   field is not part of the ban). */
static plugin_st ban_add(struct plugin_handle *plugin, const struct ban_info *ban) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    int rc;

    if (sql->exclusive)
        return st_deny;

    rc = sqlite3_prepare_v2(sql->db, "INSERT INTO bans (cid, nickname, expiry) VALUES(?, ?, ?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to store ban: %s\n", sqlite3_errmsg(sql->db));
        return st_deny;
    }

    sqlite3_bind_text(stmt, 1, (ban->flags & ban_cid) ? ban->cid : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, (ban->flags & ban_nickname) ? ban->nickname : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64) ban->expiry);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Unable to store ban\n");
        return st_deny;
    }
    return st_allow;
}

/* Remove persisted ban records. The hub offers the unban target as both cid and
   nick (it does not know which the operator typed), so delete any row matching
   either. Returns st_allow if at least one row was removed. */
static plugin_st ban_del(struct plugin_handle *plugin, const struct ban_info *ban) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(sql->db,
        "DELETE FROM bans WHERE (nickname <> '' AND nickname = ? COLLATE NOCASE) "
        "OR (cid <> '' AND cid = ?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to remove ban: %s\n", sqlite3_errmsg(sql->db));
        return st_deny;
    }

    sqlite3_bind_text(stmt, 1, (ban->flags & ban_nickname) ? ban->nickname : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, (ban->flags & ban_cid) ? ban->cid : "", -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return st_deny;
    return sqlite3_changes(sql->db) > 0 ? st_allow : st_default;
}

/* Login-time query: is this user's CID or nick in the bans table and not yet
   expired? Timed bans (expiry != 0) lift themselves once expiry passes. */
static plugin_st is_banned(struct plugin_handle *plugin, struct plugin_user *user) {
    struct sql_data *sql = (struct sql_data *)plugin->ptr;
    sqlite3_stmt *stmt;
    sqlite3_int64 now = (sqlite3_int64) time(NULL);
    int rc;
    int banned = 0;

    /* Housekeeping: drop expired timed bans (best-effort). */
    if (sqlite3_prepare_v2(sql->db, "DELETE FROM bans WHERE expiry <> 0 AND expiry <= ?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, now);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    rc = sqlite3_prepare_v2(sql->db,
        "SELECT 1 FROM bans WHERE ((nickname <> '' AND nickname = ? COLLATE NOCASE) "
        "OR (cid <> '' AND cid = ?)) AND (expiry = 0 OR expiry > ?) LIMIT 1;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return st_default;

    sqlite3_bind_text(stmt, 1, user->nick, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->cid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now);

    if (sqlite3_step(stmt) == SQLITE_ROW)
        banned = 1;
    sqlite3_finalize(stmt);

    return banned ? st_deny : st_default;
}

/**
 * Validate a user-supplied password. Returns 1 if acceptable, 0 otherwise.
 * The 'p' command argument type already rejects whitespace, so we only need
 * to guard against an empty password or one that exceeds the storage limit.
 */
static int valid_password(const char *pass) {
    size_t len;
    if (!pass)
        return 0;
    len = strlen(pass);
    if (len == 0 || len > MAX_PASS_LEN)
        return 0;
    return 1;
}

static int command_regme_handler(struct plugin_handle *plugin, struct plugin_user *user, struct plugin_command *cmd) {
    struct cbuffer *buf = cbuf_create(256);
    struct plugin_command_arg_data *arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
    const char *pass = arg ? arg->data.string : NULL;
    struct auth_info info;

    if (!valid_password(pass)) {
        cbuf_append_format(buf, "*** %s: Password must be 1-%d characters and contain no spaces.", cmd->prefix, MAX_PASS_LEN);
        plugin->hub.send_message(plugin, user, cbuf_get(buf));
        cbuf_destroy(buf);
        return 0;
    }

    if (user->credentials >= auth_cred_user) {
        cbuf_append_format(buf, "*** %s: You are already logged in as a registered user.", cmd->prefix);
        plugin->hub.send_message(plugin, user, cbuf_get(buf));
        cbuf_destroy(buf);
        return 0;
    }

    if (get_user(plugin, user->nick, &info) == st_allow) {
        cbuf_append_format(buf, "*** %s: The nick \"%s\" is already registered.", cmd->prefix, user->nick);
        plugin->hub.send_message(plugin, user, cbuf_get(buf));
        cbuf_destroy(buf);
        return 0;
    }

    memset(&info, 0, sizeof(info));
    snprintf(info.nickname, sizeof(info.nickname), "%s", user->nick);
    snprintf(info.password, sizeof(info.password), "%s", pass);
    info.credentials = auth_cred_user;

    if (register_user(plugin, &info) == st_allow) {
        cbuf_append_format(buf,
            "*** %s: Registered nick \"%s\". To log in: set this password in your "
            "client, then disconnect and reconnect to the hub.",
            cmd->prefix, user->nick);
    } else {
    cbuf_append_format(buf,
            "*** %s: Registration failed. Please try again later or "
            "contact an operator.",
            cmd->prefix);
    }
    plugin->hub.send_message(plugin, user, cbuf_get(buf));
    cbuf_destroy(buf);
    return 0;
}

static int command_passwd_handler(struct plugin_handle *plugin, struct plugin_user *user, struct plugin_command *cmd) {
    struct cbuffer *buf = cbuf_create(256);
    struct plugin_command_arg_data *arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
    const char *pass = arg ? arg->data.string : NULL;
    struct auth_info info;

    if (user->credentials < auth_cred_user) {
        cbuf_append_format(
            buf, "*** %s: Only registered users can change their password.",
            cmd->prefix);
        plugin->hub.send_message(plugin, user, cbuf_get(buf));
        cbuf_destroy(buf);
        return 0;
    }

    if (!valid_password(pass)) {
        cbuf_append_format(
            buf, "*** %s: Password must be 1-%d characters and contain no spaces.",
            cmd->prefix, MAX_PASS_LEN);
        plugin->hub.send_message(plugin, user, cbuf_get(buf));
        cbuf_destroy(buf);
        return 0;
    }

    /* Load the existing record so the credential level is preserved across the
    * update. */
    if (get_user(plugin, user->nick, &info) != st_allow) {
        cbuf_append_format(
            buf, "*** %s: Could not find your registration. Contact an operator.",
            cmd->prefix);
        plugin->hub.send_message(plugin, user, cbuf_get(buf));
        cbuf_destroy(buf);
        return 0;
    }

    strncpy(info.password, pass, MAX_PASS_LEN);
    info.password[MAX_PASS_LEN] = '\0';

    if (update_user(plugin, &info) == st_allow) {
        cbuf_append_format(buf,
            "*** %s: Password updated. Use the new password the "
            "next time you log in.",
            cmd->prefix);
    } else {
        cbuf_append_format(
            buf, "*** %s: Password change failed. Please try again later.",
            cmd->prefix);
    }
    plugin->hub.send_message(plugin, user, cbuf_get(buf));
    cbuf_destroy(buf);
    return 0;
}

int plugin_register(struct plugin_handle *plugin, const char *config) {
    PLUGIN_INITIALIZE(plugin, "SQLite authentication plugin", "1.0", "Authenticate users based on a SQLite database.");

    // Authentication actions.
    plugin->funcs.auth_get_user = get_user;
    plugin->funcs.auth_register_user = register_user;
    plugin->funcs.auth_update_user = update_user;
    plugin->funcs.auth_delete_user = delete_user;

    // Ban storage/retention.
    plugin->funcs.auth_ban_add = ban_add;
    plugin->funcs.auth_ban_del = ban_del;
    plugin->funcs.auth_is_banned = is_banned;

    plugin->ptr = parse_config(config, plugin);
    if (!plugin->ptr)
        return -1;

    // Self-service commands, only when explicitly enabled in the config.
    {
        struct sql_data *sql = (struct sql_data *)plugin->ptr;
        if (sql->self_register) {
            sql->cmd_regme = (struct plugin_command_handle *)hub_malloc_zero(sizeof(struct plugin_command_handle));
            sql->cmd_passwd = (struct plugin_command_handle *)hub_malloc_zero(sizeof(struct plugin_command_handle));
            PLUGIN_COMMAND_INITIALIZE(sql->cmd_regme, plugin, "regme", "p", auth_cred_guest, command_regme_handler, "Register your current nick with a password.");
            PLUGIN_COMMAND_INITIALIZE(sql->cmd_passwd, plugin, "passwd", "p", auth_cred_user, command_passwd_handler, "Change the password of your registered nick.");
            plugin->hub.command_add(plugin, sql->cmd_regme);
            plugin->hub.command_add(plugin, sql->cmd_passwd);
        }
    }
    return 0;
}

int plugin_unregister(struct plugin_handle *plugin) {
    struct sql_data *sql;
    set_error_message(plugin, 0);
    sql = (struct sql_data *)plugin->ptr;

    if (sql->cmd_regme) {
        plugin->hub.command_del(plugin, sql->cmd_regme);
        hub_free(sql->cmd_regme);
    }

    if (sql->cmd_passwd) {
        plugin->hub.command_del(plugin, sql->cmd_passwd);
        hub_free(sql->cmd_passwd);
    }
    sqlite3_close(sql->db);
    hub_free(sql);
    return 0;
}
