/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"
#include "util/misc.h"
#include <sqlite3.h>

// #define DEBUG_SQL

static sqlite3* db = NULL;
static const char* command = NULL;
static const char* filename = NULL;
static const char* binary = NULL;

typedef int (*command_func_t)(size_t, const char**);

static int create(size_t argc, const char** argv);
static int list(size_t argc, const char** argv);
static int pass(size_t argc, const char** argv);
static int add(size_t argc, const char** argv);
static int del(size_t argc, const char** argv);
static int mod(size_t argc, const char** argv);

static struct commands
{
	command_func_t handle;
	const char* command;
	const char* usage;
} COMMANDS[6] = {
	{ &create, "create", "" },
	{ &list,   "list",   "" },
	{ &add,    "add",    "username password [credentials = user]" },
	{ &del,    "del",    "username" },
	{ &mod,    "mod",    "username credentials" },
	{ &pass,   "pass",   "username password" },
};

static void print_usage(const char* str)
{
	fprintf(stderr, "Usage: %s filename %s %s\n", binary, command, str);
	exit(1);
}


/**
 * Escape an SQL statement and return a pointer to the string.
 * NOTE: The returned value needs to be free'd.
 *
 * @return an escaped string.
 */
static char* sql_escape_string(const char* str)
{
	size_t i, n, size;
	char* buf;

	for (n = 0, size = strlen(str); n < strlen(str); n++)
		if (str[n] == '\'')
			size++;

	buf = malloc(size+1);
	for (n = 0, i = 0; n < strlen(str); n++)
	{
		if (str[n] == '\'')
			buf[i++] = '\'';
		buf[i++] = str[n];
	}
	buf[i++] = '\0';
	return buf;
}

/**
 * Validate credentials.
 */
static const char* validate_cred(const char* cred_str)
{
	if (!strcmp(cred_str, "admin"))
		return "admin";

	if (!strcmp(cred_str, "super"))
		return "super";

	if (!strcmp(cred_str, "op"))
		return "op";

	if (!strcmp(cred_str, "user"))
		return "user";

	if (!strcmp(cred_str, "bot"))
		return "bot";

	if (!strcmp(cred_str, "ubot"))
		return "ubot";

	if (!strcmp(cred_str, "opbot"))
		return "opbot";

	if (!strcmp(cred_str, "opubot"))
		return "opubot";

	fprintf(stderr, "Invalid user credentials. Must be one of: 'bot', 'ubot', 'opbot', 'opubot', 'admin', 'super', 'op' or 'user'\n");
	exit(1);
}

static const char* validate_username(const char* username)
{
	const char* tmp;

	// verify length
	if (strlen(username) > MAX_NICK_LEN)
	{
		fprintf(stderr, "User name is too long.\n");
		exit(1);
	}

	/* Nick must not start with a space */
	if (is_white_space(username[0]))
	{
		fprintf(stderr, "User name cannot start with white space.\n");
		exit(1);
	}

	/* Check for ASCII values below 32 */
	for (tmp = username; *tmp; tmp++)
		if ((*tmp < 32) && (*tmp > 0))
		{
			fprintf(stderr, "User name contains illegal characters.\n");
			exit(1);
		}

	if (!is_valid_utf8(username))
	{
		fprintf(stderr, "User name must be utf-8 encoded.\n");
		exit(1);
	}

	return username;
}


static const char* validate_password(const char* password)
{
	// verify length
	if (strlen(password) > MAX_PASS_LEN)
	{
		fprintf(stderr, "Password is too long.\n");
		exit(1);
	}

	if (!is_valid_utf8(password))
	{
		fprintf(stderr, "Password must be utf-8 encoded.\n");
		exit(1);
	}

	return password;
}

static void open_database()
{
	int res = sqlite3_open(filename, &db);

	if (res)
	{
		fprintf(stderr, "Unable to open database: %s (result=%d)\n", filename, res);
		exit(1);
	}
}

static int sql_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static int sql_execute(const char* sql, ...)
{
	va_list args;
	char query[1024];
	char* errMsg;
	int rc;

	va_start(args, sql);
	vsnprintf(query, sizeof(query), sql, args);

#ifdef DEBUG_SQL
	printf("SQL: %s\n", query);
#endif

	open_database();

	rc = sqlite3_exec(db, query, sql_callback, NULL, &errMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "ERROR: %s\n", errMsg);
		sqlite3_free(errMsg);
	}

	rc = sqlite3_changes(db);
	sqlite3_close(db);
	return rc;
}

static int create(size_t argc, const char** argv)
{
	const char* sql = "CREATE TABLE users"
		"("
			"nickname CHAR NOT NULL UNIQUE,"
			"password CHAR NOT NULL,"
			"credentials CHAR NOT NULL DEFAULT 'user',"
			"created TIMESTAMP DEFAULT (DATETIME('NOW')),"
			"activity TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");";

	sql_execute(sql);
	return 0;
}


static int sql_callback_list(void* ptr, int argc, char **argv, char **colName)
{
	int* found = (int*) ptr;
	uhub_assert(strcmp(colName[0], "nickname") == 0 && strcmp(colName[2], "credentials") == 0);
	printf("%s\t%s\n", argv[2], argv[0]);
	(*found)++;
	return 0;
}

static int list(size_t argc, const char** argv)
{
	char* errMsg;
	int found = 0;
	int rc;

	open_database();

	rc = sqlite3_exec(db, "SELECT * FROM users;", sql_callback_list, &found, &errMsg);
	if (rc != SQLITE_OK) {
#ifdef DEBUG_SQL
		fprintf(stderr, "SQL: ERROR: %s (%d)\n", errMsg, rc);
#endif
		sqlite3_free(errMsg);
		exit(1);
	}

	sqlite3_close(db);
	return 0;
}


static int add(size_t argc, const char** argv)
{
	char* user = NULL;
	char* pass = NULL;
	const char* cred = NULL;
	int rc;

	if (argc < 2)
		print_usage("username password [credentials = user]");

	user = sql_escape_string(validate_username(argv[0]));
	pass = sql_escape_string(validate_password(argv[1]));
	cred = validate_cred(argv[2] ? argv[2] : "user");

	rc = sql_execute("INSERT INTO users (nickname, password, credentials) VALUES('%s', '%s', '%s');", user, pass, cred);

	free(user);
	free(pass);

	if (rc != 1)
	{
		fprintf(stderr, "Unable to add user \"%s\"\n", argv[0]);
		return 1;
	}
	return 0;
}

static int mod(size_t argc, const char** argv)
{
	char* user = NULL;
	const char* cred = NULL;
	int rc;

	if (argc < 2)
		print_usage("username credentials");

	user = sql_escape_string(argv[0]);
	cred = validate_cred(argv[1]);

	rc = sql_execute("UPDATE users SET credentials = '%s' WHERE nickname = '%s';", cred, user);

	free(user);

	if (rc != 1)
	{
		fprintf(stderr, "Unable to set credentials for user \"%s\"\n", argv[0]);
		return 1;
	}
	return 0;
}

static int pass(size_t argc, const char** argv)
{
	char* user = NULL;
	char* pass = NULL;
	int rc;

	if (argc < 2)
		print_usage("username password");

	user = sql_escape_string(argv[0]);
	pass = sql_escape_string(validate_password(argv[1]));

	rc = sql_execute("UPDATE users SET password = '%s' WHERE nickname = '%s';", pass, user);

	free(user);
	free(pass);

	if (rc != 1)
	{
		fprintf(stderr, "Unable to change password for user \"%s\"\n", argv[0]);
		return 1;
	}

	return 0;
}


static int del(size_t argc, const char** argv)
{
	char* user = NULL;
	int rc;

	if (argc < 1)
		print_usage("username");

	user = sql_escape_string(argv[0]);

	rc = sql_execute("DELETE FROM users WHERE nickname = '%s';", user);
	free(user);

	if (rc != 1)
	{
		fprintf(stderr, "Unable to delete user \"%s\".\n", argv[0]);
		return 1;
	}

	return 0;
}

void main_usage(const char* binary)
{
	printf(
			"Usage: %s filename command [...]\n"
			"\n"
			"Command syntax:\n"
			"  create\n"
			"  add  username password [credentials = user]\n"
			"  del  username\n"
			"  mod  username credentials\n"
			"  pass username password\n"
			"  list\n"
			"\n"
			"Parameters:\n"
			"  'filename' is a database file\n"
			"  'username' is a nickname (UTF-8, up to %i bytes)\n"
			"  'password' is a password (UTF-8, up to %i bytes)\n"
			"  'credentials' is one of 'admin', 'super', 'op', 'user'\n"
			"\n"
		, binary, MAX_NICK_LEN, MAX_PASS_LEN);
}

int main(int argc, char** argv)
{
	size_t n = 0;
	binary = argv[0];
	filename = argv[1];
	command = argv[2];

	if (argc < 3)
	{
		main_usage(argv[0]);
		return 1;
	}

	for (; n < sizeof(COMMANDS) / sizeof(COMMANDS[0]); n++)
	{
		if (!strcmp(command, COMMANDS[n].command))
			return COMMANDS[n].handle(argc - 3, (const char**) &argv[3]);
	}

	// Unknown command!
	main_usage(argv[0]);
	return 1;
}


