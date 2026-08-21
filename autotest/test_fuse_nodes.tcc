#include "system.h"
#include "util/memory.h"
#include "fuse/nodes.h"

static struct fs_node node;

static enum fs_node_type resolve(const char* path)
{
	fs_node_resolve(path, &node);
	return node.type;
}

#define CID_A "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CID_B "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

EXO_TEST(fuse_nodes_root, { return resolve("/") == FS_NODE_ROOT; });
EXO_TEST(fuse_nodes_relative, { return resolve("hub") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_null, { return resolve(NULL) == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_unknown_top, { return resolve("/nope") == FS_NODE_NONE; });

EXO_TEST(fuse_nodes_hub_dir, { return resolve("/hub") == FS_NODE_HUB_DIR; });
EXO_TEST(fuse_nodes_hub_dir_slash, { return resolve("/hub/") == FS_NODE_HUB_DIR; });
EXO_TEST(fuse_nodes_hub_name, {
	return resolve("/hub/name") == FS_NODE_HUB_FILE && strcmp(node.field->name, "name") == 0;
});
EXO_TEST(fuse_nodes_hub_unknown, { return resolve("/hub/nope") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_hub_too_deep, { return resolve("/hub/name/x") == FS_NODE_NONE; });

EXO_TEST(fuse_nodes_me_dir, { return resolve("/me") == FS_NODE_ME_DIR; });
EXO_TEST(fuse_nodes_me_cid, { return resolve("/me/cid") == FS_NODE_ME_FILE; });

EXO_TEST(fuse_nodes_chat_dir, { return resolve("/chat") == FS_NODE_CHAT_DIR; });
EXO_TEST(fuse_nodes_chat_main, { return resolve("/chat/main") == FS_NODE_CHAT_MAIN; });
EXO_TEST(fuse_nodes_chat_private, { return resolve("/chat/private") == FS_NODE_CHAT_PRIVATE; });
EXO_TEST(fuse_nodes_chat_other, { return resolve("/chat/other") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_chat_too_deep, { return resolve("/chat/main/x") == FS_NODE_NONE; });

EXO_TEST(fuse_nodes_users_dir, { return resolve("/users") == FS_NODE_USERS_DIR; });
EXO_TEST(fuse_nodes_user_dir, {
	return resolve("/users/" CID_A) == FS_NODE_USER_DIR && strcmp(node.cid, CID_A) == 0;
});
EXO_TEST(fuse_nodes_user_short_cid, { return resolve("/users/AAA") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_user_long_cid, { return resolve("/users/" CID_A "A") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_user_bad_cid, {
	/* '1' and '0' are not in the base32 alphabet. Still 39 characters, so
	   this fails on the alphabet and not on the length. */
	return resolve("/users/1" "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") == FS_NODE_NONE;
});
EXO_TEST(fuse_nodes_user_nick, {
	return resolve("/users/" CID_A "/nick") == FS_NODE_USER_FILE
		&& strcmp(node.field->name, "nick") == 0
		&& strcmp(node.cid, CID_A) == 0;
});
EXO_TEST(fuse_nodes_user_inf_is_raw, {
	return resolve("/users/" CID_A "/inf") == FS_NODE_USER_FILE
		&& (node.field->flags & FS_FIELD_RAW_INF);
});
EXO_TEST(fuse_nodes_user_msg_is_write, {
	return resolve("/users/" CID_A "/msg") == FS_NODE_USER_MSG
		&& (node.field->flags & FS_FIELD_WRITE);
});
EXO_TEST(fuse_nodes_user_unknown_file, { return resolve("/users/" CID_A "/nope") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_user_files_dir, { return resolve("/users/" CID_A "/files") == FS_NODE_USER_FILES_DIR; });
EXO_TEST(fuse_nodes_user_files_dir_slash, { return resolve("/users/" CID_A "/files/") == FS_NODE_USER_FILES_DIR; });
EXO_TEST(fuse_nodes_user_files_entry, {
	return resolve("/users/" CID_A "/files/Movies/foo.mkv") == FS_NODE_USER_FILES_ENTRY
		&& strcmp(node.tail, "Movies/foo.mkv") == 0;
});

EXO_TEST(fuse_nodes_by_nick_dir, { return resolve("/by-nick") == FS_NODE_BY_NICK_DIR; });
EXO_TEST(fuse_nodes_by_nick_link, {
	return resolve("/by-nick/alice") == FS_NODE_BY_NICK_LINK && strcmp(node.name, "alice") == 0;
});
EXO_TEST(fuse_nodes_by_tth_dir, { return resolve("/by-tth") == FS_NODE_BY_TTH_DIR; });
EXO_TEST(fuse_nodes_by_tth_file, {
	return resolve("/by-tth/" CID_B) == FS_NODE_BY_TTH_FILE && strcmp(node.name, CID_B) == 0;
});
EXO_TEST(fuse_nodes_by_tth_bad, { return resolve("/by-tth/nope") == FS_NODE_NONE; });

/* Path traversal: FUSE normalises, but this is the boundary and it does not
   get to rely on that. */
EXO_TEST(fuse_nodes_dotdot, { return resolve("/users/../etc") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_dot, { return resolve("/hub/./name") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_empty_component, { return resolve("//hub") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_embedded_empty, { return resolve("/hub//name") == FS_NODE_NONE; });
EXO_TEST(fuse_nodes_files_dotdot, {
	return resolve("/users/" CID_A "/files/../../../etc/passwd") == FS_NODE_NONE;
});
EXO_TEST(fuse_nodes_files_empty_component, {
	return resolve("/users/" CID_A "/files/a//b") == FS_NODE_NONE;
});

EXO_TEST(fuse_nodes_field_lookup_missing, {
	return fs_field_lookup(fs_user_fields, "does_not_exist") == NULL;
});
EXO_TEST(fuse_nodes_field_lookup_null, {
	return fs_field_lookup(fs_user_fields, NULL) == NULL;
});

EXO_TEST(fuse_nodes_hash_ok, { return fs_is_base32_hash(CID_A) == 1; });
EXO_TEST(fuse_nodes_hash_null, { return fs_is_base32_hash(NULL) == 0; });
EXO_TEST(fuse_nodes_hash_empty, { return fs_is_base32_hash("") == 0; });

/* -------------------------------------------------------------- nick names */

static char nick[64];

EXO_TEST(fuse_nick_plain, {
	fs_sanitize_nick("alice", nick, sizeof(nick));
	return strcmp(nick, "alice") == 0;
});
EXO_TEST(fuse_nick_slash, {
	fs_sanitize_nick("a/b", nick, sizeof(nick));
	return strcmp(nick, "a_b") == 0;
});
EXO_TEST(fuse_nick_control, {
	fs_sanitize_nick("a\tb\x7f", nick, sizeof(nick));
	return strcmp(nick, "a_b_") == 0;
});
EXO_TEST(fuse_nick_utf8_kept, {
	fs_sanitize_nick("\xc3\xa5se", nick, sizeof(nick));
	return strcmp(nick, "\xc3\xa5se") == 0;
});
EXO_TEST(fuse_nick_empty, {
	fs_sanitize_nick("", nick, sizeof(nick));
	return strcmp(nick, "user") == 0;
});
EXO_TEST(fuse_nick_null, {
	fs_sanitize_nick(NULL, nick, sizeof(nick));
	return strcmp(nick, "user") == 0;
});
EXO_TEST(fuse_nick_dot, {
	fs_sanitize_nick(".", nick, sizeof(nick));
	return strcmp(nick, "user") == 0;
});
EXO_TEST(fuse_nick_dotdot, {
	fs_sanitize_nick("..", nick, sizeof(nick));
	return strcmp(nick, "user") == 0;
});
EXO_TEST(fuse_nick_truncates, {
	char small[4];
	size_t n = fs_sanitize_nick("abcdefgh", small, sizeof(small));
	return n == 3 && strcmp(small, "abc") == 0;
});
EXO_TEST(fuse_nick_zero_size, {
	return fs_sanitize_nick("alice", nick, 0) == 0;
});
