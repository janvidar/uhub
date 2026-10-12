#include "system.h"
#include "util/log.h"

/*
 * The log level names behind !loglevel. The index of a name is the level
 * itself, so the names have to stay in step with enum log_verbosity.
 */

EXO_TEST(log_level_names_follow_enum, {
	return !strcmp(hub_log_level_to_string(log_fatal), "fatal")
		&& !strcmp(hub_log_level_to_string(log_warning), "warning")
		&& !strcmp(hub_log_level_to_string(log_info), "info")
		&& !strcmp(hub_log_level_to_string(log_debug), "debug")
		&& !strcmp(hub_log_level_to_string(log_protocol), "protocol")
		&& !strcmp(hub_log_level_to_string(log_plugin), "plugin");
});

EXO_TEST(log_level_name_out_of_range, {
	return hub_log_level_to_string(-1) == NULL
		&& hub_log_level_to_string(log_plugin + 1) == NULL;
});

EXO_TEST(log_level_from_name, {
	return hub_log_level_from_string("info") == log_info
		&& hub_log_level_from_string("TRACE") == log_trace
		&& hub_log_level_from_string("Warning") == log_warning;
});

EXO_TEST(log_level_from_unknown_name, {
	return hub_log_level_from_string("verbose") == -1
		&& hub_log_level_from_string("") == -1
		&& hub_log_level_from_string(NULL) == -1;
});

/* Every name maps back to its own level. */
EXO_TEST(log_level_round_trip, {
	int level;
	for (level = log_fatal; level <= log_plugin; level++)
		if (hub_log_level_from_string(hub_log_level_to_string(level)) != level)
			return 0;
	return 1;
});

/* Set and read back, then put the verbosity back the way it was. */
EXO_TEST(log_verbosity_get_set, {
	int saved = hub_get_log_verbosity();
	int ok;
	hub_set_log_verbosity(log_debug + 1);
	ok = hub_get_log_verbosity() == log_debug + 1 && hub_log_enabled(log_debug) && !hub_log_enabled(log_trace);
	hub_set_log_verbosity(saved);
	return ok;
});
