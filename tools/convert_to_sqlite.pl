#!/usr/bin/perl

# Usage:
#   cat /etc/uhub/users.conf | tools/convert_to_sqlite.pl | sqlite3 users.db

print <<_;
CREATE TABLE users(
	nickname CHAR(64) UNIQUE,
	password CHAR(64),
	credentials CHAR(5),
	created TIMESTAMP DEFAULT (DATETIME('NOW')),
	activity TIMESTAMP DEFAULT (DATETIME('NOW'))
);
_
sub e($) { (my $v = shift) =~ s/'/\\'/g; $v }
s{^\s*user_(op|admin|super|reg)\s+([^#\s]+):([^#\s]+)}{
	printf "INSERT INTO users (nickname, password, credentials) VALUES('%s','%s','%s');\n", e $2, e $3, $1
}eg while(<>);
