#!/usr/bin/perl

my $input = $ARGV[0];

open (FILE, "$input") || die "# Unable to open input file $input: $!";
my @lines = <FILE>;
close (FILE);

print "CREATE TABLE users(nickname CHAR(64) UNIQUE, password CHAR(64), credentials CHAR(5));\n";

foreach my $line (@lines) {

	chomp($line);

	$line =~ s/#.*//g;

	next if ($line =~ /^\s*$/);

	if ($line =~ /^\s*user_(op|admin|super|reg)\s*(.+):(.+)\s*/)
	{
		my $cred = $1;
		my $nick = $2;
		my $pass = $3;
		
		$nick =~ s/'/\\'/g;
		$pass =~ s/'/\\'/g;

		print "INSERT INTO users VALUES('" . $nick . "', '" . $pass . "', '" . $cred . "');\n";
	}
	else
	{
		# print "# Warning: Unrecognized line: \"" . $line . "\"\n";
	}
}




