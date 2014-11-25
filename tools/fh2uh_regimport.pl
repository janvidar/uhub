#!/usr/bin/perl

# A simple tool for importing FlexHub users to uhub sqlite database
#
# Usage: ./fh2uh_regimport.pl <flexhub_userlist> <uhub_database>
#
# Note: uhub database has to be created before running this script.

use File::Slurp;
use Data::Dumper;
use DBI;

my @uhubaccounts;
my $text = read_file $ARGV[0];
my $dbfile = $ARGV[1];

sub convertprofile
{
	$flexprofile = $_[0];
	if($flexprofile >= 0 && $flexprofile <= 3)
	{
		return 'user';
	}
	elsif($flexprofile >= 4 && $flexprofile <= 6)
	{
		return 'operator';
	}
	elsif($flexprofile >= 7 && $flexprofile <= 8)
	{
		return 'super';
	}
	elsif($flexprofile >= 9 && $flexprofile <= 10)
	{
		return 'admin';
	}

	return 'unknown';
}

sub parseinfo
{
	my @info = split('\n', $_[0]);

	for my $line (@info)
	{
		chop $line;
		my %reginfo;
		if ($line =~ /\["sNick"\]\s*=\s*\S+/)
		{
			my @nick = split(/\["sNick"\]\s*=\s*"(\S+)"/, $line);
			$reginfo->{'nickname'} = $nick[1];
		}
		elsif ($line =~ /\["sPassword"\]\s*=\s*\S+/)
		{
			my @password = split(/\["sPassword"\]\s*=\s*"(\S+)"/, $line);
			$reginfo->{'password'} = $password[1];
		}
		elsif ($line =~ /\["iLevel"\]\s*=\s*\S+/)
		{
			my @level = split(/\["iLevel"\]\s*=\s*(\d+)/, $line);
			$reginfo->{'credentials'} = convertprofile $level[1];
		}
		elsif ($line =~ /\["iRegDate"\]\s*=\s*\S+/)
		{
			my @created = split(/\["iRegDate"\]\s*=\s*(\d+)/, $line);
			$reginfo->{'created'} = $created[1];
		}
		elsif ($line =~ /\["iLastLogin"\]\s*=\s*\S+/)
		{
			my @activity = split(/\["iLastLogin"\]\s*=\s*(\d+)/, $line);
			$reginfo->{'activity'} = $activity[1];
		}
	}

	return %{$reginfo};
}

sub dbimport
{
	my @arr = @_;
	my $db = DBI->connect("dbi:SQLite:dbname=$dbfile", "", "", {RaiseError => 1, AutoCommit => 1});

	for my $import (@arr)
	{
		if ($import->{'credentials'} ne 'unknown')
		{
			$db->do("INSERT OR IGNORE INTO users (nickname,password,credentials,created,activity) VALUES('$import->{'nickname'}','$import->{'password'}','$import->{'credentials'}',datetime($import->{'created'}, 'unixepoch'),datetime($import->{'activity'}, 'unixepoch'));");
		}
	}

	$db->disconnect();
}


if ($text =~ /tAccounts = {/)
{
	$text =~ s/^(?:.*\n){1}/},\n/;
	my @flexaccounts = split('},.*\n.*\[".+"\] = {', $text);

	shift(@flexaccounts);

	for my $account (@flexaccounts)
	{
		my %info = parseinfo $account;
		push(@uhubaccounts, \%info);
	}

	dbimport @uhubaccounts;

}
else
{
	print "Provided file is not valid FlexHub userlist.\n";
}