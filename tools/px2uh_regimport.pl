#!/usr/bin/perl

# A simple tool for importing PtokaX (< 0.5.0.0) users to uhub sqlite database.
# Userlist MUST be in xml format.
#
# Usage: ./px2uh_regimport.pl <ptokax_userlist.xml> <uhub_database.db>
#
# Note: uhub database has to be created before running this script.

use XML::Simple;
use DBI;

# create xml object
my $xml = new XML::Simple;

# read XML file
my $regdata = $xml->XMLin($ARGV[0], ForceArray => [ 'RegisteredUser' ]);

my $dbfile = $ARGV[1];
my @pxaccounts = @{$regdata->{'RegisteredUser'}};

sub convertprofile
{
	$pxprofile = $_[0];
	if($pxprofile == 2 || $pxprofile == 3)
	{
		return 'user';
	}
	elsif($pxprofile == 1)
	{
		return 'operator';
	}
	elsif($pxprofile == 0)
	{
		return 'admin';
	}

	return 'unknown';
}

sub dbimport
{
	my @arr = @_;
	my $db = DBI->connect("dbi:SQLite:dbname=$dbfile", "", "", {RaiseError => 1, AutoCommit => 1});

	for my $import (@arr)
	{
		if ($import->{'credentials'} ne 'unknown')
		{
			$db->do("INSERT OR IGNORE INTO users (nickname,password,credentials) VALUES('$import->{'Nick'}','$import->{'Password'}','$import->{'credentials'}');");
		}
	}

	$db->disconnect();
}

for my $account (@pxaccounts)
{
	$account->{'credentials'} = convertprofile $account->{'Profile'};
}

dbimport @pxaccounts; 
