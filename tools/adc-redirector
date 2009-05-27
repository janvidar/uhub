#!/usr/bin/perl -w

# Setup using inetd/xinetd or similar.
# In /etc/inetd.conf add:
# 1511  stream  tcp nowait nobody  /usr/bin/adc-redirector adc://target:port
#
# Change port to whatever you want.
# Make sure the path and the target:port is correct, then you should be good 
# to go!

use strict;
use IO::Handle;
autoflush STDIN;
autoflush STDOUT;

my $target = $ARGV[0];

eval
{
	local %SIG;
	$SIG{ALRM}= sub { exit 0; };
        alarm 30;
};

while (my $line = <STDIN>)
{
	chomp($line);

	if ($line =~ /^HSUP /)
	{
		print "ISUP ADBASE ADPING ADTIGR\n";
		print "ISID AAAX\n";
		print "IINF CT32 NIRedirector VEadc-redirector/0.1\n";
		next;
	}

	if ($line =~ /^BINF /)
	{
		print "$line\n";
		print "IMSG This\\sserver\\shas\\smoved\\sto:\\s" . $target . "\n";
		print "IMSG You\\sare\\sbeing\\sredirected...\n";
		print "IQUI AAAX RD" . $target . "\n";
		alarm 5;
	}
}

alarm 0;

