#!/usr/bin/perl -w

# Setup using inetd/xinetd or similar.
# In /etc/inetd.conf add:
# 1511  stream  tcp nowait nobody  /usr/bin/nmdc-redirector adc://target:port
#
# Change port to whatever you want.
# Make sure the path and the target:port is correct, then you should be good 
# to go!

use strict;
use IO::Handle;
autoflush STDIN;
autoflush STDOUT;

my $target = $ARGV[0];

print "<Redirector> You are being redirected to " . $target . "|";
print "\$ForceMove " . $target . "|";

