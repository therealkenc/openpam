#!/usr/bin/perl -Tw
#-
# Copyright (c) 2011 Dag-Erling Smørgrav
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $OpenPAM$
#

use strict;
use warnings;
use vars qw(@VOWELS $DICTFILE);

our @VOWELS = qw(a e i o u y);
our $DICTFILE = "/usr/share/dict/web2";

sub usage() {
    die("usage: relname [yyyy-mm-dd]\n");
}

MAIN:{
    my ($year, $month);

    if (@ARGV == 0) {
	my @time = localtime();
	($year, $month) = (1900 + $time[5], 1 + $time[4]);
    } elsif (@ARGV == 1) {
	$ARGV[0] =~ m/^(\d\d\d\d)-(\d\d)(?:-\d\d)?$/
	    or usage();
	($year, $month) = ($1, $2);
    } else {
	usage();
    }
    if ($year < 2000 || $year > 2025 || $month < 1 || $month > 12) {
	usage();
    }
    $year = chr(ord("A") + ($year - 2000));
    $month = $VOWELS[($month - 1) / 2];
    print("$year$month\n");
    open(WEB, "<", $DICTFILE)
	or die("$DICTFILE: $!\n");
    while (<WEB>) {
	print if m/^$year$month\w+$/o;
    }
    close(WEB);
}

1;
