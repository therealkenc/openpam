#!/usr/bin/perl -Tw
#-
# Copyright (c) 2012 Dag-Erling Smørgrav
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer
#    in this position and unchanged.
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
# $Id$
#

use strict;
use warnings;

while (<>) {
    if (m/^OpenPAM ([A-Z][a-z]+)\t+(\d\d\d\d-\d\d-\d\d)\s*$/) {
	my ($relname, $reldate) = ($1, $2);
	my $wikitext = "= OpenPAM $relname =\n" .
	    "\n" .
	    "OpenPAM $relname was released on $reldate.\n";
	while (<>) {
	    last if m/^=+$/;
	    $wikitext .= $_;
	}
	$wikitext =~ s/^ - ([A-Z]+): / - '''$1''' /gm;
	$wikitext =~ s/(\w+\(\d*\))/`$1`/gs;
	$wikitext =~ s/([^'])\b([A-Z_]{2,})\b([^'])/$1`$2`$3/gs;
	$wikitext =~ s/([.!?])\n +(\w)/$1  $2/gs;
	$wikitext =~ s/(\S)\n +(\S)/$1 $2/gs;
	$wikitext .= "\n" .
	    "[http://sourceforge.net/projects/openpam/files/openpam/$relname/ Download from Sourceforge]\n";
	open(my $fh, ">", "$relname.txt")
	    or die("$relname.txt: $!\n");
	print($fh $wikitext);
	close($fh);
	print("|| $reldate || [[Releases/$relname|$relname]] ||\n");
    }
}

1;
