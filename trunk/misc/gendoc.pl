#!/usr/bin/perl -w
#-
# Copyright (c) 2002 Networks Associates Technologies, Inc.
# All rights reserved.
#
# This software was developed for the FreeBSD Project by ThinkSec AS and
# NAI Labs, the Security Research Division of Network Associates, Inc.
# under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
# DARPA CHATS research program.
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
# $Id$
#

use strict;
use Fcntl;
use POSIX qw(strftime);
use vars qw($TODAY %FUNCTIONS);

sub gendoc($) {
    my $fn = shift;

    local *FILE;
    my $source;
    my $mdoc;
    my $func;
    my $descr;
    my $type;
    my $args;
    my $name;

    if ($fn !~ m,\.c$,) {
	warn("$fn: not C source, ignoring\n");
	return;
    }
    
    sysopen(FILE, $fn, O_RDONLY)
	or die("$fn: open(): $!\n");
    $source = join('', <FILE>);
    close(FILE);

    if ($source =~ m,^(/\*-\n.*?)\s*\*/,s) {
	$mdoc = $1;
	$mdoc =~ s,^.\*,.\\\",gm;
	$mdoc .= "\n.\\\"\n";
    } else {
	$mdoc = ".\\\" \$" . "Id" . "\$\n";
    }
    $func = $fn;
    $func =~ s,^(?:.*/)?([^/]+)\.c$,$1,;
    if ($source !~ m,\n \* ([\S ]+)\n \*/\n\n([\S ]+)\n$func\((.*?)\)\n\{,s) {
	warn("$fn: can't find $func\n");
	return;
    }
    ($descr, $type, $args) = ($1, $2, $3);
    $descr =~ s,^([A-Z][a-z]),lc($1),e;
    $descr =~ s,[\.\s]*$,,;
    while ($args =~ s/^((?:[^\(]|\([^\)]*\))*),\s*/$1\" \"/g) {
	# nothing
    }
    $args =~ s/,\s+/, /gs;
    $args = "\"$args\"";

    $FUNCTIONS{$func} = [ $type, $args ];
    
    $mdoc .= ".Dd $TODAY
.Dt " . uc($func) . " 3
.Os
.Sh NAME
.Nm $func
.Nd $descr
.Sh LIBRARY
.Lb libpam
.Sh SYNOPSIS
.In security/pam_appl.h
.Ft $type
.Fn $func $args
.Sh DESCRIPTION
The
.Nm
function is not yet documented.
.Sh RETURN VALUES
The
.Fn
function returns one of the following values:
.Bl -tag -width PAM_AUTHTOK_DISABLE_AGING
.El
.Sh SEE ALSO
.Xr pam_strerror 3 ,
.Xr pam 3
.Sh STANDARDS
.Rs
.%T \"X/Open Single Sign-On Service (XSSO) - Pluggable Authentication Modules\"
.%D \"June 1997\"
.Re
.AUTHORS
The
.Nm
function and this manual page were developed for the FreeBSD Project
by ThinkSec AS and NAI Labs, the Security Research Division of Network
Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
.Pq .Dq CBOSS ,
as part of the DARPA CHATS research program.
";

     $fn =~ s,\.c$,.3,;
     sysopen(FILE, $fn, O_RDWR|O_CREAT|O_TRUNC)
 	or die("$fn: open(): $!\n");
     print(FILE $mdoc);
     close(FILE);
}

sub gensummary() {

    print ".Dd $TODAY
.Dt PAM 3
.Os
.Sh NAME
";
    my @funcs = sort(keys(%FUNCTIONS));
    while (@funcs) {
        print ".Nm " . shift(@funcs) . (@funcs ? " ,\n" : "\n");
    }
    print ".Nd Pluggable Authentication Modules
.Sh LIBRARY
.Lb libpam
.Sh SYNOPSIS
.In security/pam_appl.h
";
    foreach my $func (sort(keys(%FUNCTIONS))) {
        print ".Ft $FUNCTIONS{$func}->[0]\n";
        print ".Fn $func $FUNCTIONS{$func}->[1]\n";
    }
    print ".Sh DESCRIPTION
Foo
.Sh RETURN VALUES
.Sh SEE ALSO
";
    foreach my $func (sort(keys(%FUNCTIONS))) {
        print ".Xr $func 4 ,\n";
    }
    print ".Xr pam.conf 5
.Sh STANDARDS
.Rs
.%T \"X/Open Single Sign-On Service (XSSO) - Pluggable Authentication Modules\"
.%D \"June 1997\"
.Re
.AUTHORS
The OpenPAM library and this manual page were developed for the
FreeBSD Project by ThinkSec AS and NAI Labs, the Security Research
Division of Network Associates, Inc.  under DARPA/SPAWAR contract
N66001-01-C-8035
.Pq .Dq CBOSS ,
as part of the DARPA CHATS research program.
"
}

MAIN:{
    $TODAY = strftime("%B %e, %Y", localtime(time()));
    $TODAY =~ s,\s+, ,g;
    foreach my $fn (@ARGV) {
	gendoc($fn);
    }
    gensummary();
}
