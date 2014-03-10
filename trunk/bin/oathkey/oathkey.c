/*-
 * Copyright (c) 2013-2014 Universitetet i Oslo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openpam_asprintf.h"

#include <security/oath.h>

enum { RET_SUCCESS, RET_FAILURE, RET_ERROR, RET_USAGE, RET_UNAUTH };

static char *user;
static char *keyfile;
static int verbose;

static int isroot;		/* running as root */
static int issameuser;		/* real user same as target user */

/*
 * Generate a new key
 */
static int
oathkey_genkey(int argc, char *argv[])
{
	struct oath_key *key;

	/* XXX add parameters later */
	if (argc != 0)
		return (RET_USAGE);
	(void)argv;

	/* don't let users generate keys for eachother */
	if (!isroot && !issameuser)
		return (RET_UNAUTH);

	if ((key = oath_key_create(user, om_totp, oh_undef, NULL, 0)) == NULL)
		return (RET_ERROR);
	/* XXX should save to file, not print */
	printf("%s\n", oath_key_to_uri(key));
	oath_key_free(key);
	return (RET_SUCCESS);
}

/*
 * Set a user's key
 */
static int
oathkey_setkey(int argc, char *argv[])
{
	struct oath_key *key;

	/* XXX add parameters later */
	if (argc != 1)
		return (RET_USAGE);
	(void)argv;

	/* don't let users set eachother's keys */
	if (!isroot && !issameuser)
		return (RET_UNAUTH);

	if ((key = oath_key_from_uri(argv[0])) == NULL)
		return (RET_ERROR);
	/* XXX should save to file, not print */
	printf("%s\n", oath_key_to_uri(key));
	oath_key_free(key);
	return (RET_SUCCESS);
}

/*
 * Print the otpauth URI for a key
 */
static int
oathkey_uri(int argc, char *argv[])
{
	struct oath_key *key;

	if (argc != 0)
		return (RET_USAGE);
	(void)argv;

	/* don't let users see eachother's keys */
	if (!isroot && !issameuser)
		return (RET_UNAUTH);

	if ((key = oath_key_from_file(keyfile)) == NULL)
		return (RET_ERROR);
	printf("%s\n", oath_key_to_uri(key));
	oath_key_free(key);
	return (RET_SUCCESS);
}

/*
 * Check whether a given response is correct for the given keyfile.
 */
static int
oathkey_verify(int argc, char *argv[])
{
	struct oath_key *key;
	unsigned long response;
	char *end;
	int match;

	if (argc < 1)
		return (RET_USAGE);
	if ((key = oath_key_from_file(keyfile)) == NULL)
		return (RET_ERROR);
	response = strtoul(*argv, &end, 10);
	if (end == *argv || *end != '\0')
		response = ULONG_MAX; /* never valid */
	if (key->mode == om_totp)
		match = oath_totp_match(key, response, 3 /* XXX window */);
	else if (key->mode == om_hotp)
		match = oath_hotp_match(key, response, 17 /* XXX window */);
	else
		match = -1;
	/* oath_*_match() return -1 on error, 0 on failure, 1 on success */
	if (match < 0) {
		warnx("OATH error");
		match = 0;
	}
	if (verbose)
		warnx("response: %lu %s", response,
		    match ? "matched" : "did not match");
	if (match) {
		/* XXX write key back! */
	}
	oath_key_free(key);
	return (match ? RET_SUCCESS : RET_FAILURE);
}

/*
 * Print usage string and exit.
 */
static void
usage(void)
{
	fprintf(stderr,
	    "usage: oathkey [-hv] [-u user] [-k keyfile] <command>\n"
	    "\n"
	    "Commands:\n"
	    "    genkey      Generate a new key\n"
	    "    setkey      Generate a new key\n"
	    "    uri         Print the key in otpauth URI form\n"
	    "    verify <response>\n"
	    "                Verify a response\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	int opt, ret;
	char *cmd;

	/*
	 * Parse command-line options
	 */
	while ((opt = getopt(argc, argv, "hk:u:v")) != -1)
		switch (opt) {
		case 'k':
			keyfile = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'v':
			++verbose;
			break;
		case 'h':
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc-- < 1)
		usage();
	cmd = *argv++;

	/*
	 * Check whether we are (really!) root.
	 */
	if (getuid() == 0)
		isroot = 1;

	/*
	 * If a user was specified on the command line, check whether it
	 * matches our real UID.
	 */
	if (user != NULL) {
		if ((pw = getpwnam(user)) == NULL)
			errx(1, "no such user");
		if (getuid() == pw->pw_uid)
			issameuser = 1;
	}

	/*
	 * If no user was specified on the command line, look up the user
	 * that corresponds to our real UID.
	 */
	if (user == NULL) {
		if ((pw = getpwuid(getuid())) == NULL)
			errx(1, "who are you?");
		if (asprintf(&user, "%s", pw->pw_name) < 0)
			err(1, "asprintf()");
	}

	/*
	 * If no keyfile was specified on the command line, derive it from
	 * the user name.
	 */
	if (keyfile == NULL)
		/* XXX replace with a function that searches multiple locations? */
		if (asprintf(&keyfile, "/var/oath/%s.otpauth", user) < 0)
			err(1, "asprintf()");

	/*
	 * Execute the requested command
	 */
	if (strcmp(cmd, "help") == 0)
		ret = RET_USAGE;
	else if (strcmp(cmd, "genkey") == 0)
		ret = oathkey_genkey(argc, argv);
	else if (strcmp(cmd, "setkey") == 0)
		ret = oathkey_setkey(argc, argv);
	else if (strcmp(cmd, "uri") == 0)
		ret = oathkey_uri(argc, argv);
	else if (strcmp(cmd, "verify") == 0)
		ret = oathkey_verify(argc, argv);
	else
		ret = RET_USAGE;

	/*
	 * Check result and act accordingly
	 */
	switch (ret) {
	case RET_UNAUTH:
		errno = EPERM;
		err(1, "%s", cmd);
		break;
	case RET_USAGE:
		usage();
		break;
	case RET_SUCCESS:
		exit(0);
		break;
	case RET_FAILURE:
		exit(1);
		break;
	case RET_ERROR:
		exit(2);
		break;
	default:
		exit(3);
		break;
	}
	/* not reached */
	exit(255);
}
