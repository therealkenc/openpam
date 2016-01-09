/*-
 * Copyright (c) 2013-2014 The University of Oslo
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
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openpam_asprintf.h"

#include <security/oath.h>

/* XXX hardcoded windows */
#define HOTP_WINDOW	9
#define TOTP_WINDOW	2

enum { RET_SUCCESS, RET_FAILURE, RET_ERROR, RET_USAGE, RET_UNAUTH };

static char *user;
static char *keyfile;
static int verbose;
static int readonly;
static int numbered;

static int isroot;		/* running as root */
static int issameuser;		/* real user same as target user */

/*
 * Print key in hexadecimal form
 */
static int
oathkey_print_hex(struct oath_key *key)
{
	unsigned int i;

	for (i = 0; i < key->keylen; ++i)
		printf("%02x", key->key[i]);
	printf("\n");
	return (RET_SUCCESS);
}

/*
 * Print key in otpauth URI form
 */
static int
oathkey_print_uri(struct oath_key *key)
{
	char *keyuri;

	if ((keyuri = oath_key_to_uri(key)) == NULL) {
		warnx("failed to convert key to otpauth URI");
		return (RET_ERROR);
	}
	printf("%s\n", keyuri);
	free(keyuri);
	return (RET_SUCCESS);
}

/*
 * Load key from file
 */
static int
oathkey_load(struct oath_key **key)
{

	if (verbose)
		warnx("loading key from %s", keyfile);
	if ((*key = oath_key_from_file(keyfile)) == NULL) {
		warn("%s", keyfile);
		if (errno == EACCES || errno == EPERM)
			return (RET_UNAUTH);
		return (RET_ERROR);
	}
	return (RET_SUCCESS);
}

/*
 * Save key to file
 * XXX liboath should take care of this for us
 */
static int
oathkey_save(struct oath_key *key)
{
	char *keyuri;
	int fd, len, ret;

	if (verbose)
		warnx("saving key to %s", keyfile);
	keyuri = NULL;
	len = 0;
	fd = ret = -1;
	if ((keyuri = oath_key_to_uri(key)) == NULL) {
		warnx("failed to convert key to otpauth URI");
		goto done;
	}
	len = strlen(keyuri);
	if ((fd = open(keyfile, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0 ||
	    write(fd, keyuri, len) != len || write(fd, "\n", 1) != 1) {
		warn("%s", keyfile);
		goto done;
	}
	ret = 0;
done:
	if (fd >= 0)
		close(fd);
	if (keyuri != NULL)
		free(keyuri);
	return (ret);
}

/*
 * Generate a new key
 */
static int
oathkey_genkey(int argc, char *argv[])
{
	struct oath_key *key;
	enum oath_mode mode;
	int ret;

	if (argc != 1)
		return (RET_USAGE);
	if ((mode = oath_mode(argv[0])) == om_undef)
		return (RET_USAGE);
	if (!isroot && !issameuser)
		return (RET_UNAUTH);
	if ((key = oath_key_create(user, mode, oh_undef, NULL, 0)) == NULL)
		return (RET_ERROR);
	ret = readonly ? oathkey_print_uri(key) : oathkey_save(key);
	oath_key_free(key);
	return (ret);
}

/*
 * Set a user's key
 */
static int
oathkey_setkey(int argc, char *argv[])
{
	struct oath_key *key;
	int ret;

	/* XXX add parameters later */
	if (argc != 1)
		return (RET_USAGE);
	(void)argv;
	if (!isroot && !issameuser)
		return (RET_UNAUTH);
	if ((key = oath_key_from_uri(argv[0])) == NULL)
		return (RET_ERROR);
	ret = oathkey_save(key);
	oath_key_free(key);
	return (ret);
}

/*
 * Print raw key in hexadecimal
 */
static int
oathkey_getkey(int argc, char *argv[])
{
	struct oath_key *key;
	int ret;

	if (argc != 0)
		return (RET_USAGE);
	(void)argv;
	if (!isroot && !issameuser)
		return (RET_UNAUTH);
	if ((ret = oathkey_load(&key)) != RET_SUCCESS)
		return (ret);
	ret = oathkey_print_hex(key);
	oath_key_free(key);
	return (ret);
}

/*
 * Print the otpauth URI for a key
 */
static int
oathkey_geturi(int argc, char *argv[])
{
	struct oath_key *key;
	int ret;

	if (argc != 0)
		return (RET_USAGE);
	(void)argv;
	if (!isroot && !issameuser)
		return (RET_UNAUTH);
	if ((ret = oathkey_load(&key)) != RET_SUCCESS)
		return (ret);
	ret = oathkey_print_uri(key);
	oath_key_free(key);
	return (ret);
}

/*
 * Check whether a given response is correct for the given keyfile.
 */
static int
oathkey_verify(int argc, char *argv[])
{
	struct oath_key *key;
	unsigned long counter;
	unsigned int response;
	char *end;
	int match, ret;

	if (argc < 1)
		return (RET_USAGE);
	if ((ret = oathkey_load(&key)) != RET_SUCCESS)
		return (ret);
	response = strtoul(*argv, &end, 10);
	if (end == *argv || *end != '\0')
		response = UINT_MAX; /* never valid */
	switch (key->mode) {
	case om_hotp:
		counter = key->counter;
		match = oath_hotp_match(key, response, HOTP_WINDOW);
		if (verbose && match > 0 && key->counter > counter + 1)
			warnx("skipped %lu codes", key->counter - counter - 1);
		break;
	case om_totp:
		match = oath_totp_match(key, response, TOTP_WINDOW);
		break;
	default:
		match = -1;
	}
	/* oath_*_match() return -1 on error, 0 on failure, 1 on success */
	if (match < 0) {
		warnx("OATH error");
		match = 0;
	}
	if (verbose)
		warnx("response: %u %s", response,
		    match ? "matched" : "did not match");
	ret = match ? readonly ? RET_SUCCESS : oathkey_save(key) : RET_FAILURE;
	oath_key_free(key);
	return (ret);
}

/*
 * Compute the current code
 */
static int
oathkey_calc(int argc, char *argv[])
{
	struct oath_key *key;
	unsigned int current;
	unsigned long i, n;
	uintmax_t count;
	char *end;
	int ret;

	if (argc > 1)
		return (RET_USAGE);
	if (argc > 0) {
		n = strtoul(argv[0], &end, 10);
		if (end == argv[0] || *end != '\0' || n < 1 || n > 1000)
			return (RET_USAGE);
	} else {
		n = 1;
	}
	if ((ret = oathkey_load(&key)) != RET_SUCCESS)
		return (ret);
	for (i = 0; i < n; ++i) {
		switch (key->mode) {
		case om_hotp:
			current = oath_hotp_current(key);
			count = key->counter;
			break;
		case om_totp:
			current = oath_totp_current(key);
			count = key->lastused * key->timestep;
			break;
		default:
			current = UINT_MAX;
			count = 0;
		}
		if (current == UINT_MAX) {
			warnx("OATH error");
			ret = RET_ERROR;
			break;
		}
		if (numbered)
			printf("%6ju ", count);
		printf("%.*d\n", (int)key->digits, current);
	}
	if (ret == RET_SUCCESS && !readonly)
		ret = oathkey_save(key);
	oath_key_free(key);
	return (ret);
}

/*
 * Resynchronize
 */
static int
oathkey_resync(int argc, char *argv[])
{
	struct oath_key *key;
	unsigned long counter;
	unsigned int response[3];
	char *end;
	int i, match, n, ret, w;

	if (argc < 2 || argc > 3)
		return (RET_USAGE);
	n = argc;
	for (i = 0, w = 1; i < n; ++i) {
		response[i] = strtoul(argv[i], &end, 10);
		if (end == argv[i] || *end != '\0')
			response[i] = UINT_MAX; /* never valid */
		w = w * (HOTP_WINDOW + 1);
	}
	w -= n;
	if ((ret = oathkey_load(&key)) != RET_SUCCESS)
		return (ret);
	switch (key->mode) {
	case om_hotp:
		/* this should be a library function */
		counter = key->counter;
		match = 0;
		while (key->counter < counter + w && match == 0) {
			match = oath_hotp_match(key, response[0],
			    counter + w - key->counter - 1);
			if (match <= 0)
				break;
			for (i = 1; i < n && match > 0; ++i)
				match = oath_hotp_match(key, response[i], 0);
		}
		if (verbose && match > 0)
			warnx("skipped %lu codes", key->counter - counter);
		break;
	default:
		match = -1;
	}
	if (match < 0) {
		warnx("OATH error");
		match = 0;
	}
	if (verbose)
		warnx("resynchronization %s", match ? "succeeded" : "failed");
	ret = match ? readonly ? RET_SUCCESS : oathkey_save(key) : RET_FAILURE;
	oath_key_free(key);
	return (ret);
}

/*
 * Print usage string and exit.
 */
static void
usage(void)
{
	fprintf(stderr,
	    "usage: oathkey [-hnrvw] [-u user] [-k keyfile] command\n"
	    "\n"
	    "Commands:\n"
	    "    calc [count]\n"
            "                Print the next code(s)\n"
	    "    genkey hotp | totp\n"
	    "                Generate a new key\n"
	    "    getkey      Print the key in hexadecimal form\n"
	    "    geturi      Print the key in otpauth URI form\n"
	    "    resync code1 code2 [code3]\n"
	    "                Resynchronize an HOTP token\n"
	    "    setkey      Generate a new key\n"
	    "    verify code\n"
	    "                Verify an HOTP or TOTP code\n");
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
	while ((opt = getopt(argc, argv, "hk:nru:vw")) != -1)
		switch (opt) {
		case 'k':
			keyfile = optarg;
			break;
		case 'n':
			numbered = 1;
			break;
		case 'r':
			readonly = 1;
			break;
		case 'u':
			user = optarg;
			break;
		case 'v':
			++verbose;
			break;
		case 'w':
			readonly = 0;
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
		issameuser = 1;
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
	else if (strcmp(cmd, "calc") == 0)
		ret = oathkey_calc(argc, argv);
	else if (strcmp(cmd, "genkey") == 0)
		ret = oathkey_genkey(argc, argv);
	else if (strcmp(cmd, "getkey") == 0)
		ret = oathkey_getkey(argc, argv);
	else if (strcmp(cmd, "geturi") == 0 || strcmp(cmd, "uri") == 0)
		ret = oathkey_geturi(argc, argv);
	else if (strcmp(cmd, "resync") == 0)
		ret = oathkey_resync(argc, argv);
	else if (strcmp(cmd, "setkey") == 0)
		ret = oathkey_setkey(argc, argv);
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
