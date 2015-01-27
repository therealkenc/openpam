/*-
 * Copyright (c) 2012-2013 The University of Oslo
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

#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/oath.h>

#define PAM_OATH_PROMPT "Verification code: "
#define PAM_OATH_HOTP_WINDOW 3
#define PAM_OATH_TOTP_WINDOW 3

enum pam_oath_nokey { nokey_error = -1, nokey_fail, nokey_fake, nokey_ignore };

static const char *pam_oath_default_keyfile = "/var/oath/%u.otpauth";

/*
 * Parse the nokey or badkey option, which indicates how we should act if
 * the user has no keyfile or the keyfile is invalid.
 */
static enum pam_oath_nokey
pam_oath_nokey_option(pam_handle_t *pamh, const char *option)
{
	const char *value;

	if ((value = openpam_get_option(pamh, option)) == NULL)
		return (nokey_fail);
	else if (strcmp(value, "fail") == 0)
		return (nokey_fail);
	else if (strcmp(value, "fake") == 0)
		return (nokey_fake);
	else if (strcmp(value, "ignore") == 0)
		return (nokey_ignore);
	openpam_log(PAM_LOG_ERROR, "the value of the %s option "
	    "must be either 'fail', 'fake' or 'ignore'", option);
	return (nokey_error);
}

/*
 * Parse a numeric option.  Returns -1 if the option is not set or its
 * value is not an integer in the range [0, INT_MAX].
 */
static int
pam_oath_int_option(pam_handle_t *pamh, const char *option)
{
	const char *value;
	char *end;
	long num;

	if ((value = openpam_get_option(pamh, option)) == NULL)
		return (-1);
	num = strtol(value, &end, 10);
	if (*value == '\0' || *end != '\0' || num < 0 || num > INT_MAX) {
		openpam_log(PAM_LOG_ERROR, "the value of the %s option "
		    "is invalid.", option);
		return (-1);
	}
	return (num);
}

/*
 * Determine the location of the user's keyfile.
 */
static char *
pam_oath_keyfile(pam_handle_t *pamh)
{
	const char *keyfile;
	char *path;
	size_t size;

	if ((keyfile = openpam_get_option(pamh, "keyfile")) == NULL)
		keyfile = pam_oath_default_keyfile;
	size = 0;
	if (openpam_subst(pamh, NULL, &size, keyfile) != PAM_TRY_AGAIN)
		return (NULL);
	if ((path = malloc(size)) == NULL)
		return (NULL);
	if (openpam_subst(pamh, path, &size, keyfile) != PAM_SUCCESS) {
		free(path);
		return (NULL);
	}
	return (path);
}

/*
 * Load the user's key.
 */
static struct oath_key *
pam_oath_load_key(const char *keyfile)
{

	/* XXX should check ownership and permissions */
	return (oath_key_from_file(keyfile));
}

/*
 * Save the user's key.
 * XXX should be a liboath API function.
 */
static int
pam_oath_save_key(const struct oath_key *key, const char *keyfile)
{
	char *keyuri;
	int fd, len, pam_err;

	keyuri = NULL;
	len = 0;
	fd = -1;
	pam_err = PAM_SYSTEM_ERR;
	if ((keyuri = oath_key_to_uri(key)) == NULL)
		goto done;
	len = strlen(keyuri);
	if ((fd = open(keyfile, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0 ||
	    write(fd, keyuri, len) != len || write(fd, "\n", 1) != 1) {
		openpam_log(PAM_LOG_ERROR, "%s: %m", keyfile);
		goto done;
	}
	pam_err = PAM_SUCCESS;
done:
	if (fd >= 0)
		close(fd);
	if (keyfile != NULL) {
		memset(keyuri, 0, len);
		free(keyuri);
	}
	return (pam_err);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	enum pam_oath_nokey nokey, badkey;
	struct passwd *pwd;
	const char *user, *password;
	char *end, *keyfile;
	struct oath_key *key;
	unsigned long response;
	int pam_err, ret, window;

	/* unused */
	(void)flags;
	(void)argc;
	(void)argv;

	keyfile = NULL;
	key = NULL;

	openpam_log(PAM_LOG_VERBOSE, "attempting OATH authentication");

	/* check how to behave if the user does not have a valid key */
	if ((nokey = pam_oath_nokey_option(pamh, "nokey")) == nokey_error ||
	    (badkey = pam_oath_nokey_option(pamh, "badkey")) == nokey_error) {
		pam_err = PAM_SERVICE_ERR;
		goto done;
	}

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		goto done;
	if ((pwd = getpwnam(user)) == NULL) {
		pam_err = PAM_USER_UNKNOWN;
		goto done;
	}

	openpam_log(PAM_LOG_VERBOSE, "authenticating user %s", user);

	/* load key */
	if ((keyfile = pam_oath_keyfile(pamh)) == NULL) {
		pam_err = PAM_SYSTEM_ERR;
		goto done;
	}
	openpam_log(PAM_LOG_VERBOSE, "attempting to load %s for %s", keyfile, user);
	key = pam_oath_load_key(keyfile);

	/*
	 * The user doesn't have a key, should we fake it?
	 *
	 * XXX implement badkey - currently, oath_key_from_file() doesn't
	 * provide enough information for us to tell the difference
	 * between a bad key and no key at all.
	 *
	 * XXX move this into pam_oath_load_key()
	 */
	if (key == NULL) {
		openpam_log(PAM_LOG_VERBOSE, "no key found for %s", user);
		switch (nokey) {
		case nokey_fail:
			pam_err = PAM_AUTHINFO_UNAVAIL;
			goto done;
		case nokey_fake:
			key = oath_key_dummy(om_hotp, oh_sha1, 6);
			break;
		case nokey_ignore:
			pam_err = PAM_IGNORE;
			goto done;
		default:
			/* can't happen */
			pam_err = PAM_SERVICE_ERR;
			goto done;
		}
	}

	/* get user's response */
	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
	    &password, PAM_OATH_PROMPT);
	if (pam_err != PAM_SUCCESS) {
		openpam_log(PAM_LOG_VERBOSE, "conversation failure");
		goto done;
	}

	/* convert to number */
	response = strtoul(password, &end, 10);
	if (end == password || *end != '\0')
		response = ULONG_MAX;

	/* verify response */
	if (key->mode == om_hotp) {
		if ((window = pam_oath_int_option(pamh, "hotp_window")) < 0 &&
		    (window = pam_oath_int_option(pamh, "window")) < 0)
			window = PAM_OATH_HOTP_WINDOW;
		ret = oath_hotp_match(key, response, window);
	} else {
		if ((window = pam_oath_int_option(pamh, "totp_window")) < 0 &&
		    (window = pam_oath_int_option(pamh, "window")) < 0)
			window = PAM_OATH_TOTP_WINDOW;
		ret = oath_totp_match(key, response, window);
	}
	openpam_log(PAM_LOG_VERBOSE, "verification code %s",
	    ret > 0 ? "matched" : "did not match");
	if (ret <= 0) {
		pam_err = ret < 0 ? PAM_SERVICE_ERR : PAM_AUTH_ERR;
		goto done;
	}

	/* write back the key (update counter for HOTP, lastused for TOTP) */
	if (pam_oath_save_key(key, keyfile) != 0) {
		pam_err = PAM_SERVICE_ERR;
		goto done;
	}

	openpam_log(PAM_LOG_VERBOSE, "OATH authentication succeeded");
	pam_err = PAM_SUCCESS;
done:
	oath_key_free(key);
	free(keyfile);
	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	/* unused */
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	/* unused */
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_unix");
