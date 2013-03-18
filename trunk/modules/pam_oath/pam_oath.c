/*-
 * Copyright (c) 2012-2013 Universitetet i Oslo
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

#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/oath.h>

#define PAM_OATH_PROMPT "Verification code: "

enum pam_oath_nokey { nokey_error = -1, nokey_fail, nokey_fake, nokey_ignore };

static enum pam_oath_nokey
get_nokey_option(pam_handle_t *pamh, const char *option)
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

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	enum pam_oath_nokey nokey, badkey;
	struct passwd *pwd;
	const char *user;
	char *keyfile;
	struct oath_key *key;
	unsigned long response;
	char *password, *end;
	int pam_err, ret;

	/* unused */
	(void)flags;
	(void)argc;
	(void)argv;

	/* check how to behave if the user does not have a valid key */
	if ((nokey = get_nokey_option(pamh, "nokey")) == nokey_error ||
	    (badkey = get_nokey_option(pamh, "badkey")) == nokey_error)
		return (PAM_SERVICE_ERR);

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if ((pwd = getpwnam(user)) == NULL)
		return (PAM_USER_UNKNOWN);

	/* load key */
	/* XXX implement additional schemes */
	keyfile = calloc(1, strlen(pwd->pw_dir) + sizeof "/.otpauth");
	if (keyfile == NULL)
		return (PAM_SYSTEM_ERR);
	sprintf(keyfile, "%s/.otpauth", pwd->pw_dir);
	key = oath_key_from_file(keyfile);
	free(keyfile);

	/*
	 * The user doesn't have a key, should we fake it?
	 *
	 * XXX implement badkey - currently, oath_key_from_file() doesn't
	 * provide enough information for us to tell the difference
	 * between a bad key and no key at all.
	 */
	if (key == NULL) {
		switch (nokey) {
		case nokey_fail:
			return (PAM_AUTHINFO_UNAVAIL);
		case nokey_fake:
			key = oath_dummy_key(om_hotp, oh_sha1, 6);
			break;
		case nokey_ignore:
			return (PAM_IGNORE);
		default:
			/* can't happen */
			return (PAM_SERVICE_ERR);
		}
	}

	/* get user's response */
	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
	    (const char **)&password, PAM_OATH_PROMPT);
	if (pam_err != PAM_SUCCESS) {
		oath_key_free(key);
		return (pam_err);
	}

	/* convert to number */
	response = strtoul(password, &end, 10);
	if (end == password || *end != '\0')
		response = ULONG_MAX;

	/* verify response */
	if (key->mode == om_hotp)
		ret = oath_hotp_match(key, response, 1);
	else
		ret = oath_totp_match(key, response, 1);
	oath_key_free(key);
	if (ret != 1)
		return (PAM_AUTH_ERR);

	/* XXX write back */
	return (PAM_SUCCESS);
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
