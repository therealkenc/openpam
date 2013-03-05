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

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct passwd *pwd;
	const char *user;
	char *keyfile;
	struct oath_key *key;
	unsigned long code;
	char *password, *end;
	int pam_err, ret;

	(void)flags;
	(void)argc;
	(void)argv;

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if ((pwd = getpwnam(user)) == NULL)
		return (PAM_USER_UNKNOWN);

	/* load key */
	keyfile = calloc(1, strlen(pwd->pw_dir) + sizeof "/.otpauth");
	if (keyfile == NULL)
		return (PAM_SYSTEM_ERR);
	sprintf(keyfile, "%s/.otpauth", pwd->pw_dir);
	free(keyfile);
	if ((key = oath_key_from_file(keyfile)) == NULL) {
		/* no key, fake it? */
		if (openpam_get_option(pamh, "fakeauth") == NULL)
			return (PAM_AUTHINFO_UNAVAIL);
		key = oath_dummy_key(om_hotp, oh_sha1, 6);
	}

	/* get code */
	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
	    (const char **)&password, NULL);
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);

	/* convert to number */
	code = strtoul(password, &end, 10);
	if (end == password || *end != '\0')
		code = ULONG_MAX;

	/* verify response */
	if (key->mode == om_hotp)
		ret = oath_hotp_match(key, code, 1);
	else
		ret = oath_totp_match(key, code, 1);
	oath_key_free(key);
	if (ret != 0)
		return (PAM_AUTH_ERR);

	/* XXX write back */
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

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

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_unix");
