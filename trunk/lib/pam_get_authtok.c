/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
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
 * $P4: //depot/projects/openpam/lib/pam_get_authtok.c#13 $
 */

#include <sys/param.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_impl.h"

const char authtok_prompt[] = "Password:";
const char oldauthtok_prompt[] = "Old Password:";

/*
 * OpenPAM extension
 *
 * Retrieve authentication token
 */

int
pam_get_authtok(pam_handle_t *pamh,
	int item,
	const char **authtok,
	const char *prompt)
{
	const char *default_prompt;
	char *resp;
	int pitem, r, style;

	if (pamh == NULL || authtok == NULL)
		return (PAM_SYSTEM_ERR);

	*authtok = NULL;
	switch (item) {
	case PAM_AUTHTOK:
		pitem = PAM_AUTHTOK_PROMPT;
		default_prompt = authtok_prompt;
		break;
	case PAM_OLDAUTHTOK:
		pitem = PAM_OLDAUTHTOK_PROMPT;
		default_prompt = oldauthtok_prompt;
		break;
	default:
		return (PAM_SYMBOL_ERR);
	}

	if (openpam_get_option(pamh, "try_first_pass") ||
	    openpam_get_option(pamh, "use_first_pass")) {
		r = pam_get_item(pamh, item, (const void **)authtok);
		if (r == PAM_SUCCESS && *authtok != NULL)
			return (PAM_SUCCESS);
		else if (openpam_get_option(pamh, "use_first_pass"))
			return (r == PAM_SUCCESS ? PAM_AUTH_ERR : r);
	}
	if (prompt == NULL) {
		r = pam_get_item(pamh, pitem, (const void **)&prompt);
		if (r != PAM_SUCCESS || prompt == NULL)
			prompt = default_prompt;
	}
	style = openpam_get_option(pamh, "echo_pass") ?
	    PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
	r = pam_prompt(pamh, style, &resp, "%s", prompt);
	if (r != PAM_SUCCESS)
		return (r);
	*authtok = resp;
	return (pam_set_item(pamh, item, *authtok));
}

/*
 * Error codes:
 *
 *	=pam_get_item
 *	=pam_prompt
 *	=pam_set_item
 *	!PAM_SYMBOL_ERR
 */

/**
 * The =pam_get_authtok function returns the cached authentication token,
 * or prompts the user if no token is currently cached.  Either way, a
 * pointer to the authentication token is stored in the location pointed
 * to by the =authtok argument.
 *
 * The =item argument must have one of the following values:
 *
 *	=PAM_AUTHTOK
 *		Returns the current authentication token, or the new token
 *		when changing authentication tokens.
 *	=PAM_OLDAUTHTOK
 *		Returns the previous authentication token when changing
 *		authentication tokens.
 *
 * The =prompt argument specifies a prompt to use if no token is cached.
 * If =NULL, the =PAM_AUTHTOK_PROMPT or =PAM_OLDAUTHTOK_PROMPT item, as
 * appropriate, will be used.  If that item is also =NULL, a hardcoded
 * default prompt will be used.
 *
 * >pam_get_item
 */
