/*-
 * Copyright (c) 2002 Networks Associates Technologies, Inc.
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
 * $Id$
 */

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include "openpam_impl.h"

/*
 * XSSO 4.2.1
 * XSSO 6 page 56
 *
 * Set the value of an environment variable
 */

int
pam_putenv(pam_handle_t *pamh,
	const char *namevalue)
{
	char **env, *p;
	int i;

	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	/* sanity checks */
	if (namevalue == NULL || (p = strchr(namevalue, '=')) == NULL)
		return (PAM_SYSTEM_ERR);

	/* see if the variable is already in the environment */
	if ((i = openpam_findenv(pamh, namevalue, p - namevalue)) != -1) {
		if ((p = strdup(namevalue)) == NULL)
			return (PAM_BUF_ERR);
		free(pamh->env[i]);
		pamh->env[i] = p;
		return (PAM_SUCCESS);
	}

	/* grow the environment list if necessary */
	if (pamh->env_count == pamh->env_size) {
		env = realloc(pamh->env, pamh->env_size * 2 + 1);
		if (env == NULL)
			return (PAM_BUF_ERR);
		pamh->env = env;
		pamh->env_size = pamh->env_size * 2 + 1;
	}

	/* add the variable at the end */
	if ((pamh->env[pamh->env_count] = strdup(namevalue)) == NULL)
		return (PAM_BUF_ERR);
	++pamh->env_count;
	return (PAM_SUCCESS);
}