/*-
 * Copyright (c) 2002-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2004-2011 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
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

#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_impl.h"

/*
 * OpenPAM extension
 *
 * Sets the value of a module option
 */

int
openpam_set_option(pam_handle_t *pamh,
	const char *option,
	const char *value)
{
	pam_chain_t *cur;
	pam_opt_t *opt, **optv;
	int i, ol, vl;

	ENTERS(option);
	if (pamh == NULL || pamh->current == NULL || option == NULL)
		RETURNC(PAM_SYSTEM_ERR);
	cur = pamh->current;
	for (i = 0; i < cur->optc; ++i)
		if (strcmp(cur->optv[i]->name, option) == 0)
			break;
	if (value == NULL) {
		/* remove */
		if (i == cur->optc)
			RETURNC(PAM_SUCCESS);
		for (free(cur->optv[i]); i < cur->optc; ++i)
			cur->optv[i] = cur->optv[i + 1];
		cur->optv[i] = NULL;
		cur->optc--;
		RETURNC(PAM_SUCCESS);
	}
	ol = strlen(option) + 1;
	vl = strlen(value) + 1;
	if ((opt = malloc(sizeof *opt + ol + vl)) == NULL)
		RETURNC(PAM_BUF_ERR);
	opt->name = (char *)opt + sizeof *opt;
	strlcpy(opt->name, option, ol);
	opt->value = opt->name + ol;
	strlcpy(opt->value, value, vl);
	if (i == cur->optc) {
		/* add */
		optv = realloc(cur->optv, sizeof *optv * (cur->optc + 2));
		if (optv == NULL) {
			FREE(opt);
			RETURNC(PAM_BUF_ERR);
		}
		optv[i] = opt;
		optv[i + 1] = NULL;
		cur->optv = optv;
		++cur->optc;
	} else {
		/* replace */
		FREE(cur->optv[i]);
		cur->optv[i] = opt;
	}
	RETURNC(PAM_SUCCESS);
}

/*
 * Error codes:
 *
 *	PAM_SYSTEM_ERR
 *	PAM_BUF_ERR
 */

/**
 * The =openpam_set_option function sets the specified option in the
 * context of the currently executing service module.
 *
 * >openpam_get_option
 */
