/*-
 * Copyright (c) 2015 Dag-Erling Smørgrav
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_impl.h"
#include "t.h"
#include "t_pam_conv.h"

T_FUNC(empty_policy, "empty policy")
{
	struct t_pam_conv_script script;
	struct pam_conv pamc;
	struct t_file *tf;
	pam_handle_t *pamh;
	int pam_err, ret;

	memset(&script, 0, sizeof script);
	pamc.conv = &t_pam_conv;
	pamc.appdata_ptr = &script;
	tf = t_fopen(NULL);
	t_fprintf(tf, "# empty policy\n");
	pam_err = pam_start(tf->name, "test", &pamc, &pamh);
	t_verbose("pam_start() returned %d\n", pam_err);
	/*
	 * Note: openpam_dispatch() currently returns PAM_SYSTEM_ERR when
	 * the chain is empty, it should possibly return PAM_SERVICE_ERR
	 * instead.
	 */
	pam_err = pam_authenticate(pamh, 0);
	t_verbose("pam_authenticate() returned %d\n", pam_err);
	ret = (pam_err != PAM_SUCCESS);
	pam_err = pam_setcred(pamh, 0);
	t_verbose("pam_setcred() returned %d\n", pam_err);
	ret |= (pam_err != PAM_SUCCESS);
	pam_err = pam_acct_mgmt(pamh, 0);
	t_verbose("pam_acct_mgmt() returned %d\n", pam_err);
	ret |= (pam_err != PAM_SUCCESS);
	pam_err = pam_chauthtok(pamh, 0);
	t_verbose("pam_chauthtok() returned %d\n", pam_err);
	ret |= (pam_err != PAM_SUCCESS);
	pam_err = pam_open_session(pamh, 0);
	t_verbose("pam_open_session() returned %d\n", pam_err);
	ret |= (pam_err != PAM_SUCCESS);
	pam_err = pam_close_session(pamh, 0);
	t_verbose("pam_close_session() returned %d\n", pam_err);
	ret |= (pam_err != PAM_SUCCESS);
	pam_err = pam_end(pamh, pam_err);
	ret |= (pam_err == PAM_SUCCESS);
	t_fclose(tf);
	return (ret);
}


/***************************************************************************
 * Boilerplate
 */

static const struct t_test *t_plan[] = {
	T(empty_policy),

	NULL
};

const struct t_test **
t_prepare(int argc, char *argv[])
{

	openpam_set_feature(OPENPAM_RESTRICT_MODULE_NAME, 0);
	openpam_set_feature(OPENPAM_VERIFY_MODULE_FILE, 0);
	openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME, 0);
	openpam_set_feature(OPENPAM_VERIFY_POLICY_FILE, 0);
	openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0);

	(void)argc;
	(void)argv;
	return (t_plan);
}

void
t_cleanup(void)
{
}
