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

#include <sys/param.h>

#include <security/pam_appl.h>

#include "openpam_impl.h"

#if !defined(OPENPAM_RELAX_CHECKS)
static void _openpam_check_error_code(int, int);
#else
#define _openpam_check_error_code(a, b)
#endif /* !defined(OPENPAM_RELAX_CHECKS) */

/*
 * OpenPAM internal
 *
 * Execute a module chain
 */

int
openpam_dispatch(pam_handle_t *pamh,
	int primitive,
	int flags)
{
	pam_chain_t *chain;
	int err, fail, r;

	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	/* prevent recursion */
	if (pamh->current != NULL) {
		openpam_log(PAM_LOG_ERROR, "indirect recursion");
		return (PAM_ABORT);
	}

	/* pick a chain */
	switch (primitive) {
	case PAM_SM_AUTHENTICATE:
	case PAM_SM_SETCRED:
		chain = pamh->chains[PAM_AUTH];
		break;
	case PAM_SM_ACCT_MGMT:
		chain = pamh->chains[PAM_ACCOUNT];
		break;
	case PAM_SM_OPEN_SESSION:
	case PAM_SM_CLOSE_SESSION:
		chain = pamh->chains[PAM_SESSION];
		break;
	case PAM_SM_CHAUTHTOK:
		chain = pamh->chains[PAM_PASSWORD];
		break;
	default:
		return (PAM_SYSTEM_ERR);
	}

	/* execute */
	for (err = fail = 0; chain != NULL; chain = chain->next) {
		openpam_log(PAM_LOG_DEBUG, "calling %s() in %s",
		    _pam_sm_func_name[primitive], chain->module->path);
		if (chain->module->func[primitive] == NULL) {
			openpam_log(PAM_LOG_ERROR, "%s: no %s()",
			    chain->module->path, _pam_sm_func_name[primitive]);
			continue;
		} else {
			pamh->current = chain;
			r = (chain->module->func[primitive])(pamh, flags,
			    chain->optc, (const char **)chain->optv);
			pamh->current = NULL;
			openpam_log(PAM_LOG_DEBUG, "%s: %s(): %s",
			    chain->module->path, _pam_sm_func_name[primitive],
			    pam_strerror(pamh, r));
		}

		if (r == PAM_IGNORE)
			continue;
		if (r == PAM_SUCCESS) {
			/*
			 * For pam_setcred(), treat "sufficient" as
			 * "optional".
			 *
			 * Note that Solaris libpam does not terminate
			 * the chain here if a required module has
			 * previously failed.  I'm not sure why.
			 */
			if (chain->flag == PAM_SUFFICIENT &&
			    primitive != PAM_SM_SETCRED)
				break;
			continue;
		}

		_openpam_check_error_code(primitive, r);

		/*
		 * Record the return code from the first module to
		 * fail.  If a required module fails, record the
		 * return code from the first required module to fail.
		 */
		if (err == 0)
			err = r;
		if (chain->flag == PAM_REQUIRED && !fail) {
			openpam_log(PAM_LOG_DEBUG, "required module failed");
			fail = 1;
			err = r;
		}

		/*
		 * If a requisite module fails, terminate the chain
		 * immediately.
		 */
		if (chain->flag == PAM_REQUISITE) {
			openpam_log(PAM_LOG_DEBUG, "requisite module failed");
			fail = 1;
			break;
		}
	}

	if (!fail)
		err = PAM_SUCCESS;
	openpam_log(PAM_LOG_DEBUG, "returning: %s", pam_strerror(pamh, err));
	return (err);
}

#if !defined(OPENPAM_RELAX_CHECKS)
static void
_openpam_check_error_code(int primitive, int r)
{
	/* common error codes */
	if (r == PAM_SUCCESS ||
	    r == PAM_SERVICE_ERR ||
	    r == PAM_BUF_ERR ||
	    r == PAM_CONV_ERR ||
	    r == PAM_PERM_DENIED ||
	    r == PAM_ABORT)
		return;

	/* specific error codes */
	switch (primitive) {
	case PAM_SM_AUTHENTICATE:
		if (r == PAM_AUTH_ERR ||
		    r == PAM_CRED_INSUFFICIENT ||
		    r == PAM_AUTHINFO_UNAVAIL ||
		    r == PAM_USER_UNKNOWN ||
		    r == PAM_MAXTRIES)
			return;
		break;
	case PAM_SM_SETCRED:
		if (r == PAM_CRED_UNAVAIL ||
		    r == PAM_CRED_EXPIRED ||
		    r == PAM_USER_UNKNOWN ||
		    r == PAM_CRED_ERR)
			return;
		break;
	case PAM_SM_ACCT_MGMT:
		if (r == PAM_USER_UNKNOWN ||
		    r == PAM_AUTH_ERR ||
		    r == PAM_NEW_AUTHTOK_REQD ||
		    r == PAM_ACCT_EXPIRED)
			return;
		break;
	case PAM_SM_OPEN_SESSION:
	case PAM_SM_CLOSE_SESSION:
		if (r == PAM_SESSION_ERR)
			return;
		break;
	case PAM_SM_CHAUTHTOK:
		if (r == PAM_PERM_DENIED ||
		    r == PAM_AUTHTOK_ERR ||
		    r == PAM_AUTHTOK_RECOVERY_ERR ||
		    r == PAM_AUTHTOK_LOCK_BUSY ||
		    r == PAM_AUTHTOK_DISABLE_AGING)
			return;
		break;
	}

	openpam_log(PAM_LOG_ERROR, "%s(): unexpected return value %d",
	    _pam_sm_func_name[primitive], r);
}
#endif /* !defined(OPENPAM_RELAX_CHECKS) */

/*
 * NODOC
 *
 * Error codes:
 */