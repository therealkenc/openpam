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

#include "openpam.h"

#if !defined(OPENPAM_RELAX_CHECKS)
static void _openpam_check_error_code(int, int);
#else
#define _openpam_check_error_code(a, b)
#endif /* !defined(OPENPAM_RELAX_CHECKS) */

/*
 * Execute a module chain
 */

int
openpam_dispatch(pam_handle_t *pamh,
	int primitive,
	int flags)
{
	pam_chain_t *module;
	int err, fail, r;
	
	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	switch (primitive) {
	case PAM_AUTHENTICATE:
	case PAM_SETCRED:
		module = pamh->chains[PAM_AUTH];
		break;
	case PAM_ACCT_MGMT:
		module = pamh->chains[PAM_ACCOUNT];
		break;
	case PAM_OPEN_SESSION:
	case PAM_CLOSE_SESSION:
		module = pamh->chains[PAM_SESSION];
		break;
	case PAM_CHAUTHTOK:
		module = pamh->chains[PAM_PASSWORD];
		break;
	default:
		return (PAM_SYSTEM_ERR);
	}

	for (err = fail = 0; module != NULL; module = module->next) {
		if (module->primitive[primitive] == NULL) {
			openpam_log(PAM_LOG_ERROR, "%s: no %s()",
			    module->modpath, _pam_sm_func_name[primitive]);
			return (PAM_SYMBOL_ERR);
		}
		r = (module->primitive[primitive])(pamh, flags);
		openpam_log(PAM_LOG_DEBUG, "%s: %s(): %s",
		    module->modpath, _pam_sm_func_name[primitive],
		    pam_strerror(pamh, r));

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
			if (module->flag == PAM_SUFFICIENT &&
			    primitive != PAM_SETCRED)
				break;
		}

		_openpam_check_error_code(primitive, r);

		/*
		 * Record the return code from the first module to
		 * fail.  If a required module fails, record the
		 * return code from the first required module to fail.
		 */
		if (err == 0)
			err = r;
		if (module->flag == PAM_REQUIRED && !fail) {
			fail = 1;
			err = r;
		}

		/*
		 * If a requisite module fails, terminate the chain
		 * immediately.
		 */
		if (module->flag == PAM_REQUISITE) {
			fail = 1;
			break;
		}
	}

	if (fail)
		return (err);
	return (PAM_SUCCESS);
}

#if !defined(OPENPAM_RELAX_CHECKS)
static void
_openpam_check_error_code(int primitive, int r)
{
	/* common error codes */
	if (r == PAM_SERVICE_ERR ||
	    r == PAM_BUF_ERR ||
	    r == PAM_BUF_ERR ||
	    r == PAM_CONV_ERR ||
	    r == PAM_PERM_DENIED)
		return;
	
	/* specific error codes */
	switch (primitive) {
	case PAM_AUTHENTICATE:
		if (r == PAM_AUTH_ERR ||
		    r == PAM_CRED_INSUFFICIENT ||
		    r == PAM_AUTHINFO_UNAVAIL ||
		    r == PAM_USER_UNKNOWN ||
		    r == PAM_MAXTRIES)
			return;
		break;
	case PAM_SETCRED:
		if (r == PAM_CRED_UNAVAIL ||
		    r == PAM_CRED_EXPIRED ||
		    r == PAM_USER_UNKNOWN ||
		    r == PAM_CRED_ERR)
			return;
		break;
	case PAM_ACCT_MGMT:
		if (r == PAM_USER_UNKNOWN ||
		    r == PAM_AUTH_ERR ||
		    r == PAM_NEW_AUTHTOK_REQD ||
		    r == PAM_ACCT_EXPIRED)
			return;
		break;
	case PAM_OPEN_SESSION:
	case PAM_CLOSE_SESSION:
		if (r == PAM_SESSION_ERR)
			return;
		break;
	case PAM_CHAUTHTOK:
		if (r == PAM_PERM_DENIED ||
		    r == PAM_AUTHTOK_ERR ||
		    r == PAM_AUTHTOK_RECOVERY_ERR ||
		    r == PAM_AUTHTOK_LOCK_BUSY ||
		    r == PAM_AUTHTOK_DISABLE_AGING)
			return;
		break;
	}
	
	openpam_log(PAM_LOG_ERROR, "%s(): invalid return value %d",
	    _pam_sm_func_name[primitive], r);
}
#endif /* !defined(OPENPAM_RELAX_CHECKS) */
