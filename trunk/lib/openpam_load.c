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

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include "openpam_impl.h"

const char *_pam_sm_func_name[PAM_NUM_PRIMITIVES] = {
	"pam_sm_acct_mgmt",
	"pam_sm_authenticate",
	"pam_sm_chauthtok",
	"pam_sm_close_session",
	"pam_sm_open_session",
	"pam_sm_setcred"
};

int
openpam_add_module(pam_handle_t *pamh,
	int chain,
	int flag,
	const char *modpath,
	const char *options /* XXX */ __unused)
{
	pam_chain_t *module, *iterator;
	int i;

	/* fill in configuration data */
	if ((module = malloc(sizeof(*module))) == NULL) {
		openpam_log(PAM_LOG_ERROR, "malloc(): %m");
		return (PAM_BUF_ERR);
	}
	if ((module->modpath = strdup(modpath)) == NULL) {
		openpam_log(PAM_LOG_ERROR, "strdup(): %m");
		free(module);
		return (PAM_BUF_ERR);
	}
	module->flag = flag;
	module->next = NULL;

	/* load module and resolve symbols */
	/*
	 * Each module is dlopen()'d once for evey time it occurs in
	 * any chain.  While the linker is smart enough to not load
	 * the same module more than once, it does waste space in the
	 * form of linker handles and pam_func structs.
	 *
	 * TODO: implement a central module cache and replace the
	 * array of pam_func structs in struct pam_chain with pointers
	 * to the appropriate entry in the module cache.
	 */
	if ((module->dlh = dlopen(modpath, RTLD_NOW)) == NULL) {
		openpam_log(PAM_LOG_ERROR, "dlopen(): %s", dlerror());
		free(module->modpath);
		free(module);
		return (PAM_OPEN_ERR);
	}
	for (i = 0; i < PAM_NUM_PRIMITIVES; ++i)
		module->primitive[i] =
		    dlsym(module->dlh, _pam_sm_func_name[i]);

	if ((iterator = pamh->chains[chain]) != NULL) {
		while (iterator->next != NULL)
			iterator = iterator->next;
		iterator->next = module;
	} else {
		pamh->chains[chain] = module;
	}
	return (PAM_SUCCESS);
}

/*
 * Clear the chains and release the modules
 */

void
openpam_clear_chains(pam_handle_t *pamh)
{
	pam_chain_t *module;
	int i;

	for (i = 0; i < PAM_NUM_CHAINS; ++i) {
		while (pamh->chains[i] != NULL) {
			module = pamh->chains[i];
			pamh->chains[i] = module->next;
			/* XXX free options */
			dlclose(module->dlh);
			free(module->modpath);
			free(module);
		}
	}
}
