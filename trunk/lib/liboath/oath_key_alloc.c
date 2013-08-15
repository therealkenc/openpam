/*-
 * Copyright (c) 2013 Universitetet i Oslo
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

#include <sys/mman.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/openpam.h>
#include <security/oath.h>

/*
 * OATH
 *
 * Allocates an OATH key structure
 */

struct oath_key *
oath_key_alloc(void)
{
	struct oath_key *key;
	int prot, flags;

	prot = PROT_READ|PROT_WRITE;
	flags = MAP_ANON;
#ifdef MAP_NOCORE
	flags |= MAP_NOCORE;
#endif
	if ((key = mmap(NULL, sizeof *key, prot, flags, -1, 0)) != NULL) {
		memset(key, 0, sizeof *key);
		key->mapped = 1;
		if (mlock(key, sizeof *key) == 0)
			key->locked = 1;
	} else {
		openpam_log(PAM_LOG_ERROR, "mmap(): %m");
		if ((key = calloc(sizeof *key, 1)) == NULL)
			openpam_log(PAM_LOG_ERROR, "malloc(): %m");
	}
	return (key);
}

/**
 * The =oath_key_alloc function allocates and initializes an OATH key
 * structure.
 *
 * Keys allocated with =oath_key_alloc must be freed using =oath_key_free.
 *
 * >oath_key_free
 *
 * AUTHOR UIO
 */
