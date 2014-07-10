/*-
 * Copyright (c) 2013 The University of Oslo
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

#include <inttypes.h>
#include <string.h>

#include <security/oath.h>

/*
 * OATH
 *
 * Creates a dummy OATH key structure
 */

struct oath_key *
oath_key_dummy(enum oath_mode mode, enum oath_hash hash, unsigned int digits)
{
	struct oath_key *key;

	if ((key = oath_key_alloc()) == NULL)
		return (NULL);
	key->dummy = 1;
	key->mode = mode;
	key->digits = digits;
	key->counter = 0;
	key->timestep = 30;
	key->hash = hash;
	memcpy(key->label, OATH_DUMMY_LABEL, sizeof OATH_DUMMY_LABEL);
	key->labellen = sizeof OATH_DUMMY_LABEL - 1;
	key->keylen = sizeof key->key;
	return (key);
}

/**
 * The =oath_key_dummy function allocates and initializes a dummy OATH key
 * structure.
 * Authentication attempts using a dummy key will always fail.
 *
 * Keys allocated with =oath_key_dummy must be freed using =oath_key_free.
 *
 * >oath_key_alloc
 * >oath_key_free
 *
 * AUTHOR UIO
 */
