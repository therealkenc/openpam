/*-
 * Copyright (c) 2013-2014 The University of Oslo
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

#include <stdint.h>
#include <string.h>

#include <openssl/rand.h>

#include <security/oath.h>

/*
 * OATH
 *
 * Creates an OATH key with the specified parameters
 */

struct oath_key *
oath_key_create(const char *label,
    enum oath_mode mode, enum oath_hash hash,
    const char *keydata, size_t keylen)
{
	char keybuf[OATH_MAX_KEYLEN];
	struct oath_key *key;
	int labellen;

	/* check label length */
	if (label == NULL ||
	    (labellen = strlen(label)) >= OATH_MAX_LABELLEN)
		return (NULL);

	/* check key length */
	if (keylen > OATH_MAX_KEYLEN ||
	    (keydata != NULL && keylen == 0))
		return (NULL);
	if (keylen == 0)
		keylen = 20;

	/* check mode */
	switch (mode) {
	case om_hotp:
	case om_totp:
		break;
	default:
		return (NULL);
	}

	/* check hash */
	switch (hash) {
	case oh_undef:
		hash = oh_sha1;
		break;
	case oh_md5:
	case oh_sha1:
	case oh_sha256:
	case oh_sha512:
		break;
	default:
		return (NULL);
	}

	/* generate key data if necessary */
	if (keydata == NULL) {
		if (RAND_bytes((void *)keybuf, keylen) != 1)
			return (NULL);
		keydata = keybuf;
	}

	/* allocate */
	if ((key = oath_key_alloc()) == NULL)
		return (NULL);

	/* label */
	memcpy(key->label, label, labellen);
	key->label[labellen] = 0;
	key->labellen = labellen;

	/* mode and hash */
	key->mode = mode;
	key->hash = hash;

	/* default parameters */
	key->digits = 6;
	if (key->mode == om_totp)
		key->timestep = 30;

	/* key */
	memcpy(key->key, keydata, keylen);
	key->keylen = keylen;

	return (key);
}

/**
 * The =oath_key_create function allocates and initializes an OATH key
 * structure with the specified parameters.
 *
 * The =label parameter must point to a string describing the key.
 *
 * The =mode parameter indicates the OTP algorithm to use:
 *
 *  ;om_hotp:
 *	RFC 4226 HOTP
 *  ;om_totp:
 *	RFC 6238 TOTP
 *
 * The =hash parameter indicates which hash algorithm to use:
 *
 *  ;oh_md5:
 *	RFC 1321 MD5
 *  ;oh_sha1:
 *	RFC 3174 SHA-1
 *  ;oh_sha256:
 *	RFC 6234 SHA-256
 *  ;oh_sha512:
 *	RFC 6234 SHA-512
 *
 * If =hash is ;oh_undef, the default algorithm (SHA-1) is used.
 *
 * The =keydata parameter should point to a buffer containing the raw key
 * to use.
 * If =keydata is NULL, a key will be randomly generated.
 * Note that the strength of the generated key is dependent on the
 * strength of the operating system's pseudo-random number generator.
 *
 * The =keylen parameter specifies the length of the provided (or
 * generated) key in bytes.
 * Note that some OATH HOTP / TOTP implementations do not support key
 * lengths that are not a multiple of 20 bits (5 bytes).
 * If =keydata is NULL and =keylen is 0, a hardcoded default of 160 bits
 * (20 bytes) is used.
 *
 * The following key parameters are set to hardcoded default values and
 * can be changed after key creation:
 *
 *  - For HOTP keys, the initial counter value is set to 0.
 *  - For TOTP keys, the timestep is set to 30 seconds.
 *  - For both HOTP and TOTP keys, the number of digits is set to 6.
 *
 * Keys created with =oath_key_create must be freed using =oath_key_free.
 *
 * >oath_key_alloc
 * >oath_key_free
 *
 * AUTHOR UIO
 */
