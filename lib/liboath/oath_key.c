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

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_asprintf.h"

#include <security/oath.h>

char *
oath_key_to_uri(const struct oath_key *key)
{
	const char *hash;
	char *tmp, *uri;
	size_t kslen, urilen;

	switch (key->hash) {
	case oh_sha1:
		hash = "SHA1";
		break;
	case oh_sha256:
		hash = "SHA256";
		break;
	case oh_sha512:
		hash = "SHA512";
		break;
	case oh_md5:
		hash = "MD5";
		break;
	default:
		return (NULL);
	}

	/* XXX the label and secret should be URI-encoded */
	if (key->mode == om_hotp) {
		urilen = asprintf(&uri, "otpauth://%s/%s?"
		    "algorithm=%s&digits=%d&counter=%ju&secret=",
		    "hotp", key->label, hash, key->digits,
		    (uintmax_t)key->counter);
	} else if (key->mode == om_totp) {
		urilen = asprintf(&uri, "otpauth://%s/%s?"
		    "algorithm=%s&digits=%d&period=%u&lastused=%ju&secret=",
		    "totp", key->label, hash, key->digits, key->timestep,
		    (uintmax_t)key->lastused);
	} else {
		/* unreachable */
		return (NULL);
	}

	/* compute length of base32-encoded key and append it */
	kslen = base32_enclen(key->keylen) + 1;
	if ((tmp = realloc(uri, urilen + kslen)) == NULL) {
		free(uri);
		return (NULL);
	}
	uri = tmp;
	if (base32_enc((const char *)key->key, key->keylen, uri + urilen, &kslen) != 0) {
		free(uri);
		return (NULL);
	}

	return (uri);
}
