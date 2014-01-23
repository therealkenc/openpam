/*-
 * Copyright (c) 2013-2014 Universitetet i Oslo
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
#include <string.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_strlcmp.h"

#include <security/oath.h>

/*
 * OATH
 *
 * Creates an OATH key from a Google otpauth URI
 */

struct oath_key *
oath_key_from_uri(const char *uri)
{
	struct oath_key *key;
	const char *p, *q, *r;
	uintmax_t n;
	char *e;

	if ((key = oath_key_alloc()) == NULL)
		return (NULL);

	/* check method */
	p = uri;
	if (strlcmp("otpauth://", p, 10) != 0)
		goto invalid;
	p += 10;

	/* check mode (hotp = event, totp = time-sync) */
	if ((q = strchr(p, '/')) == NULL)
		goto invalid;
	if (strlcmp("hotp", p, q - p) == 0) {
		key->mode = om_hotp;
	} else if (strlcmp("totp", p, q - p) == 0) {
		key->mode = om_totp;
	} else {
		goto invalid;
	}
	p = q + 1;

	/* extract label */
	if ((q = strchr(p, '?')) == NULL)
		goto invalid;
	key->labellen = oath_uri_decode(p, q - p, key->label,
	    sizeof key->label);
	if (key->labellen > sizeof key->label)
		goto invalid;
	p = q + 1;

	/* extract parameters */
	key->counter = UINT64_MAX;
	key->lastused = UINT64_MAX;
	while (*p != '\0') {
		if ((q = strchr(p, '=')) == NULL)
			goto invalid;
		q = q + 1;
		if ((r = strchr(p, '&')) == NULL)
			r = strchr(p, '\0');
		if (r < q)
			/* & before = */
			goto invalid;
		/* p points to key, q points to value, r points to & or NUL */
		if (strlcmp("secret=", p, q - p) == 0) {
			if (key->keylen != 0)
				/* dupe */
				goto invalid;
			key->keylen = sizeof key->key;
			if (base32_dec(q, r - q, key->key, &key->keylen) != 0)
				goto invalid;
			if (base32_enclen(key->keylen) != (size_t)(r - q))
				goto invalid;
		} else if (strlcmp("algorithm=", p, q - p) == 0) {
			if (key->hash != oh_undef)
				/* dupe */
				goto invalid;
			if (strlcmp("SHA1", q, r - q) == 0)
				key->hash = oh_sha1;
			else if (strlcmp("SHA256", q, r - q) == 0)
				key->hash = oh_sha256;
			else if (strlcmp("SHA512", q, r - q) == 0)
				key->hash = oh_sha512;
			else if (strlcmp("MD5", q, r - q) == 0)
				key->hash = oh_md5;
			else
				goto invalid;
		} else if (strlcmp("digits=", p, q - p) == 0) {
			if (key->digits != 0)
				/* dupe */
				goto invalid;
			/* only 6 or 8 */
			if (r - q != 1 || (*q != '6' && *q != '8'))
				goto invalid;
			key->digits = *q - '0';
		} else if (strlcmp("counter=", p, q - p) == 0) {
			if (key->counter != UINT64_MAX)
				/* dupe */
				goto invalid;
			n = strtoumax(q, &e, 10);
			if (e != r || n >= UINT64_MAX)
				goto invalid;
			key->counter = (uint64_t)n;
		} else if (strlcmp("lastused=", p, q - p) == 0) {
			if (key->lastused != UINT64_MAX)
				/* dupe */
				goto invalid;
			n = strtoumax(q, &e, 10);
			if (e != r || n >= UINT64_MAX)
				goto invalid;
			key->lastused = (uint64_t)n;
		} else if (strlcmp("period=", p, q - p) == 0) {
			if (key->timestep != 0)
				/* dupe */
				goto invalid;
			n = strtoumax(q, &e, 10);
			if (e != r || n > OATH_MAX_TIMESTEP)
				goto invalid;
			key->timestep = n;
		} else {
			goto invalid;
		}
		/* final parameter? */
		if (*r == '\0')
			break;
		/* skip & and continue */
		p = r + 1;
	}

	/* sanity checks and default values */
	if (key->mode == om_hotp) {
		if (key->counter == UINT64_MAX)
			key->counter = 0;
		if (key->timestep != 0)
			goto invalid;
		if (key->lastused != UINT64_MAX)
			goto invalid;
	} else if (key->mode == om_totp) {
		if (key->counter != UINT64_MAX)
			goto invalid;
		if (key->timestep == 0)
			key->timestep = OATH_DEF_TIMESTEP;
		if (key->lastused == UINT64_MAX)
			key->lastused = 0;
	} else {
		/* unreachable */
		oath_key_free(key);
		return (NULL);
	}
	if (key->hash == oh_undef)
		key->hash = oh_sha1;
	if (key->digits == 0)
		key->digits = 6;
	if (key->keylen == 0)
		goto invalid;
	return (key);

invalid:
	openpam_log(PAM_LOG_NOTICE, "invalid OATH URI: %s", uri);
	oath_key_free(key);
	return (NULL);
}

/**
 * The =oath_key_from_uri parses a Google otpauth URI into a key
 * structure.
 *
 * The =uri parameter points to a NUL-terminated string containing the
 * URI.
 *
 * Keys created with =oath_key_from_uri must be freed using
 * =oath_key_free.
 *
 * >oath_key_alloc
 * >oath_key_free
 * >oath_key_to_uri
 *
 * REFERENCES
 *
 * https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
 *
 * AUTHOR UIO
 */
