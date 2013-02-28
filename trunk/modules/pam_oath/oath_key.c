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

#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_asprintf.h"
#include "openpam_strlcmp.h"

#include "oath.h"

/*
 * Allocate a struct oath_key with sufficient additional space for the
 * label and key.
 */
struct oath_key *
oath_key_alloc(size_t extra)
{
	struct oath_key *key;

	if ((key = calloc(1, sizeof *key + extra)) == NULL) {
		openpam_log(PAM_LOG_ERROR, "malloc(): %s", strerror(errno));
		return (NULL);
	}
	key->datalen = extra;
	/* XXX should try to wire */
	return (key);
}

/*
 * Wipe and free a struct oath_key
 */
void
oath_key_free(struct oath_key *key)
{

	if (key != NULL) {
		memset(key, 0, sizeof *key + key->datalen);
		free(key);
	}
}

/*
 * Allocate a struct oath_key and populate it from a Google Authenticator
 * otpauth URI
 */
struct oath_key *
oath_key_from_uri(const char *uri)
{
	struct oath_key *key;
	const char *p, *q, *r;
	uintmax_t n;
	char *e;

	/*
	 * The URI string contains the label, the base32-encoded key and
	 * some fluff, so the combined length of the label and key can
	 * never exceed the length of the URI string.
	 */
	if ((key = oath_key_alloc(strlen(uri))) == NULL)
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
		openpam_log(PAM_LOG_DEBUG, "OATH mode: HOTP");
		key->mode = om_hotp;
	} else if (strlcmp("totp", p, q - p) == 0) {
		openpam_log(PAM_LOG_DEBUG, "OATH mode: TOTP");
		key->mode = om_totp;
	} else {
		goto invalid;
	}
	p = q + 1;

	/* extract label */
	if ((q = strchr(p, '?')) == NULL)
		goto invalid;
	key->label = (char *)key->data;
	key->labellen = (q - p) + 1;
	memcpy(key->label, p, q - p);
	key->label[q - p] = '\0';
	p = q + 1;

	/* extract parameters */
	key->counter = UINTMAX_MAX;
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
			/* base32-encoded key - multiple of 40 bits */
			if ((r - q) % 8 != 0 ||
			    base32_declen(r - q) > OATH_MAX_KEYLEN)
				goto invalid;
			key->key = key->data + key->labellen;
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
			if (key->counter != UINTMAX_MAX)
				/* dupe */
				goto invalid;
			n = strtoumax(q, &e, 10);
			if (e != r || n >= UINTMAX_MAX)
				goto invalid;
			key->counter = (uint64_t)n;
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
		if (key->timestep != 0)
			goto invalid;
		if (key->counter == UINTMAX_MAX)
			key->counter = 0;
	} else if (key->mode == om_totp) {
		if (key->counter != UINTMAX_MAX)
			goto invalid;
		if (key->timestep == 0)
			key->timestep = OATH_DEF_TIMESTEP;
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

invalid:
	openpam_log(PAM_LOG_NOTICE, "invalid OATH URI: %s", uri);
	oath_key_free(key);
	return (NULL);
}

struct oath_key *
oath_key_from_file(const char *filename)
{
	struct oath_key *key;
	FILE *f;
	char *line;
	size_t len;

	if ((f = fopen(filename, "r")) == NULL)
		return (NULL);
	/* get first non-empty non-comment line */
	line = openpam_readline(f, NULL, &len);
	if (strlcmp("otpauth://", line, len) == 0) {
		key = oath_key_from_uri(line);
	} else {
		openpam_log(PAM_LOG_ERROR,
		    "unrecognized key file format: %s", filename);
		key = NULL;
	}
	fclose(f);
	return (key);
}

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

	if (key->mode == om_hotp) {
		urilen = asprintf(&uri, "otpauth://"
		    "%s/%s?algorithm=%s&digits=%d&counter=%ju&secret=",
		    "hotp", key->label, hash, key->digits,
		    (uintmax_t)key->counter);
	} else if (key->mode == om_totp) {
		urilen = asprintf(&uri, "otpauth://"
		    "%s/%s?algorithm=%s&digits=%d&period=%u&secret=",
		    "totp", key->label, hash, key->digits, key->timestep);
	} else {
		/* unreachable */
		return (NULL);
	}

	/* compute length of base32-encoded key and append it */
	kslen = base32_enclen(key->keylen);
	if ((tmp = realloc(uri, urilen + kslen + 1)) == NULL) {
		free(uri);
		return (NULL);
	}
	uri = tmp;
	if (base32_enc(key->key, key->keylen, uri + urilen, &kslen) != 0) {
		free(uri);
		return (NULL);
	}

	return (uri);
}
