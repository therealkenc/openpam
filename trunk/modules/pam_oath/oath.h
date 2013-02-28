/*-
 * Copyright (c) 2012-2013 Universitetet i Oslo
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

#ifndef OATH_H_INCLUDED
#define OATH_H_INCLUDED

/*
 * Default time step for TOTP: 30 seconds.
 */
#define OATH_DEF_TIMESTEP	30

/*
 * Maximum time step for TOTP: 10 minutes, which RFC 6238 cites as an
 * example of an unreasonably large time step.
 */
#define OATH_MAX_TIMESTEP	600

/*
 * Maximum key length in bytes.  HMAC has a 64-byte block size; if the key
 * K is longer than that, HMAC derives a new key K' = H(K).
 */
#define OATH_MAX_KEYLEN		64

/* estimate of output length for base32 encoding / decoding */
#define base32_enclen(l) (size_t)(((l + 4) / 5) * 8)
#define base32_declen(l) (size_t)(((l + 7) / 8) * 5)

/* base32 encoding / decoding */
int base32_enc(const uint8_t *, size_t, char *, size_t *);
int base32_dec(const char *, size_t, uint8_t *, size_t *);

/* estimate of output length for base64 encoding / decoding */
#define base64_enclen(l) (size_t)(((l + 2) / 3) * 4)
#define base64_declen(l) (size_t)(((l + 3) / 4) * 3)

/* base64 encoding / decoding */
int base64_enc(const uint8_t *, size_t, char *, size_t *);
int base64_dec(const char *, size_t, uint8_t *, size_t *);

/* mode: hotp (event mode) or totp (time-synch mode) */
enum oath_mode { om_undef, om_hotp, om_totp };

/* hash function */
enum oath_hash { oh_undef, oh_sha1, oh_sha256, oh_sha512, oh_md5 };

/* key structure */
struct oath_key {
	/* mode and parameters */
	enum oath_mode	 mode;
	unsigned int	 digits;
	uint64_t	 counter;
	unsigned int	 timestep; /* in seconds */

	/* hash algorithm */
	enum oath_hash	 hash;

	/* label */
	size_t		 labellen; /* bytes incl. NUL */
	char		*label;

	/* key */
	size_t		 keylen; /* bytes */
	uint8_t		*key;

	/* buffer for label + NUL + key */
	size_t		 datalen; /* bytes */
	uint8_t		 data[];
};

unsigned int oath_hotp(const uint8_t *, size_t, uint64_t, unsigned int);
unsigned int oath_totp(const uint8_t *, size_t, unsigned int);

#endif
