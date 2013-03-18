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

#ifndef OATH_CONSTANTS_H_INCLUDED
#define OATH_CONSTANTS_H_INCLUDED

/*
 * OATH modes
 */
enum oath_mode {
	om_undef,		/* not set / default */
	om_hotp,		/* RFC 4226 HOTP */
	om_totp,		/* RFC 6238 TOTP */
	om_max
};

/*
 * Hash functions
 */
enum oath_hash {
	oh_undef,		/* not set / default */
	oh_md5,			/* RFC 1321 MD5 */
	oh_sha1,		/* FIPS 180 SHA-1 */
	oh_sha256,		/* FIPS 180 SHA-256 */
	oh_sha512,		/* FIPS 180 SHA-512 */
	oh_max
};

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

/*
 * Maximum label length in characters, including terminating NUL.
 */
#define OATH_MAX_LABELLEN	64

#endif
