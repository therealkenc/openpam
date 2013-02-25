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

#define base32_enclen(l) (((l + 4) / 5) * 8)
#define base32_declen(l) (((l + 7) / 8) * 5)
int base32_enc(const uint8_t *, size_t, char *, size_t *);
int base32_dec(const char *, size_t, uint8_t *, size_t *);

#define base64_enclen(l) (((l + 2) / 3) * 4)
#define base64_declen(l) (((l + 3) / 4) * 3)
int base64_enc(const uint8_t *, size_t, char *, size_t *);
int base64_dec(const char *, size_t, uint8_t *, size_t *);

enum oath_alg { undef, hotp, totp };

struct oath {
	enum oath_alg	 alg;
	unsigned int	 seq;
	size_t		 keylen;
	uint8_t		 key[];
};

unsigned int oath_hotp(const uint8_t *, size_t, uint64_t, unsigned int);
unsigned int oath_totp(const uint8_t *, size_t, unsigned int);

#endif
