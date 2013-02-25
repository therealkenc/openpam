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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdint.h>

#include "oath.h"

#define StToNum(St) (St)

static uint32_t
DT(const uint8_t *String)
{
	uint8_t OffsetBits;
	int Offset;
	uint32_t P;

	OffsetBits = String[19] & 0x0f;
	Offset = StToNum(OffsetBits);
	P = (uint32_t)String[Offset + 0] << 24 |
	    (uint32_t)String[Offset + 1] << 16 |
	    (uint32_t)String[Offset + 2] << 8 |
	    (uint32_t)String[Offset + 3];
	return (P & 0x7fffffffUL);
}

unsigned int
oath_hotp(const uint8_t *K, size_t Klen, uint64_t seq, unsigned int Digit)
{
	HMAC_CTX ctx;
	uint8_t C[8];
	uint8_t HS[20];
	unsigned int HSlen;
	uint32_t Sbits, Snum;
	unsigned int mod, D;

	for (int i = 7; i >= 0; --i) {
		C[i] = seq & 0xff;
		seq >>= 8;
	}

	/* HS = HMAC-SHA-1(K,C) */
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, K, Klen, EVP_sha1(), NULL);
	HMAC_Update(&ctx, (const uint8_t *)&C, sizeof C);
	HMAC_Final(&ctx, HS, &HSlen);
	HMAC_CTX_cleanup(&ctx);

	Sbits = DT(HS);
	Snum = StToNum(Sbits);
	for (mod = 1; Digit > 0; --Digit)
		mod *= 10;
	D = Snum % mod;
	return (D);
}
