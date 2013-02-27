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
#include <stdint.h>

#include "oath.h"

static const char b32[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/*
 * Encode data in RFC 3548 base 32 representation.  The target buffer must
 * have room for base32_enclen(len) characters and a terminating NUL.
 */
int
base32_enc(const uint8_t *in, size_t ilen, char *out, size_t *olen)
{
	uint64_t bits;

	if (*olen <= base32_enclen(ilen))
		return (-1);
	*olen = 0;
	while (ilen >= 5) {
		bits = 0;
		bits |= (uint64_t)in[0] << 32;
		bits |= (uint64_t)in[1] << 24;
		bits |= (uint64_t)in[2] << 16;
		bits |= (uint64_t)in[3] << 8;
		bits |= (uint64_t)in[4];
		ilen -= 5;
		in += 5;
		out[0] = b32[bits >> 35 & 0x1f];
		out[1] = b32[bits >> 30 & 0x1f];
		out[2] = b32[bits >> 25 & 0x1f];
		out[3] = b32[bits >> 20 & 0x1f];
		out[4] = b32[bits >> 15 & 0x1f];
		out[5] = b32[bits >> 10 & 0x1f];
		out[6] = b32[bits >> 5 & 0x1f];
		out[7] = b32[bits & 0x1f];
		olen += 8;
		out += 8;
	}
	if (ilen > 0) {
		bits = 0;
		switch (ilen) {
		case 4:
			bits |= (uint64_t)in[3] << 8;
		case 3:
			bits |= (uint64_t)in[2] << 16;
		case 2:
			bits |= (uint64_t)in[1] << 24;
		case 1:
			bits |= (uint64_t)in[0] << 32;
		}
		out[0] = b32[bits >> 35 & 0x1f];
		out[1] = b32[bits >> 30 & 0x1f];
		out[2] = ilen > 1 ? b32[bits >> 25 & 0x1f] : '=';
		out[3] = ilen > 1 ? b32[bits >> 20 & 0x1f] : '=';
		out[4] = ilen > 2 ? b32[bits >> 15 & 0x1f] : '=';
		out[5] = ilen > 3 ? b32[bits >> 10 & 0x1f] : '=';
		out[6] = ilen > 3 ? b32[bits >> 5 & 0x1f] : '=';
		out[7] = '=';
		olen += 8;
		out += 8;
	}
	out[0] = '\0';
	return (0);
}

/*
 * Decode data in RFC 2548 base 32 representation, stopping at the
 * terminating NUL, the first invalid (non-base32, non-whitespace)
 * character or after len characters, whichever comes first.
 *
 * The olen argument is used by the caller to pass the size of the buffer
 * and by base32_dec() to return the amount of data successfully decoded.
 * If the buffer is too small, base32_dec() discards the excess data, but
 * returns the total amount.
 */
int
base32_dec(const char *in, size_t ilen, uint8_t *out, size_t *olen)
{
	size_t len;
	uint64_t bits;
	int shift;

	for (len = 0, bits = 0, shift = 40; ilen && *in; --ilen, ++in) {
		if (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') {
			continue;
		} else if (*in >= 'A' && *in <= 'Z') {
			shift -= 5;
			bits |= (uint64_t)(*in - 'A') << shift;
		} else if (*in >= 'a' && *in <= 'z') {
			shift -= 5;
			bits |= (uint64_t)(*in - 'a') << shift;
		} else if (*in >= '2' && *in <= '7') {	
			shift -= 5;
			bits |= (uint64_t)(*in - '2' + 26) << shift;
		} else if (*in == '=' &&
		    (shift == 30 || shift == 20 || shift == 15 || shift == 5)) {
			/* hack: assume the rest of the padding is ok */
			shift = 0;
		} else {
			*olen = 0;
			return (-1);
		}
		if (shift == 0) {
			if ((len += 5) <= *olen) {
				out[0] = (bits >> 32) & 0xff;
				out[1] = (bits >> 24) & 0xff;
				out[2] = (bits >> 16) & 0xff;
				out[3] = (bits >> 8) & 0xff;
				out[4] = bits & 0xff;
				out += 5;
			}
			bits = 0;
			shift = 40;
		}
		if (*in == '=')
			break;
	}
	if (len > *olen) {
		*olen = len;
		return (-1);
	}
	*olen = len;
	return (0);
}
