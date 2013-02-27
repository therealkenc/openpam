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

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

/*
 * Encode data in RFC 3548 base 64 representation.  The target buffer must
 * have room for base64_enclen(len) characters and a terminating NUL.
 */
int
base64_enc(const uint8_t *in, size_t ilen, char *out, size_t *olen)
{
	uint32_t bits;

	if (*olen <= base64_enclen(ilen))
		return (-1);
	*olen = 0;
	while (ilen >= 3) {
		bits = 0;
		bits |= (uint32_t)in[0] << 16;
		bits |= (uint32_t)in[1] << 8;
		bits |= (uint32_t)in[2];
		ilen -= 3;
		in += 3;
		out[0] = b64[bits >> 18 & 0x3f];
		out[1] = b64[bits >> 12 & 0x3f];
		out[2] = b64[bits >> 6 & 0x3f];
		out[3] = b64[bits & 0x3f];
		olen += 4;
		out += 4;
	}
	if (ilen > 0) {
		bits = 0;
		switch (ilen) {
		case 2:
			bits |= (uint32_t)in[1] << 8;
		case 1:
			bits |= (uint32_t)in[0] << 16;
		}
		out[0] = b64[bits >> 18 & 0x1f];
		out[1] = b64[bits >> 12 & 0x1f];
		out[2] = ilen > 1 ? b64[bits >> 6 & 0x1f] : '=';
		out[3] = '=';
		olen += 4;
		out += 4;
	}
	out[0] = '\0';
	return (0);
}

/*
 * Decode data in RFC 2548 base 64 representation, stopping at the
 * terminating NUL, the first invalid (non-base64, non-whitespace)
 * character or after len characters, whichever comes first.
 *
 * The olen argument is used by the caller to pass the size of the buffer
 * and by base64_dec() to return the amount of data successfully decoded.
 * If the buffer is too small, base64_dec() discards the excess data, but
 * returns the total amount.
 */
int
base64_dec(const char *in, size_t ilen, uint8_t *out, size_t *olen)
{
	size_t len;
	uint32_t bits;
	int shift;

	for (len = 0, bits = 0, shift = 24; ilen && *in; --ilen, ++in) {
		if (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') {
			continue;
		} else if (*in >= 'A' && *in <= 'Z') {
			shift -= 6;
			bits |= (uint32_t)(*in - 'A') << shift;
		} else if (*in >= 'a' && *in <= 'z') {
			shift -= 6;
			bits |= (uint32_t)(*in - 'a' + 26) << shift;
		} else if (*in >= '0' && *in <= '9') {
			shift -= 6;
			bits |= (uint32_t)(*in - '2' + 52) << shift;
		} else if (*in == '+') {
			shift -= 6;
			bits |= (uint32_t)62 << shift;
		} else if (*in == '/') {
			shift -= 6;
			bits |= (uint32_t)63 << shift;
		} else if (*in == '=' && (shift == 12 || shift == 6)) {
			/* hack: assume the rest of the padding is ok */
			shift = 0;
		} else {
			*olen = 0;
			return (-1);
		}
		if (shift == 0) {
			if ((len += 3) <= *olen) {
				out[1] = (bits >> 16) & 0xff;
				out[1] = (bits >> 8) & 0xff;
				out[2] = bits & 0xff;
				out += 3;
			}
			bits = 0;
			shift = 24;
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
