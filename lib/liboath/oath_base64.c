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

#include <errno.h>
#include <stdint.h>

#include <security/oath.h>

static const char b64enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const uint8_t b64dec[256] = {
	['A'] =  0, ['B'] =  1, ['C'] =  2, ['D'] =  3,
	['E'] =  4, ['F'] =  5, ['G'] =  6, ['H'] =  7,
	['I'] =  8, ['J'] =  9, ['K'] = 10, ['L'] = 11,
	['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
	['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
	['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
	['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27,
	['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
	['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
	['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39,
	['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
	['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
	['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51,
	['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
	['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
	['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
};

/*
 * Encode data in RFC 4648 base 64 representation.  The target buffer must
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
		out[0] = b64enc[bits >> 18 & 0x3f];
		out[1] = b64enc[bits >> 12 & 0x3f];
		out[2] = b64enc[bits >> 6 & 0x3f];
		out[3] = b64enc[bits & 0x3f];
		*olen += 4;
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
		out[0] = b64enc[bits >> 18 & 0x3f];
		out[1] = b64enc[bits >> 12 & 0x3f];
		out[2] = ilen > 1 ? b64enc[bits >> 6 & 0x3f] : '=';
		out[3] = '=';
		*olen += 4;
		out += 4;
	}
	out[0] = '\0';
	++*olen;
	return (0);
}

/*
 * Decode data in RFC 4648 base 64 representation, stopping at the
 * terminating NUL, the first invalid (non-base64, non-whitespace)
 * character or after len characters, whichever comes first.
 *
 * Padding is handled sloppily: any padding character following the data
 * is silently consumed.  This not only simplifies the code but ensures
 * compatibility with implementations which do not emit or understand
 * padding.
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
	int bits, shift, padding;

	for (bits = shift = padding = len = 0; ilen && *in; --ilen, ++in) {
		if (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n' ||
		    (padding && *in == '=')) {
			/* consume */
			continue;
		} else if (!padding && b64dec[(int)*in]) {
			/* shift into accumulator */
			shift += 6;
			bits = bits << 6 | b64dec[(int)*in];
		} else if (!padding && shift && *in == '=') {
			/* final byte */
			shift = 0;
			padding = 1;
		} else {
			/* error */
			*olen = 0;
			errno = EINVAL;
			return (-1);
		}
		if (shift >= 8) {
			/* output accumulated byte */
			shift -= 8;
			if (len++ < *olen)
				*out++ = (bits >> shift) & 0xff;
		}
	}
	/* report decoded length */
	*olen = len;
	if (len > *olen) {
		/* overflow */
		errno = ENOSPC;
		return (-1);
	}
	return (0);
}
