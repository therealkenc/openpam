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

#include "oath_impl.h"

static const char b32enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static const char b32dec[256] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/*
 * Encode data in RFC 4648 base 32 representation.  The target buffer must
 * have room for base32_enclen(len) characters and a terminating NUL.
 */
int
base32_enc(const char *in, size_t ilen, char *out, size_t *olen)
{
	uint64_t bits;

	if (*olen <= base32_enclen(ilen)) {
		*olen = base32_enclen(ilen) + 1;
		errno = ENOSPC;
		return (-1);
	}
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
		out[0] = b32enc[bits >> 35 & 0x1f];
		out[1] = b32enc[bits >> 30 & 0x1f];
		out[2] = b32enc[bits >> 25 & 0x1f];
		out[3] = b32enc[bits >> 20 & 0x1f];
		out[4] = b32enc[bits >> 15 & 0x1f];
		out[5] = b32enc[bits >> 10 & 0x1f];
		out[6] = b32enc[bits >> 5 & 0x1f];
		out[7] = b32enc[bits & 0x1f];
		*olen += 8;
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
		COVERAGE_NO_DEFAULT_CASE
		}
		out[0] = b32enc[bits >> 35 & 0x1f];
		out[1] = b32enc[bits >> 30 & 0x1f];
		out[2] = ilen > 1 ? b32enc[bits >> 25 & 0x1f] : '=';
		out[3] = ilen > 1 ? b32enc[bits >> 20 & 0x1f] : '=';
		out[4] = ilen > 2 ? b32enc[bits >> 15 & 0x1f] : '=';
		out[5] = ilen > 3 ? b32enc[bits >> 10 & 0x1f] : '=';
		out[6] = ilen > 3 ? b32enc[bits >> 5 & 0x1f] : '=';
		out[7] = '=';
		*olen += 8;
		out += 8;
	}
	out[0] = '\0';
	++*olen;
	return (0);
}

/*
 * Decode data in RFC 4648 base 32 representation, stopping at the
 * terminating NUL, the first invalid (non-base32, non-whitespace)
 * character or after len characters, whichever comes first.
 *
 * Padding is handled sloppily: any padding character following the data
 * is silently consumed.  This not only simplifies the code but ensures
 * compatibility with implementations which do not emit or understand
 * padding.
 *
 * The olen argument is used by the caller to pass the size of the buffer
 * and by base32_dec() to return the amount of data successfully decoded.
 * If the buffer is too small, base32_dec() discards the excess data, but
 * returns the total amount.
 */
int
base32_dec(const char *in, size_t ilen, char *out, size_t *olen)
{
	size_t len;
	int bits, shift, padding;

	for (bits = shift = padding = len = 0; ilen && *in; --ilen, ++in) {
		if (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n' ||
		    (padding && *in == '=')) {
			/* consume */
			continue;
		} else if (!padding && b32dec[(int)*in] >= 0) {
			/* shift into accumulator */
			shift += 5;
			bits = bits << 5 | b32dec[(int)*in];
		} else if (!padding && shift > 0 && shift < 5 && *in == '=') {
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
	if (len > *olen) {
		/* overflow */
		*olen = len;
		errno = ENOSPC;
		return (-1);
	}
	*olen = len;
	return (0);
}
