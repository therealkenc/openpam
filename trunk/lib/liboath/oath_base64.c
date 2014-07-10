/*-
 * Copyright (c) 2013-2014 The University of Oslo
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

static const char b64enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const char b64dec[256] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, 
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 
	0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 
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
 * Encode data in RFC 4648 base 64 representation.  The target buffer must
 * have room for base64_enclen(len) characters and a terminating NUL.
 */
int
base64_enc(const char *cin, size_t ilen, char *out, size_t *olen)
{
	const uint8_t *in = (uint8_t *)cin;
	uint32_t bits;

	if (*olen <= base64_enclen(ilen)) {
		*olen = base64_enclen(ilen) + 1;
		errno = ENOSPC;
		return (-1);
	}
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
		COVERAGE_NO_DEFAULT_CASE
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
base64_dec(const char *cin, size_t ilen, char *out, size_t *olen)
{
	const uint8_t *in = (uint8_t *)cin;
	size_t len;
	int bits, shift, padding;

	for (bits = shift = padding = len = 0; ilen && *in; --ilen, ++in) {
		if (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n' ||
		    (padding && *in == '=')) {
			/* consume */
			continue;
		} else if (!padding && b64dec[*in] >= 0) {
			/* shift into accumulator */
			shift += 6;
			bits = bits << 6 | b64dec[*in];
		} else if (!padding && shift > 0 && shift != 6 && *in == '=') {
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
