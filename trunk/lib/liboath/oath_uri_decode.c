/*-
 * Copyright (c) 2014 Dag-Erling Smørgrav
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

#include <string.h>

#include "openpam_ctype.h"

#define unhex(ch)							\
	((ch >= '0' && ch <= '9') ? ch - '0' :				\
	 (ch >= 'A' && ch <= 'F') ? 0xa + ch - 'A' :			\
	 (ch >= 'a' && ch <= 'f') ? 0xa + ch - 'a' : 0)

/*
 * OATH
 *
 * Decodes a URI-encoded string.
 */

size_t
oath_uri_decode(const char *in, size_t ilen, char *out, size_t olen)
{
	size_t ipos, opos;

	if (ilen == 0)
		ilen = strlen(in);
	for (ipos = opos = 0; ipos < ilen && in[ipos] != '\0'; ++ipos, ++opos) {
		if (in[ipos] == '%' && ipos + 2 < ilen &&
		    is_xdigit(in[ipos + 1]) && is_xdigit(in[ipos + 2])) {
			if (out != NULL && opos < olen - 1)
				out[opos] = unhex(in[ipos + 1]) * 16 +
				    unhex(in[ipos + 2]);
			ilen += 2;
			ipos += 2;
		} else {
			if (out != NULL && opos < olen - 1)
				out[opos] = in[ipos];
		}
	}
	if (out != NULL && olen > 0)
		out[opos < olen ? opos : olen - 1] = '\0';
	return (opos + 1);
}

/**
 * The =oath_uri_decode function decodes a URI-encoded ("percent-encoded")
 * string.
 *
 * The =in parameter points to the string to be decoded, and the =ilen
 * parameter is its length.  If =ilen is 0, =oath_uri_decode will decode
 * the entire string.
 *
 * The =out parameter points to a buffer in which the decoded data is to
 * be stored; the =olen parameter is the size of that buffer.  If =out is
 * =NULL, the decoded data is discarded, but =oath_uri_decode still counts
 * the amount of space needed to store it.
 *
 * The output buffer is always NUL-terminated, regardless of how much or
 * how little data was decoded.
 *
 * RETURN VALUES
 *
 * The =oath_uri_decode funtion always returns the amount of space
 * required to store the entire decoded string, including the terminating
 * NUL.  This may exceed the actual size of the output buffer.
 *
 * AUTHOR UIO
 */
