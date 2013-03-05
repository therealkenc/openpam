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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "oath.h"

#include "t.h"

struct test_vector {
	const uint8_t *in;
	size_t ilen;
	const char *out;
	size_t olen;
};

#define TV(i, o) \
	{ (const uint8_t *)i, sizeof i - 1, (const char *)o, sizeof o }
#define TV_ZERO \
	{ NULL, 0, NULL, 0 }

static struct test_vector base64_vectors[] = {
	TV("", ""),
	TV("f", "Zg=="),
	TV("fo", "Zm8="),
	TV("foo", "Zm9v"),
	TV("foob", "Zm9vYg=="),
	TV("fooba", "Zm9vYmE="),
	TV("foobar", "Zm9vYmFy"),
	TV_ZERO
};

static struct test_vector base32_vectors[] = {
	TV("", ""),
	TV("f", "MY======"),
	TV("fo", "MZXQ===="),
	TV("foo", "MZXW6==="),
	TV("foob", "MZXW6YQ="),
	TV("fooba", "MZXW6YTB"),
	TV("foobar", "MZXW6YTBOI======"),
	TV_ZERO
};


/***************************************************************************
 * Base 64
 */

T_FUNC(base_64, "RFC 4648 base 64 test vectors")
{
	struct test_vector *tv;
	char buf[64];
	size_t buflen;

	for (tv = base64_vectors; tv->in != NULL; ++tv) {
		buflen = tv->olen;
		t_verbose("BASE64(\"%s\") = \"%s\"\n", tv->in, tv->out);
		if (base64_enc(tv->in, tv->ilen, buf, &buflen) != 0) {
			t_verbose("BASE64(\"%s\") failed\n", tv->in);
			return (0);
		}
		if (buflen != tv->olen) {
			t_verbose("BASE64(\"%s\") expected %zu B got %zu B\n",
			    tv->in, tv->olen, buflen);
			return (0);
		}
		if (strcmp(buf, tv->out) != 0) {
			t_verbose("BASE64(\"%s\") expected \"%s\" got \"%s\"\n",
			    tv->in, tv->out, buf);
			return (0);
		}
	}
	return (1);
}


/***************************************************************************
 * Base 32
 */

T_FUNC(base_32, "RFC 4648 base 32 test vectors")
{
	struct test_vector *tv;
	char buf[64];
	size_t buflen;

	for (tv = base32_vectors; tv->in != NULL; ++tv) {
		buflen = tv->olen;
		t_verbose("BASE32(\"%s\") = \"%s\"\n", tv->in, tv->out);
		if (base32_enc(tv->in, tv->ilen, buf, &buflen) != 0) {
			t_verbose("BASE32(\"%s\") failed\n", tv->in);
			return (0);
		}
		if (buflen != tv->olen) {
			t_verbose("BASE32(\"%s\") expected %zu B got %zu B\n",
			    tv->in, tv->olen, buflen);
			return (0);
		}
		if (strcmp(buf, tv->out) != 0) {
			t_verbose("BASE32(\"%s\") expected \"%s\" got \"%s\"\n",
			    tv->in, tv->out, buf);
			return (0);
		}
	}
	return (1);
}


/***************************************************************************
 * Boilerplate
 */

const struct t_test *t_plan[] = {
	T(base_64),
	T(base_32),
	NULL
};

const struct t_test **
t_prepare(int argc, char *argv[])
{

	(void)argc;
	(void)argv;
	return (t_plan);
}

void
t_cleanup(void)
{
}
