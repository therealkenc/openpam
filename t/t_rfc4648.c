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
#include <security/oath.h>

#include "t.h"

/*
 * Test vectors from RFC 4648
 */
static struct t_vector {
	const char *plain;
/*	const char *base16; */
	const char *base32;
	const char *base64;
} t_vectors[] = {
	{
		.plain	= "",
		.base32	= "",
		.base64	= "",
	},
	{
		.plain	= "f",
		.base32	= "MY======",
		.base64	= "Zg=="
	},
	{
		.plain	= "fo",
		.base32	= "MZXQ====",
		.base64	= "Zm8=",
	},
	{
		.plain	= "foo",
		.base32	= "MZXW6===",
		.base64	= "Zm9v",
	},
	{
		.plain	= "foob",
		.base32	= "MZXW6YQ=",
		.base64	= "Zm9vYg==",
	},
	{
		.plain	= "fooba",
		.base32	= "MZXW6YTB",
		.base64	= "Zm9vYmE=",
	},
	{
		.plain	= "foobar",
		.base32	= "MZXW6YTBOI======",
		.base64	= "Zm9vYmFy",
	},
};

/*
 * Encoding test function
 */
static int
t_rfc4648_enc(const char *plain, const char *encoded,
    int (*enc)(const uint8_t *, size_t, char *, size_t *))
{
	char buf[64];
	size_t blen, ilen, olen;

	blen = sizeof buf;
	ilen = strlen(plain);
	olen = strlen(encoded) + 1;
	if (enc((const uint8_t *)plain, ilen, buf, &blen) != 0) {
		t_verbose("encoding failed\n");
		return (0);
	}
	if (blen != olen) {
		t_verbose("expected %zu B got %zu B\n", olen, blen);
		return (0);
	}
	if (strcmp(buf, encoded) != 0) {
		t_verbose("expected \"%s\" got \"%s\"\n", encoded, buf);
		return (0);
	}
	return (1);
}

/*
 * Encoding test wrapper for base 32
 */
static int
t_base32(void *arg)
{
	struct t_vector *tv = (struct t_vector *)arg;

	return (t_rfc4648_enc(tv->plain, tv->base32, base32_enc));
}

/*
 * Encoding test wrapper for base 64
 */
static int
t_base64(void *arg)
{
	struct t_vector *tv = (struct t_vector *)arg;

	return (t_rfc4648_enc(tv->plain, tv->base64, base64_enc));
}

/*
 * Generate a test case for a given test vector
 */
static struct t_test *
t_create_test(int (*func)(void *), const char *name, struct t_vector *tv)
{
	struct t_test *test;
	char *desc;

	if ((test = calloc(1, sizeof *test)) == NULL)
		return (NULL);
	test->func = func;
	if ((desc = calloc(1, strlen(name) + strlen(tv->plain) + 5)) == NULL)
		return (NULL);
	sprintf(desc, "%s(\"%s\")", name, tv->plain);
	test->desc = desc;
	test->arg = tv;
	return (test);
}

/*
 * Generate the test plan
 */
const struct t_test **
t_prepare(int argc, char *argv[])
{
	struct t_test **plan, **test;
	int n;

	(void)argc;
	(void)argv;
	n = sizeof t_vectors / sizeof t_vectors[0];
	plan = calloc(n * 2 + 1, sizeof *plan);
	if (plan == NULL)
		return (NULL);
	test = plan;
	for (int i = 0; i < n; ++i) {
		*test++ = t_create_test(t_base32, "BASE32", &t_vectors[i]);
		*test++ = t_create_test(t_base64, "BASE64", &t_vectors[i]);
	}
	return ((const struct t_test **)plan);
}

/*
 * Cleanup
 */
void
t_cleanup(void)
{
}
