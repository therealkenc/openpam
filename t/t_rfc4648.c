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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oath.h>

#include "t.h"

struct t_case {
	const char *desc;
	int (*func)(const char *, size_t, char *, size_t *);
	const char *in;		/* input string  */
	size_t ilen;		/* input length */
	const char *out;	/* expected output string or NULL */
	size_t blen;		/* initial value for olen or 0*/
	size_t olen;		/* expected value for olen */
	int ret;		/* expected return value */
	int err;		/* expected errno if ret != 0 */
};

/* basic encoding / decoding */
#define T_ENCODE_N(N, i, o)						\
	{ "base"#N"_enc("#i")", base##N##_enc, i, sizeof i - 1,		\
	  o, sizeof o, sizeof o, 0, 0 }
#define T_DECODE_N(N, i, o)						\
	{ "base"#N"_dec("#i")", base##N##_dec, i, sizeof i - 1,		\
	  o, sizeof o - 1, sizeof o - 1, 0, 0 }
#define T_ENCODE(p, b32, b64)						\
	T_ENCODE_N(32, p, b32), T_ENCODE_N(64, p, b64)
#define T_DECODE(p, b32, b64)						\
	T_DECODE_N(32, b32, p), T_DECODE_N(64, b64, p)

/* roundtrip encoding tests */
#define T_ENCDEC(p, b32, b64)						\
	T_ENCODE(p, b32, b64), T_DECODE(p, b32, b64)

/* decoding failure */
#define T_DECODE_FAIL_N(N, e, i)					\
	{ "base"#N"_dec("#i")", base##N##_dec, i, sizeof i - 1,		\
	  NULL, 0, 0, -1, e }
#define T_DECODE_FAIL(e, b32, b64)					\
	T_DECODE_FAIL_N(32, e, b32), T_DECODE_FAIL_N(64, e, b64)

/* input string shorter than input length */
#define T_SHORT_INPUT_DEC(N, i)						\
	{ "base"#N"_dec (short input)", base##N##_dec, i, sizeof i + 2, \
	  NULL, 0, base##N##_declen(sizeof i - 1), 0, 0 }
#define T_SHORT_INPUT()							\
	T_SHORT_INPUT_DEC(32, "AAAAAAAA"),				\
	T_SHORT_INPUT_DEC(64, "AAAA")

/* output string longer than output length */
#define T_LONG_OUTPUT_ENC(N, i)						\
	{ "base"#N"_enc (long output)", base##N##_enc, i, sizeof i - 1,	\
	  NULL, 1, base##N##_enclen(sizeof i - 1) + 1, -1, ENOSPC }
#define T_LONG_OUTPUT_DEC(N, i)						\
	{ "base"#N"_dec (long output)", base##N##_dec, "AAAAAAAA", 8,	\
	  NULL, 1, base##N##_declen(sizeof i - 1), -1, ENOSPC }
#define T_LONG_OUTPUT()							\
	T_LONG_OUTPUT_ENC(32, "foo"),					\
	T_LONG_OUTPUT_DEC(32, "AAAAAAAA"),				\
	T_LONG_OUTPUT_ENC(64, "foo"),					\
	T_LONG_OUTPUT_DEC(64, "AAAA")

static struct t_case t_cases[] = {
	/* test vectors from RFC 4648 */
	/*	 plain		base32			base64 */
	T_ENCDEC("",		"",			""),
	T_ENCDEC("f",		"MY======",		"Zg=="),
	T_ENCDEC("fo",		"MZXQ====",		"Zm8="),
	T_ENCDEC("foo",		"MZXW6===",		"Zm9v"),
	T_ENCDEC("foob",	"MZXW6YQ=",		"Zm9vYg=="),
	T_ENCDEC("fooba",	"MZXW6YTB",		"Zm9vYmE="),
	T_ENCDEC("foobar",	"MZXW6YTBOI======",	"Zm9vYmFy"),

	/* zeroes */
	T_ENCDEC("\0\0\0",	"AAAAA===",		"AAAA"),

	/* sloppy padding */
	T_DECODE("f",		"MY=",			"Zg="),
	T_DECODE("f",		"MY",			"Zg"),

	/* whitespace */
	/*	 plain		base32			base64 */
	T_DECODE("tst",		"ORZX I===",		"dH N0"),
	T_DECODE("tst",		"ORZX\tI===",		"dH\tN0"),
	T_DECODE("tst",		"ORZX\rI===",		"dH\rN0"),
	T_DECODE("tst",		"ORZX\nI===",		"dH\nN0"),

	/* invalid character in data */
	T_DECODE_FAIL(EINVAL,	"AA!AAAAAA",		"AA!A"),

	/* invalid character in padding */
	T_DECODE_FAIL(EINVAL,	"AAAAA==!",		"AA=!"),

	/* padding with no data */
	T_DECODE_FAIL(EINVAL,	"AAAAAAAA=",		"AAAA="),

	/* data after padding */
	T_DECODE_FAIL(EINVAL,	"AA=A",			"AA=A"),

	/* padding in incorrect location */
	T_DECODE_FAIL_N(32, EINVAL, "A======="),
	T_DECODE_FAIL_N(32, EINVAL, "AAA====="),
	T_DECODE_FAIL_N(32, EINVAL, "AAAAAA=="),
	T_DECODE_FAIL_N(64, EINVAL, "A==="),

	/* various error conditions */
	T_SHORT_INPUT(),
	T_LONG_OUTPUT(),
};

/*
 * Encoding test function
 */
static int
t_rfc4648(void *arg)
{
	struct t_case *t = arg;
	char buf[64];
	size_t len;
	int ret;

	len = t->blen ? t->blen : sizeof buf;
	ret = t->func(t->in, t->ilen, buf, &len);
	if (ret != t->ret) {
		t_verbose("expected return code %d, got %d\n",
		    t->ret, ret);
		return (0);
	}
	if (t->out && len != t->olen) {
		t_verbose("expected output length %zu, got %zu\n",
		    t->olen, len);
		return (0);
	}
	if (t->ret != 0 && errno != t->err) {
		t_verbose("expected errno %d, got %d\n",
		    t->err, errno);
		return (0);
	}
	if (t->ret == 0 && t->out && strncmp(buf, t->out, len) != 0) {
		t_verbose("expected '%.*s' got '%.*s'\n",
		    (int)t->olen, t->out, (int)len, buf);
		return (0);
	}
	return (1);
}

/*
 * Generate the test plan
 */
const struct t_test **
t_prepare(int argc, char *argv[])
{
	struct t_test **plan, *tests;
	int i, n;

	(void)argc;
	(void)argv;
	n = sizeof t_cases / sizeof t_cases[0];
	if ((plan = calloc(n + 1, sizeof *plan)) == NULL ||
	    (tests = calloc(n + 1, sizeof *tests)) == NULL)
		return (NULL);
	for (i = 0; i < n; ++i) {
		plan[i] = &tests[i];
		tests[i].func = t_rfc4648;
		tests[i].desc = t_cases[i].desc;
		tests[i].arg = &t_cases[i];
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
