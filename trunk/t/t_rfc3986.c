/*-
 * Copyright (c) 2013-2015 The University of Oslo
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
 * $Id: t_rfc4648.c 799 2014-07-10 17:16:48Z des $
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
	size_t (*func)(const char *, size_t, char *, size_t);
	const char *in;		/* input string  */
	size_t ilen;		/* input length */
	const char *out;	/* expected output string */
	size_t olen;		/* expected output length */
};

/* basic encoding / decoding */
#define T_ENCODE4(d, i, il, o, ol)					\
	{ .func = oath_uri_encode, .desc = d,				\
	  .in = i, .ilen = il, .out = o, .olen = ol }
#define T_ENCODE(d, i, o)						\
	T_ENCODE4(d, i, sizeof(i) - 1, o, sizeof(o))
#define T_DECODE4(d, i, il, o, ol)					\
	{ .func = oath_uri_decode, .desc = d,				\
	  .in = i, .ilen = il, .out = o, .olen = ol }
#define T_DECODE(d, i, o)						\
	T_DECODE4(d, i, sizeof(i) - 1, o, sizeof(o))
#define T_ENCDEC(d, i, o)						\
	T_ENCODE(d " enc", i, o), T_DECODE(d " dec", o, i)

static struct t_case t_cases[] = {
	/* empty */
	T_DECODE("empty",		"",		""),

	/* simple */
	T_DECODE("simple",		"%20",		" "),
	T_DECODE("prefix",		"x%20",		"x "),
	T_DECODE("suffix",		"%20x",		" x"),
	T_DECODE("surrounded",		"x%20x",	"x x"),

	/* partials */
	T_DECODE("partial, one",	"%",		"%"),
	T_DECODE("partial, two",	"%2",		"%2"),

	/* non-hex character */
	T_DECODE("non-hex, first",	"%2x",		"%2x"),
	T_DECODE("non-hex, second",	"%x0",		"%x0"),
	T_DECODE("non-hex, both",	"%xx",		"%xx"),
};

/*
 * Encoding test function
 */
static int
t_rfc3986(void *arg)
{
	struct t_case *t = arg;
	char buf[256];
	size_t len;
	int ret;

	len = t->func(t->in, t->ilen, buf, sizeof buf);
	ret = 1;
	if (t->out && len != t->olen) {
		t_verbose("expected output length %zu, got %zu\n",
		    t->olen, len);
		ret = 0;
	}
	if (t->out && strncmp(buf, t->out, len) != 0) {
		t_verbose("expected '%.*s' got '%.*s'\n",
		    (int)t->olen, t->out, (int)len, buf);
		ret = 0;
	}
	return (ret);
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
	    (tests = calloc(n, sizeof *tests)) == NULL)
		return (NULL);
	for (i = 0; i < n; ++i) {
		plan[i] = &tests[i];
		tests[i].func = t_rfc3986;
		tests[i].desc = t_cases[i].desc;
		tests[i].arg = &t_cases[i];
	}
	plan[n] = NULL;
	return ((const struct t_test **)plan);
}

/*
 * Cleanup
 */
void
t_cleanup(void)
{
}
