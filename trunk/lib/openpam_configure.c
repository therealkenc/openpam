/*-
 * Copyright (c) 2001-2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
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
 * $P4: //depot/projects/openpam/lib/openpam_configure.c#8 $
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include "openpam_impl.h"

static int openpam_load_chain(pam_chain_t **, const char *, const char *);

/*
 * Matches a word against the first one in a string.
 * Returns non-zero if they match.
 */
static int
match_word(const char *str, const char *word)
{

	while (*str && *str == *word)
		++str, ++word;
	return (*str == ' ' && *word == '\0');
}

/*
 * Return a pointer to the next word (or the final NUL) in a string.
 */
static const char *
next_word(const char *str)
{

	/* skip current word */
	while (*str && !isspace(*str))
		++str;
	/* skip whitespace */
	while (isspace(*str))
		++str;
	return (str);
}

/*
 * Return a malloc()ed copy of the first word in a string.
 */
static char *
dup_word(const char *str)
{
	const char *end;
	char *word;

	for (end = str; *end && !isspace(*end); ++end)
		/* nothing */ ;
	if (asprintf(&word, "%.*s", (int)(end - str), str) < 0)
		return (NULL);
	return (word);
}

typedef enum { pam_conf_style, pam_d_style } openpam_style_t;

/*
 * Extracts a given chain from a policy file.
 */
static int
openpam_read_chain(pam_chain_t **chain,
	const char *service,
	const char *facility,
	const char *filename,
	openpam_style_t style)
{
	pam_chain_t *this, **next;
	const char *p, *q;
	int count, i, ret;
	char *line, *name;
	FILE *f;

	if ((f = fopen(filename, "r")) == NULL) {
		openpam_log(errno == ENOENT ? PAM_LOG_NOTICE : PAM_LOG_ERROR,
		    "%s: %m", filename);
		return (0);
	}
	next = chain;
	this = *next = NULL;
	count = 0;
	while ((line = openpam_readline(f, NULL)) != NULL) {
		p = line;

		/* match service name */
		if (style == pam_conf_style) {
			if (!match_word(p, service)) {
				FREE(line);
				continue;
			}
			p = next_word(p);
		}

		/* match facility name */
		if (!match_word(p, facility)) {
			FREE(line);
			continue;
		}
		p = next_word(p);

		/* include other chain */
		if (match_word(p, "include")) {
			p = next_word(p);
			if (*next_word(p) != '\0')
				openpam_log(PAM_LOG_NOTICE,
				    "%s: garbage at end of 'include' line",
				    filename);
			if ((name = dup_word(p)) == NULL)
				goto syserr;
			ret = openpam_load_chain(next, name, facility);
			FREE(name);
			while (*next != NULL) {
				next = &(*next)->next;
				++count;
			}
			FREE(line);
			if (ret < 0)
				goto fail;
			continue;
		}

		/* allocate new entry */
		if ((this = calloc(1, sizeof *this)) == NULL)
			goto syserr;

		/* control flag */
		if (match_word(p, "required")) {
			this->flag = PAM_REQUIRED;
		} else if (match_word(p, "requisite")) {
			this->flag = PAM_REQUISITE;
		} else if (match_word(p, "sufficient")) {
			this->flag = PAM_SUFFICIENT;
		} else if (match_word(p, "optional")) {
			this->flag = PAM_OPTIONAL;
		} else if (match_word(p, "binding")) {
			this->flag = PAM_BINDING;
		} else {
			q = next_word(p);
			openpam_log(PAM_LOG_ERROR,
			    "%s: invalid control flag '%.*s'",
			    filename, (int)(q - p), p);
			goto fail;
		}

		/* module name */
		p = next_word(p);
		q = next_word(p);
		if (*p == '\0') {
			openpam_log(PAM_LOG_ERROR,
			    "%s: missing module name", filename);
			goto fail;
		}
		if ((name = dup_word(p)) == NULL)
			goto syserr;
		this->module = openpam_load_module(name);
		FREE(name);
		if (this->module == NULL)
			goto fail;

		/* module options */
		while (*q != '\0') {
			++this->optc;
			q = next_word(q);
		}
		this->optv = calloc(this->optc + 1, sizeof(char *));
		if (this->optv == NULL)
			goto syserr;
		for (i = 0; i < this->optc; ++i) {
			p = next_word(p);
			if ((this->optv[i] = dup_word(p)) == NULL)
				goto syserr;
		}

		/* hook it up */
		*next = this;
		next = &this->next;
		this = NULL;
	        ++count;

		/* next please... */
		FREE(line);
	}
	if (!feof(f))
		goto syserr;
	fclose(f);
	return (count);
 syserr:
	openpam_log(PAM_LOG_ERROR, "%s: %m", filename);
 fail:
	FREE(this);
	FREE(line);
	fclose(f);
	return (-1);
}

static const char *openpam_policy_path[] = {
	"/etc/pam.d/",
	"/etc/pam.conf",
	"/usr/local/etc/pam.d/",
	"/usr/local/etc/pam.conf",
	NULL
};

/*
 * Locates the policy file for a given service and reads the given chain
 * from it.
 */
static int
openpam_load_chain(pam_chain_t **chain,
	const char *service,
	const char *facility)
{
	const char **path;
	char *filename;
	size_t len;
	int r;

	for (path = openpam_policy_path; *path != NULL; ++path) {
		len = strlen(*path);
		if ((*path)[len - 1] == '/') {
			if (asprintf(&filename, "%s%s", *path, service) < 0) {
				openpam_log(PAM_LOG_ERROR, "asprintf(): %m");
				return (-PAM_BUF_ERR);
			}
			r = openpam_read_chain(chain, service, facility,
			    filename, pam_d_style);
			FREE(filename);
		} else {
			r = openpam_read_chain(chain, service, facility,
			    *path, pam_conf_style);
		}
		if (r != 0)
			return (r);
	}
	return (0);
}

const char *_pam_chain_name[PAM_NUM_CHAINS] = {
	[PAM_AUTH] = "auth",
	[PAM_ACCOUNT] = "account",
	[PAM_SESSION] = "session",
	[PAM_PASSWORD] = "password"
};

/*
 * OpenPAM internal
 *
 * Configure a service
 */

int
openpam_configure(pam_handle_t *pamh,
	const char *service)
{
	int i, ret;

	for (i = 0; i < PAM_NUM_CHAINS; ++i) {
		ret = openpam_load_chain(&pamh->chains[i],
		    service, _pam_chain_name[i]);
		if (ret == 0)
			ret = openpam_load_chain(&pamh->chains[i],
			    PAM_OTHER, _pam_chain_name[i]);
		if (ret < 0) {
			openpam_clear_chains(pamh->chains);
			return (PAM_SYSTEM_ERR);
		}
	}
	return (PAM_SUCCESS);
}

/*
 * NODOC
 *
 * Error codes:
 *	PAM_SYSTEM_ERR
 */
