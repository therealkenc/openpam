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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/openpam.h>

#include "openpam_strlcmp.h"

#include <security/oath.h>

/*
 * OATH
 *
 * Loads an OATH key from a file
 */

struct oath_key *
oath_key_from_file(const char *filename)
{
	struct oath_key *key;
	FILE *f;
	char *line;
	size_t len;

	if ((f = fopen(filename, "r")) == NULL)
		return (NULL);
	/* get first non-empty non-comment line */
	line = openpam_readline(f, NULL, &len);
	if (strlcmp("otpauth://", line, len) == 0) {
		key = oath_key_from_uri(line);
	} else {
		openpam_log(PAM_LOG_ERROR,
		    "unrecognized key file format: %s", filename);
		key = NULL;
	}
	fclose(f);
	return (key);
}

/**
 * The =oath_key_from_file function loads a key from the specified file.
 * The file format is automatically detected.
 *
 * The following key file formats are supported:
 *
 *  - otpauth URI
 *
 * Keys created with =oath_key_from_file must be freed using
 * =oath_key_free.
 *
 * >oath_key_alloc
 * >oath_key_free
 * >oath_key_from_uri
 *
 * AUTHOR UIO
 */
