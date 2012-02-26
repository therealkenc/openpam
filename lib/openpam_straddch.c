/*-
 * Copyright (c) 2012 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <stdlib.h>

#include <security/pam_appl.h>
#include "openpam_impl.h"

/*
 * OpenPAM extension
 *
 * Add a character to a string, expanding the buffer if needed.
 */

int
openpam_straddch(char **str, size_t *size, size_t *len, char ch)
{
	char *tmp;

	if (*str == NULL) {
		/* initial allocation */
		if ((*str = malloc(*size = 32)) == NULL) {
			openpam_log(PAM_LOG_ERROR, "malloc(): %m");
			return (-1);
		}
		*len = 0;
	} else if (*len >= *size - 1) {
		/* additional space required */
		if ((tmp = realloc(*str, *size *= 2)) == NULL) {
			openpam_log(PAM_LOG_ERROR, "realloc(): %m");
			free(*str);
			*str = NULL;
			return (-1);
		}
		*str = tmp;
	}
	(*str)[*len] = ch;
	++*len;
	(*str)[*len] = '\0';
	return (0);
}

/*
 * NODOC
 */
