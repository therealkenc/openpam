/*-
 * Copyright (c) 2012-2013 Universitetet i Oslo
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

#ifndef OATH_TYPES_H_INCLUDED
#define OATH_TYPES_H_INCLUDED

/*
 * OATH key and associated parameters
 */
struct oath_key {
	/* mode and parameters */
	enum oath_mode	 mode;
	unsigned int	 digits;
	uint64_t	 counter;  /* HOTP only */
	unsigned int	 timestep; /* TOTP only - in seconds */
	uint64_t	 lastused; /* TOTP only */

	/* housekeeping */
	unsigned int	 dummy:1;  /* dummy key, always fail */
	unsigned int	 mapped:1; /* allocated with mmap() */
	unsigned int	 locked:1; /* locked / wired with madvise() */

	/* hash algorithm */
	enum oath_hash	 hash;

	/* label */
	size_t		 labellen; /* bytes incl. NUL */
	char		 label[OATH_MAX_LABELLEN];

	/* key */
	size_t		 keylen; /* bytes */
	uint8_t		 key[OATH_MAX_KEYLEN];
};

#endif
