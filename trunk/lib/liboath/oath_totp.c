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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <security/oath.h>

#define TOTP_TIME_STEP 30

unsigned int
oath_totp(const uint8_t *K, size_t Klen, unsigned int Digit)
{
	time_t now;

	time(&now);
	return (oath_hotp(K, Klen, now / TOTP_TIME_STEP, Digit));
}

unsigned int
oath_totp_current(const struct oath_key *k)
{
	unsigned int code;
	uint64_t seq;

	if (k == NULL)
		return (-1);
	if (k->mode != om_totp)
		return (-1);
	if (k->timestep == 0)
		return (-1);
	seq = time(NULL) / k->timestep;
	code = oath_hotp(k->key, k->keylen, seq, k->digits);
	return (code);
}

int
oath_totp_match(const struct oath_key *k, unsigned int response, int window)
{
	unsigned int code;
	uint64_t seq;
	int dummy;

	if (k == NULL)
		return (-1);
	if (window < 1)
		return (-1);
	if (k->mode != om_totp)
		return (-1);
	if (k->timestep == 0)
		return (-1);
	seq = time(NULL) / k->timestep;
	dummy = (strcmp(k->label, OATH_DUMMY_LABEL) == 0);
	for (int i = -window; i <= window; ++i) {
		code = oath_hotp(k->key, k->keylen, seq + i, k->digits);
		if (code == response && !dummy)
			return (1);
	}
	return (0);
}
