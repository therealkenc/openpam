/*-
 * Copyright (c) 2002 Networks Associates Technologies, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
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

#ifndef _SECURITY_OPENPAM_H_INCLUDED
#define _SECURITY_OPENPAM_H_INCLUDED

/*
 * Log levels
 */
enum {
	PAM_LOG_DEBUG,
	PAM_LOG_VERBOSE,
	PAM_LOG_NOTICE,
	PAM_LOG_ERROR
};

/*
 * Log to syslog
 */
void _openpam_log(int _level,
	const char *_func,
	const char *_fmt,
	...);

#ifdef __GNUC__
#define openpam_log(lvl, fmt...) \
	_openpam_log((lvl), __func__, ##fmt)
#else
#define openpam_log(lvl, fmt, ...) \
	_openpam_log((lvl), __func__, fmt, __VA_ARGS__)
#endif

/*
 * Generic conversation function
 */
int openpam_ttyconv(int _n,
	const struct pam_message **_msg,
	struct pam_response **_resp,
	void *_data);

#endif
