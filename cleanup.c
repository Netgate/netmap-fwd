/*-
 * Copyright (c) 2015, Luiz Souza <loos@freebsd.org>
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
 */

#include <sys/queue.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cleanup.h"
#include "config.h"
#include "event.h"

struct cln_cb {
	STAILQ_ENTRY(cln_cb)	cln_cb_next;
	void			(*cb)(void *);
	void			*arg;
};

static STAILQ_HEAD(cln_cbs_, cln_cb) cln_cbs;
static struct event *ev_sigint = NULL;
static struct event *ev_sigterm = NULL;

static void
cleanup_run(int sig, short event, void *data)
{

	cleanup();
}

void
cleanup_init(void)
{

	STAILQ_INIT(&cln_cbs);
	ev_sigint = evsignal_new(ev_get_base(), SIGINT, cleanup_run, NULL);
	evsignal_add(ev_sigint, NULL);
	ev_sigterm = evsignal_new(ev_get_base(), SIGTERM, cleanup_run, NULL);
	evsignal_add(ev_sigterm, NULL);
}

void
cleanup_add(void (*cb)(void *), void *arg)
{
	struct cln_cb *clncb;

	clncb = malloc(sizeof(*clncb));
	if (clncb == NULL)
		exit(51);
	memset(clncb, 0, sizeof(*clncb));
	clncb->cb = cb;
	clncb->arg = arg;
	STAILQ_INSERT_HEAD(&cln_cbs, clncb, cln_cb_next);
}

void
cleanup(void)
{
	struct cln_cb *clncb, *tmp;

	/* Cleanup signal handlers. */
	if (ev_sigint != NULL && evsignal_initialized(ev_sigint)) {
		evsignal_del(ev_sigint);
		event_free(ev_sigint);
		ev_sigint = NULL;
	}
	if (ev_sigterm != NULL && evsignal_initialized(ev_sigterm)) {
		evsignal_del(ev_sigterm);
		event_free(ev_sigterm);
		ev_sigterm = NULL;
	}

	STAILQ_FOREACH_SAFE(clncb, &cln_cbs, cln_cb_next, tmp) {
		STAILQ_REMOVE(&cln_cbs, clncb, cln_cb, cln_cb_next);
		clncb->cb(clncb->arg);
		free(clncb);
	}

	/* Remove pid file. */
	unlink(config_get_str("pidfile"));

	exit(0);
}
