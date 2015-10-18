/*-
 * Copyright (c) 2015, Luiz Otavio O Souza <loos@FreeBSD.org>
 * Copyright (c) 2015, Rubicon Communications, LLC (Netgate)
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

#include <string.h>

#include "config.h"
#include "cleanup.h"
#include "event.h"
#include "util.h"

static struct event_base *ev_base = NULL;

static void
ev_cleanup(void *unused)
{

	event_base_free(ev_base);
}

struct event_base *
ev_get_base(void)
{

	return (ev_base);
}

int
ev_init(void)
{
	const char *evbackend, **m;
	int backendok;
	struct event_config *cfg;

	cfg = event_config_new();
	if (cfg == NULL) {
		printf("cannot setup event config.\n");
		return (-1);
	}
	evbackend = config_get_str("event_backend");
	if (evbackend == NULL ||
	    (strcasecmp(evbackend, "poll") != 0 &&
	    strcasecmp(evbackend, "kqueue") != 0)) {
		printf("invalid netmap event backend.\n");
		return (-1);
	}
	backendok = 0;
	m = event_get_supported_methods();
	while (m != NULL && *m != NULL) {
		if (strcasecmp(*m, evbackend) == 0)
			backendok = 1;
		else
			/*
			 * Netmap support kqueue and poll() notifications, so
			 * we avoid all the other options.
			 */
			if (event_config_avoid_method(cfg, *m) == -1) {
				printf("cannot avoid method: %s\n", *m);
				event_config_free(cfg);
				return (-1);
			}
		m++;
	}
	if (backendok == 0) {
		printf("libevent doesn't support %s() backend.\n", evbackend);
		event_config_free(cfg);
		return (-1);
	}
	ev_base = event_base_new_with_config(cfg);
	if (ev_base == NULL) {
		printf("cannot setup event base.\n");
		event_config_free(cfg);
		return (-1);
	}
	DPRINTF("event method: %s\n", event_base_get_method(ev_base));
	event_config_free(cfg);

	/* Add the cleanup callback. */
	cleanup_add(ev_cleanup, NULL);

	return (0);
}
