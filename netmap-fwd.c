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
#include <sys/types.h>
#include <sys/socket.h>

#include <net/ethernet.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arp.h"
#include "cleanup.h"
#include "counters.h"
#include "cli.h"
#include "config.h"
#include "event.h"
#include "if.h"
#include "inet.h"
#include "util.h"

#ifndef PREFIX
#define	PREFIX		"/usr/local/etc/"
#endif

int verbose = 0;
struct pkt_cnt pktcnt;

void
usage(void)
{

	printf("usage:\n");
	printf("netmap-fwd [-f netmap-fwd.conf] if [if2] [ifN]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	char *ifn;
	const char *config;
	int ch, err, ifs;

	if (argc < 2)
		usage();

	config = NULL;
	while ((ch = getopt(argc, argv, "f:v")) != -1) {
		switch (ch) {
		case 'f':
			config = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}
	ifs = 0;
	argc -= optind;
	argv += optind;

	/* Parse the config file. */
	if (config == NULL)
		config = PREFIX "netmap-fwd.conf";
	if (config_parse(config) == -1)
		exit(1);

	/* Create the pidfile. */
	if (pidfile_create(config_get_str("pidfile")) == -1)
		exit(1);

	/* Initialize event library. */
	if (ev_init() == -1)
		exit(1);
	/* Initialize the basic stuff. */
	cleanup_init();
	cli_init();
	if_init();

	/* Reset statistics. */
	memset(&pktcnt, 0, sizeof(pktcnt));

	/* Init IPv4 */
	arp_init();
	if (inet_init() == -1) {
		printf("error: cannot initialize the inet data structures.\n");
		exit(1);
	}

	while (argc > 0) {
		ifn = argv[0];
		err = if_open(ifn);
		switch (err) {
		case ENOENT:
			printf("interface %s has no IP address\n", ifn);
			break;
		case ENOTSUP:
			printf("interface not supported: %s\n", ifn);
			break;
		case 0:
			ifs++;
			break;
		case -1:
			printf("cannot open interface: %s\n", ifn);
			cleanup();
			exit(1);
		}
		argc -= 1;
		argv += 1;
	}
	if (ifs == 0) {
		printf("no valid interface selected.\n");
		cleanup();
		exit(1);
	}
	if (cli_open() == -1) {
		printf("cannot open the cli socket.\n");
		cleanup();
		exit(1);
	}
	event_base_dispatch(ev_get_base()); 
	cleanup();

	exit(0);
}
