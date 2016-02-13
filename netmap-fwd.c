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
#include "ribsync.h"
#include "util.h"

#ifndef PREFIX
#define	PREFIX		"/usr/local/etc/"
#endif

int burst = 1024;
int nohostring = 0;
int verbose = 0;
struct pkt_cnt pktcnt;

void
usage(void)
{

	printf("usage:\n");
	printf("netmap-fwd [-b 1024] [-H] [-f netmap-fwd.conf] [-v] if1 [if2] [ifN]\n");
	printf("\t-b\tmaximum number of packets processed at each read event\n");
	printf("\t-H\tdo not open the host ring\n");
	printf("\t-f\tset the path to netmap-fwd config file\n");
	printf("\t-v\tverbose\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	char *ifn;
	const char *config;
	int ch, err, ifs;

	config = NULL;
	while ((ch = getopt(argc, argv, "b:Hf:v")) != -1) {
		switch (ch) {
		case 'b':
			burst = atoi(optarg);
			if (burst == 0)
				burst = 1024;
			break;
		case 'H':
			nohostring = 1;
			break;
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
	if (argc < 1)
		usage();

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
	ribsync_init();

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
    if (ribsync_open() == -1) {
        printf("cannot open the kernel PF_ROUTE socket.\n");
        cleanup();
        exit(1);
    }

	event_base_dispatch(ev_get_base()); 
	cleanup();

	exit(0);
}
