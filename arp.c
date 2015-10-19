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
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libutil.h>

#include "arp.h"
#include "cli.h"
#include "config.h"
#include "counters.h"
#include "event.h"
#include "ether.h"
#include "if.h"
#include "inet.h"
#include "netmap.h"
#include "util.h"

extern int nohostring;
extern int verbose;

struct arp_head {
	LIST_HEAD(arplist_, arp)	arplist;
	int			maxtries;
	int			tdown;
	int			tkeep;
};

static void arp_del(struct arp *);

static struct arp_head arp_head_g;

/*
 * list arp entries.
 */
static int
arp_cli_list(char **buf, int *buflen, int *resid)
{
	const char *etheraddr;
	int err;
	struct arp *arp;
	struct arp_head *arp_head;
	time_t now;

	now = time(NULL);
	arp_head = &arp_head_g;
	LIST_FOREACH(arp, &arp_head->arplist, arp_next) {
		if ((arp->flags & ARP_VALID) == 0)
			etheraddr = "(incomplete)";
		else
			etheraddr = ether_ntoa(&arp->lladdr);
		err = printf_buf(buf, buflen, resid,
		    "? (%s) at %s on %s", inet_ntoa(arp->addr),
		    etheraddr, arp->nmif->nm_if_name);
		if (err != 0)
			break;
		if (arp->flags & ARP_PERMANENT)
			err = printf_buf(buf, buflen, resid, " permanent\n");
		else
			err = printf_buf(buf, buflen, resid,
			    " expire%s %ld second%s\n",
			    (arp->expire - now > 1) ? "s" : "",
			    arp->expire - now,
			    (arp->expire - now > 1) ? "s" : "");
		if (err != 0)
			break;
	}

	return (err);
}

/*
 * Parse arp cli arguments.
 */
static int
arp_cli_parse_args(struct cli_args *args, int *delete, int *deleteall,
	struct in_addr *host)
{
	int i, nargs;
	struct cli_arg *arg;

	arg = STAILQ_FIRST(&args->args_list);
	nargs = args->args - 1;
	while (nargs-- > 0) {
		arg = STAILQ_NEXT(arg, arg_next);
		if (arg == NULL || arg->len == 0)
			return (-2);
		if (*arg->arg != '-')
			break;
		for (i = 1; i < arg->len; i++) {
			if (*(arg->arg + i) == 'd')
				*delete = 1;
			if (*(arg->arg + i) == 'a')
				*deleteall = 1;
		}
	}
	if (*delete == 1 && *deleteall == 1)
		return (0);
	if (*delete == 0 || nargs == -1)
		return (-2);
	host->s_addr = inet_addr(arg->arg);
	if (host->s_addr == INADDR_BROADCAST)
		return (-2);

	return (0);
}

/*
 * delete all arp entries.
 */
static int
arp_cli_deleteall(void)
{
	struct arp *arp, *tmp;
	struct arp_head *arp_head;

	arp_head = &arp_head_g;
	LIST_FOREACH_SAFE(arp, &arp_head->arplist, arp_next, tmp) {
		if (arp->flags & ARP_PERMANENT)
			continue;
		arp_del(arp);
	}

	return (0);
}

/*
 * delete a single host from the arp table.
 */
static int
arp_cli_delete_host(struct in_addr *host)
{
	struct arp *arp, *tmp;
	struct arp_head *arp_head;

	arp_head = &arp_head_g;
	LIST_FOREACH_SAFE(arp, &arp_head->arplist, arp_next, tmp) {
		if (arp->flags & ARP_PERMANENT)
			continue;
		if (memcmp(&arp->addr, host, sizeof(arp->addr)) != 0)
			continue;
		arp_del(arp);
		break;
	}

	return (0);
}

/*
 * cli arp support.
 */
static int
arp_cli(struct cli *cli, struct cli_args *args)
{
	char *buf;
	int buflen, delete, deleteall, err, resid;
	struct in_addr host;

	resid = 0;
	buflen = BUFSZ;
	buf = (char *)malloc(BUFSZ);
	if (buf == NULL)
		exit(51);
	memset(buf, 0, buflen);

	if (args->args > 1) {
		delete = deleteall = 0;
		if (arp_cli_parse_args(args, &delete, &deleteall, &host) != 0)
			return (-2);
		if (deleteall)
			return (arp_cli_deleteall());
		if (delete)
			return (arp_cli_delete_host(&host));
	}
	err = arp_cli_list(&buf, &buflen, &resid);
	if (err == 0)
		err = cli_obuf_append(cli, buf, strlen(buf));
	free(buf);

	return (err);
}

static int
arp_cli_help(struct cli *cli, struct cli_args *args)
{
	const char *p;

	p = "arp -d host\t- delete ARP entry for host\n"
	    "arp -d -a\t- delete all ARP entries\n";
	if (cli_obuf_append(cli, p, strlen(p)) == -1)
		return (-1);

	return (0);
}

void
arp_init(void)
{
	struct arp_head *arp_head;

	arp_head = &arp_head_g;
	LIST_INIT(&arp_head->arplist);
	arp_head->maxtries = config_get_int("arp_max_tries");
	/* Time to keep incomplete entries - 20 seconds. */
	arp_head->tdown = 20;
	/* Time to keep valid entries - 20 minutes. */
	arp_head->tkeep = 60 * 20;

	/* Register the cli callback. */
	cli_cmd_add("arp", "arp - show ARP list\n", arp_cli, arp_cli_help);
}

static void
arp_del(struct arp *arp)
{

	LIST_REMOVE(arp, arp_next);
	if (arp->timer) {
		evtimer_del(arp->timer);
		event_free(arp->timer);
	}
	free(arp);
}

static void
arp_timer(int evfd, short event, void *data)
{
	struct arp *arp;

	(void)evfd;
	(void)event;
	arp = (struct arp *)data;
	arp_del(arp);
}

struct arp *
arp_add(struct nm_if *nmif, struct ether_addr *lladdr, struct in_addr *addr,
	int flags)
{
	struct arp *arp, *entry;
	struct arp_head *arp_head;
	struct ether_addr bcast;

	arp_head = &arp_head_g;
	/* Search for an existen entry. */
	entry = NULL;
	LIST_FOREACH(arp, &arp_head->arplist, arp_next) {
		if (memcmp(&arp->addr, addr, sizeof(arp->addr)) == 0) {
			entry = arp;
			break;
		}
	}
	if (entry == NULL) {
		/* New entry. */
		arp = (struct arp *)malloc(sizeof(*arp));
		if (arp == NULL)
			return (NULL);
		memset(arp, 0, sizeof(*arp));
		arp->nmif = nmif;
		memcpy(&arp->addr, addr, sizeof(arp->addr));
		arp->timer = evtimer_new(ev_get_base(), arp_timer, arp);
		if (arp->timer == NULL) {
			free(arp);
			return (NULL);
		}
		memcpy(&arp->lladdr, lladdr, sizeof(arp->lladdr));
		LIST_INSERT_HEAD(&arp_head->arplist, arp, arp_next);
	} else
		arp = entry;

	arp->flags |= flags;
	memset(&bcast, 0xff, sizeof(bcast));
	if (memcmp(lladdr, &bcast, sizeof(*lladdr)) != 0) {
		memcpy(&arp->lladdr, lladdr, sizeof(arp->lladdr));
		arp->flags |= ARP_VALID;
		arp->expire = time(NULL) + arp_head->tkeep;
		arp->tv_timer.tv_sec = arp_head->tkeep;
	} else {
		arp->expire = time(NULL) + arp_head->tdown;
		arp->tv_timer.tv_sec = arp_head->tdown;
	}

	if ((arp->flags & ARP_PERMANENT) == 0)
		evtimer_add(arp->timer, &arp->tv_timer);

	return (arp);
}

int
arp_search_if(struct nm_if *nmif, struct in_addr *addr, struct arp **lladdr)
{
	struct arp *arp;
	struct arp_head *arp_head;
	time_t now;

	now = time(NULL);
	arp_head = &arp_head_g;
	LIST_FOREACH(arp, &arp_head->arplist, arp_next) {
		if (arp->nmif != nmif)
			continue;
		if (memcmp(&arp->addr, addr, sizeof(arp->addr)) != 0)
			continue;
		if ((arp->flags & ARP_VALID) == 0) {
			/* Retry no more than once per second. */
			if (arp->expire - arp_head->tdown < now) {
				if (++arp->asked >= arp_head->maxtries)
					return (EHOSTDOWN);
				arp_request(nmif, addr);
				arp->expire = now + arp_head->tdown;
				arp->tv_timer.tv_sec = arp_head->tdown;
				evtimer_add(arp->timer, &arp->tv_timer);
			}
			return (EWOULDBLOCK);
		}
		/* Check if we need to renew the ARP entry. */
		if (arp->expire - arp_head->maxtries < now)
			arp_request(nmif, addr);
		*lladdr = arp;
		return (0);
	}
	arp_request(nmif, addr);

	return (EWOULDBLOCK);
}

static int
arp_send_reply(struct nm_if *nmif, struct ether_addr *ea, struct in_addr *src,
	struct in_addr *dst)
{
	struct arphdr *ah;

	ah = (struct arphdr *)malloc(arphdr_len2(ETHER_ADDR_LEN,
	    sizeof(in_addr_t)));
	memset(ah, 0, arphdr_len2(ETHER_ADDR_LEN, sizeof(in_addr_t)));
	ah->ar_hrd = ntohs(ARPHRD_ETHER);
	ah->ar_pro = ntohs(ETHERTYPE_IP);
	ah->ar_hln = ETHER_ADDR_LEN;
	ah->ar_pln = sizeof(in_addr_t);
	ah->ar_op = ntohs(ARPOP_REPLY);
	memcpy(ar_sha(ah), LLADDR(&nmif->nm_if_dl), ETHER_ADDR_LEN);
	memcpy(ar_spa(ah), dst, sizeof(in_addr_t));
	memcpy(ar_tha(ah), ea, ETHER_ADDR_LEN);
	memcpy(ar_tpa(ah), src, sizeof(in_addr_t));

	/* Send the arp packet. */
	ether_output(nmif, dst, ea, ETHERTYPE_ARP, (char *)ah, arphdr_len(ah));
	free(ah);

	return (0);
}

int
arp_input(struct nm_if *nmif, int ring, char *buf, int len)
{
	struct arphdr *ah;
	struct in_addr dst, src;

	if (len < sizeof(struct arphdr)) {
		DPRINTF("%s: discarding the packet, too short (%d).\n",
		    __func__, len);
		pktcnt.arp_drop++;
		return (-1);
	}
	ah = (struct arphdr *)buf;
	if (len < arphdr_len(ah)) {
		DPRINTF("%s: discarding the packet, too short (%d).\n",
		    __func__, len);
		pktcnt.arp_drop++;
		return (-1);
	}
	if (ntohs(ah->ar_hrd) != ARPHRD_ETHER) {
		DPRINTF("%s: discarding non-ethernet packet.\n", __func__);
		pktcnt.arp_drop++;
		return (-1);
	}
	if (ntohs(ah->ar_pro) != ETHERTYPE_IP) {
		DPRINTF("%s: unsupported protocol %#04x, discarding packet.\n",
		    __func__, ntohs(ah->ar_pro));
		pktcnt.arp_drop++;
		return (-1);
	}
	if (ah->ar_hln != ETHER_ADDR_LEN) {
		DPRINTF("%s: unsupported hardware length (%d), discarding packet.\n",
		    __func__, ah->ar_hln);
		pktcnt.arp_drop++;
		return (-1);
	}
	if (ah->ar_pln != sizeof(in_addr_t)) {
		DPRINTF("%s: unsupported protocol length (%d), discarding packet.\n",
		    __func__, ah->ar_pln);
		pktcnt.arp_drop++;
		return (-1);
	}
	memcpy(&dst, ar_tpa(ah), sizeof(dst));
	memcpy(&src, ar_spa(ah), sizeof(src));
	switch (ntohs(ah->ar_op)) {
	case ARPOP_REQUEST:
		if (NETMAP_HOST_RING(NETMAP_PARENTIF(nmif), ring))
			break;
		if (!inet_our_addr(&dst))
			return (0);	/* Not for us. */
		arp_add(nmif, (struct ether_addr *)ar_sha(ah), &src, 0);
		if (nohostring)
			arp_send_reply(nmif, (struct ether_addr *)ar_sha(ah),
			    &src, &dst);
		pktcnt.arp_whohas++;
		break;
	case ARPOP_REPLY:
		arp_add(nmif, (struct ether_addr *)ar_sha(ah), &src, 0);
		pktcnt.arp_reply++;
		break;
	default:
		DPRINTF("%s: ARP operation not supported, discarding packet.\n",
		    __func__);
		pktcnt.arp_drop++;
		return (-1);
	}

	return (1);
}

int
arp_request(struct nm_if *nmif, struct in_addr *dst)
{
	struct arphdr *ah;
	struct ether_header bcast;
	struct inet_addr *addr;

	addr = inet_get_if_addr(nmif);
	if (addr == NULL) {
		DPRINTF("%s: no IP for %s\n", __func__, nmif->nm_if_name);
		return (-1);
	}
	ah = (struct arphdr *)malloc(arphdr_len2(ETHER_ADDR_LEN,
	    sizeof(in_addr_t)));
	memset(ah, 0, arphdr_len2(ETHER_ADDR_LEN, sizeof(in_addr_t)));
	ah->ar_hrd = ntohs(ARPHRD_ETHER);
	ah->ar_pro = ntohs(ETHERTYPE_IP);
	ah->ar_hln = ETHER_ADDR_LEN;
	ah->ar_pln = sizeof(in_addr_t);
	ah->ar_op = ntohs(ARPOP_REQUEST);
	memcpy(ar_sha(ah), LLADDR(&nmif->nm_if_dl), ETHER_ADDR_LEN);
	memcpy(ar_spa(ah), &addr->addr.sin_addr, sizeof(in_addr_t));
	memcpy(ar_tpa(ah), dst, sizeof(in_addr_t));

	/* Add an ARP entry. */
	memset(&bcast, 0xff, sizeof(bcast));
	arp_add(nmif, (struct ether_addr *)&bcast, dst, 0);

	/* Send the arp packet. */
	ether_output(nmif, dst, (struct ether_addr *)&bcast, ETHERTYPE_ARP,
	    (char *)ah, arphdr_len(ah));
	free(ah);

	return (0);
}
