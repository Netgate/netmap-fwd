/*-
 * Copyright (c) 2015, ServerU Inc.
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "counters.h"
#include "icmp.h"
#include "if.h"
#include "inet.h"
#include "ip.h"
#include "netmap.h"
#include "util.h"

#define	ICMP_QUOTELEN		8

static int
icmp_reflect(struct nm_if *nmif, char *inbuf, int inlen)
{
	int hlen;
	struct icmp *icmp;
	struct ip *ip;
	struct in_addr t;
	struct inet_addr *broadaddr, *src;

	ip = (struct ip *)inbuf;
	if (IN_MULTICAST(ntohl(ip->ip_src.s_addr)) ||
	    IN_EXPERIMENTAL(ntohl(ip->ip_src.s_addr)) ||
	    IN_ZERONET(ntohl(ip->ip_src.s_addr)) ) {
		pktcnt.icmp_badaddr++;
		return (0);
	}

	t = ip->ip_dst;
	ip->ip_dst = ip->ip_src;

	/*
	 * If the incoming packet was addressed directly to one of our
	 * own addresses, use dst as the src for the reply.
	 */
	if (inet_our_addr(&t) != NULL)
		ip->ip_src = t;
	else if ((broadaddr = inet_our_broadcast(&t)) != NULL) {
		/*
		 * If the incoming packet was addressed to one of our broadcast
		 * addresses, use the non-broadcast address.
		 */
		ip->ip_src = broadaddr->addr.sin_addr;
	} else {
		/*
		 * Use the address from the interface where the ICMP packet
		 * come in.
		 */
		src = inet_get_if_addr(nmif);
		if (src == NULL)
			return (-1);
		ip->ip_src = src->addr.sin_addr;
	}

	ip->ip_ttl = IPDEFTTL;
	hlen = ip->ip_hl << 2;
	icmp = (struct icmp *)(inbuf + hlen);
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum(inbuf + hlen, inlen - hlen);

	return (ip_output(nmif, inbuf, inlen));
}

static int
icmp_reply(struct nm_if *nmif, char *inbuf, int inlen)
{
	struct icmp *icmp;
	struct ip *ip;

	ip = (struct ip *)inbuf;
	icmp = (struct icmp *)(inbuf + (ip->ip_hl << 2));
	icmp->icmp_type = ICMP_ECHOREPLY;
	pktcnt.icmp_reply++;

	return (icmp_reflect(nmif, inbuf, inlen));
}

int
icmp_input(struct nm_if *nmif, char *buf, int len)
{
	int icmp_len, hlen;
	struct icmp *icmp;
	struct ip *ip;

	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;
	icmp_len = len - hlen;
	if (icmp_len < ICMP_MINLEN || icmp_len < sizeof(struct icmphdr)) {
		dprintf("%s: packet too short, discading (%d).\n",
		    __func__, icmp_len);
		pktcnt.icmp_drop++;
		return (-1);
	}
	icmp = (struct icmp *)(buf + hlen);
	if (in_cksum(buf + hlen, len - hlen)) {
		dprintf("%s: bad checksum, discarding the packet.\n", __func__);
		pktcnt.icmp_drop++;
		return (-1);
	}

	if (icmp->icmp_type != ICMP_ECHO || icmp->icmp_code != 0) {
		dprintf("%s: unknown ICMP type and code, discading the packet (%#x:%d).\n",
		    __func__, icmp->icmp_type, icmp->icmp_code);
		pktcnt.icmp_unknown++;
		return (-1);
	}

	/* XXX - rate */
	pktcnt.icmp_echo++;

	return (icmp_reply(nmif, buf, len));
}

int
icmp_error(struct nm_if *nmif, char *buf, int len, int type, int code)
{
	char *nbuf;
	int err;
	struct icmp *icmp;
	struct ip *ip, *oip;
	unsigned int icmplen, icmpelen, nlen, oiphlen;

	if (type > ICMP_MAXTYPE) {
		dprintf("%s: invalid ICMP type: %d\n", __func__, type);
		return (-1);
	}

	oip = (struct ip *)buf;
	if (oip->ip_off & htons(~(IP_MF|IP_DF)))
		return (0);
	oiphlen = oip->ip_hl << 2;
	if (oiphlen + 8 > len)
		return (0);

	if (oip->ip_p == IPPROTO_ICMP && type != ICMP_REDIRECT &&
	    len >= oiphlen + ICMP_MINLEN &&
	    !ICMP_INFOTYPE(((struct icmp *)((caddr_t)oip + oiphlen))->icmp_type)) {
		pktcnt.icmp_old++;
		return (0);
	}


	icmpelen = MAX(8, MIN(ICMP_QUOTELEN, ntohs(oip->ip_len) - oiphlen));

	icmplen = MIN(oiphlen + icmpelen, len);
	if (icmplen < sizeof(struct ip))
		return (0);
	nlen = sizeof(struct ip) + ICMP_MINLEN + icmplen;
	nbuf = (char *)malloc(nlen);
	if (nbuf == NULL)
		return (ENOMEM);
	memset(nbuf, 0, nlen);

	/* Copy old IP header (without options). */
	memcpy(nbuf, buf, sizeof(struct ip));
	ip = (struct ip *)nbuf;
	ip->ip_len = htons(sizeof(struct ip) + ICMP_MINLEN + icmplen);
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_tos = 0;
	ip->ip_off = 0;

	icmp = (struct icmp *)(nbuf + (ip->ip_hl << 2));
	// inc_icmp[type];
	icmp->icmp_type = type;
	icmp->icmp_code = code;

	/* Copy the quotation into ICMP message. */
	memcpy(&icmp->icmp_ip, buf, icmplen);

	pktcnt.icmp_error++;

	err = icmp_reflect(nmif, nbuf, nlen);
	free(nbuf);

	return (err);
}
