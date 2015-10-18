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

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <errno.h>
#include <stdio.h>

#include "cli.h"
#include "counters.h"
#include "ether.h"
#include "icmp.h"
#include "if.h"
#include "inet.h"
#include "ip.h"
#include "netmap.h"
#include "util.h"

extern int nohostring;
static int ip_id = 1;

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

int
in_cksum(char *buf, int len)
{
	register int sum;
	register u_short *w;

	union {
		char	c[2];
		u_short	s;
	} s_util;
	union {
		u_short	s[2];
		long	l;
	} l_util;

	w = (u_short *)buf;
	sum = 0;
	while ((len -= 32) >= 0) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
		w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		w += 4;
	}
	len += 8;
	REDUCE;
	while ((len -= 2) >= 0) {
		sum += *w++;
	}
	if (len == -1) {
		s_util.c[0] = *(char *)w;
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;

	return (~sum & 0xffff);
}

static int
ip_fwd(struct nm_if *nmif, char *buf, int len)
{
	int err;
	struct ip *ip;
	struct inet_rtentry *rt;

	ip = (struct ip *)buf;
	rt = inet_match(&ip->ip_dst);
	if (rt == NULL) {
		DPRINTF("%s: no route for host (dst: %s)\n",
		    __func__, inet_ntoa(ip->ip_dst));
		return (-1);
	}

	if (ip->ip_ttl <= IPTTLDEC) {
		icmp_error(nmif, buf, len, ICMP_TIMXCEED,
		    ICMP_TIMXCEED_INTRANS);
		return (-1);
	}

	/*
	 * Decrement the TTL and incrementally change the IP header checksum.
	 * Don't bother doing this with hw checksum offloading, it's faster
	 * doing it right here.
	 */
	ip->ip_ttl -= IPTTLDEC;
	if (ip->ip_sum >= (u_int16_t) ~htons(IPTTLDEC << 8))
		ip->ip_sum -= ~htons(IPTTLDEC << 8);
	else
		ip->ip_sum += htons(IPTTLDEC << 8);

	if (rt->flags & RTF_GATEWAY)
		err = ether_output(rt->nmif, &rt->gw.sin_addr, NULL,
		    ETHERTYPE_IP, buf, len);
	else
		err = ether_output(rt->nmif, &ip->ip_dst, NULL, ETHERTYPE_IP,
		    buf, len);
	switch (err) {
	case EWOULDBLOCK:
		/* Add packet to FIFO. */
//printf("%s: enqueue packet\n", __func__);
		break;
	case EHOSTDOWN:
		icmp_error(nmif, buf, len, ICMP_UNREACH, ICMP_UNREACH_HOST);
		return (0);
	}

	pktcnt.ip_fwd++;

	return (0);
}

int
ip_input(struct nm_if *nmif, int ring, char *buf, int len)
{
	int hlen, ip_len;
	struct ip *ip;

	if (len < sizeof(*ip)) {
		DPRINTF("%s: discard packet, too short (%d).\n", __func__, len);
		pktcnt.ip_drop++;
		return (-1);
	}
	ip = (struct ip *)buf;
	if (ip->ip_v != IPVERSION) {
		DPRINTF("%s: discard packet, bad ver (%#x).\n",
		    __func__, ip->ip_v);
		pktcnt.ip_drop++;
		return (-1);
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) { /* minimum header length */
		DPRINTF("%s: discard packet, bad header len (%d).\n",
		    __func__, len);
		pktcnt.ip_drop++;
		return (-1);
	}
	if (in_cksum(buf, hlen)) {
		DPRINTF("%s: bad checksum, discarding the packet.\n", __func__);
		pktcnt.ip_drop++;
		return (-1);
	}
	ip_len = ntohs(ip->ip_len);
	if (ip_len < hlen || ip_len > len) {
		DPRINTF("%s: discard packet, bad ip len (%d).\n",
		    __func__, len);
		pktcnt.ip_drop++;
		return (-1);
	}

	/* Discard packet addressed to 127/8. */
	if ((ntohl(ip->ip_dst.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    (ntohl(ip->ip_src.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) {
		DPRINTF("%s: bad address (127/8), discanding the packet.\n",
		    __func__);
		pktcnt.ip_drop++;
		return (-1);
	}

	/* Only IP packets without options. */
	if (ip->ip_hl != (sizeof(struct ip) >> 2)) {
		pktcnt.ip_drop++;
		return (-1);
		/* XXX - Fallback */
	}

	/* Only unicast IP on fast forward routing. */
	if (!NETMAP_HOST_RING(NETMAP_PARENTIF(nmif), ring) &&
	    inet_our_addr(&ip->ip_dst) == 0 &&
	    inet_our_broadcast(&ip->ip_dst) == 0 &&
	    ntohl(ip->ip_src.s_addr) != (u_long)INADDR_BROADCAST &&
	    ntohl(ip->ip_dst.s_addr) != (u_long)INADDR_BROADCAST &&
	    IN_MULTICAST(ntohl(ip->ip_src.s_addr)) == 0 &&
	    IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) == 0 &&
	    IN_LINKLOCAL(ntohl(ip->ip_src.s_addr)) == 0 &&
	    IN_LINKLOCAL(ntohl(ip->ip_dst.s_addr)) == 0 &&
	    ip->ip_src.s_addr != INADDR_ANY &&
	    ip->ip_dst.s_addr != INADDR_ANY)
		return (ip_fwd(nmif, buf, len));

	if (nohostring && ip->ip_p == IPPROTO_ICMP) {
		pktcnt.ip_icmp++;
		return (icmp_input(nmif, buf, len));
	}

	/* Ask to ether_input to send the packet to host <-> hw bridge. */
	return (1);
}

int
ip_output(struct nm_if *nmif, char *inbuf, int inlen)
{
	struct ip *ip;

	ip = (struct ip *)inbuf;
	ip->ip_v = IPVERSION;
	ip->ip_id = htons(ip_id++);
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(inbuf, ip->ip_hl << 2);

	return (ether_output(nmif, &ip->ip_dst, NULL, ETHERTYPE_IP, inbuf,
	    inlen));
}
