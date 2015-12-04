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

#if 0	/** turned off for now while I play with the dpdk IP checksum code */

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

inline uint16_t 
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

#else

/**
 * 
 * Code from DPDK librte_net (BSD-licensed)
 * http://dpdk.org/browse/dpdk/tree/lib/librte_net/rte_ip.h
 */

/**
 * @internal Calculate a sum of all words in the buffer.
 * Helper routine for _raw_cksum().
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @param sum
 *   Initial value of the sum.
 * @return
 *   sum += Sum of all words in the buffer.
 */
static inline uint32_t
__rte_raw_cksum(const void *buf, size_t len, uint32_t sum)
{
        /* workaround gcc strict-aliasing warning */
        uintptr_t ptr = (uintptr_t)buf;
        const uint16_t *u16 = (const uint16_t *)ptr;

        while (len >= (sizeof(*u16) * 4)) {
                sum += u16[0];
                sum += u16[1];
                sum += u16[2];
                sum += u16[3];
                len -= sizeof(*u16) * 4;
                u16 += 4;
        }
        while (len >= sizeof(*u16)) {
                sum += *u16;
                len -= sizeof(*u16);
                u16 += 1;
        }

        /* if length is in odd bytes */
        if (len == 1)
                sum += *((const uint8_t *)u16);

        return sum;
}

/**
 * @internal Reduce a sum to the non-complemented checksum.
 * Helper routine for the raw_cksum().
 *
 * @param sum
 *   Value of the sum.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
__rte_raw_cksum_reduce(uint32_t sum)
{
        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        return (uint16_t)sum;
}

/**
 * Process the non-complemented checksum of a buffer.
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
_raw_cksum(const void *buf, size_t len)
{
        uint32_t sum;

        sum = __rte_raw_cksum(buf, len, 0);
        return __rte_raw_cksum_reduce(sum);
}

#if 0 /* NOT_USED_YET */
/**
 * Process the IPv4 checksum of an IPv4 header.
 *
 * The checksum field must be set to 0 by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
ipv4_cksum(const struct ipv4_hdr *ipv4_hdr)
{
        uint16_t cksum;
        cksum = _raw_cksum(ipv4_hdr, sizeof(struct ipv4_hdr));
        return (cksum == 0xffff) ? cksum : ~cksum;
}
#endif

inline uint16_t 
in_cksum(char *buf, int len)
{
	uint16_t cksum;
	cksum = _raw_cksum(buf, len);
	return (~cksum & 0xffff);
}

#endif


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
	case 0:
		pktcnt.ip_fwd++;
		break;
	case EWOULDBLOCK:
		/* Add packet to FIFO. */
//printf("%s: enqueue packet\n", __func__);
		break;
	case EHOSTDOWN:
		icmp_error(nmif, buf, len, ICMP_UNREACH, ICMP_UNREACH_HOST);
		return (0);
	}

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

	/* Ask ether_input to send the packet to host <-> hw bridge. */
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
