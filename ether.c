/*-
 * Copyright (c) 2015, Luiz Otavio O Souza <loos@FreeBSD.org>
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

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <stdio.h>
#include <string.h>
#include <libutil.h>	/* XXX - hexdump */

#include "if.h"
#include "arp.h"
#include "counters.h"
#include "ether.h"
#include "icmp.h"
#include "ip.h"
#include "netmap.h"
#include "util.h"

extern int nohostring;
extern int verbose;

void
ether_bridge(struct nm_if *nmif, int ring, char *inbuf, int len)
{
	char *buf;
	struct netmap_if *ifp;
	struct netmap_ring *nring;
	struct nm_if *parentif;

	parentif = NETMAP_PARENTIF(nmif);
	ifp = parentif->nm_if_ifp;
	if (NETMAP_HOST_RING(parentif, ring))
		nring = netmap_hw_tx_ring(ifp);
	else
		nring = NETMAP_TXRING(ifp, ifp->ni_tx_rings);

	buf = NETMAP_GET_BUF(nring);
	if (buf == NULL) {
		DPRINTF("%s: no available buffer for tx (%s).\n",
		    __func__, nmif->nm_if_name);
		parentif->nm_if_txsync = 1;
		pktcnt.tx_drop++;
		return;
	}
	/* Copy the payload. */
	memcpy(buf, inbuf, len);

	NETMAP_UPDATE_LEN(nring, len);

	/* Update the current ring slot. */
	NETMAP_RING_NEXT(nring);

	pktcnt.tx_pkts++;
	parentif->nm_if_txsync = 1;
}

int
ether_input(struct nm_if *nmif, int ring, char *buf, int len)
{
	int err;
	struct ether_header *eh;
	struct ether_vlan_header *evl;
	struct nm_if_vlan *vlan;

	if (len < ETHER_HDR_LEN) {
		DPRINTF("%s: discarding packet, too short.\n", __func__);
		pktcnt.rx_drop++;
		return (-1);
	}
	err = 0;
	eh = (struct ether_header *)buf;
	switch (ntohs(eh->ether_type)) {
	case ETHERTYPE_ARP:
		pktcnt.rx_arp++;
		err = arp_input(nmif, ring, buf + ETHER_HDR_LEN,
		    len - ETHER_HDR_LEN);
		break;
	case ETHERTYPE_IP:
		pktcnt.rx_ip++;
		err = ip_input(nmif, ring, buf + ETHER_HDR_LEN,
		    len - ETHER_HDR_LEN);
		break;
	case ETHERTYPE_VLAN:
		//pktcnt.rx_vlan++;
		if (len < ETHER_VLAN_ENCAP_LEN) {
			DPRINTF("%s: discarding vlan packet, too short.\n",
			    __func__);
			pktcnt.rx_drop++;
			return (-1);
		}
		evl = (struct ether_vlan_header *)buf;
		vlan = if_find_vlan(nmif, ntohs(evl->evl_tag));
		if (vlan == NULL) {
			pktcnt.rx_drop++;
			DPRINTF("%s: unknown vlan tag %d, discanding packet.\n",
			    __func__, ntohs(evl->evl_tag));
			return (-1);
		}
		memmove(buf + ETHER_VLAN_ENCAP_LEN, buf, ETHER_ADDR_LEN * 2);
		err = ether_input(vlan->nmif, ring, buf + ETHER_VLAN_ENCAP_LEN,
		    len - ETHER_VLAN_ENCAP_LEN);
		if (!nohostring && err == 1) {
			memmove(buf, buf + ETHER_VLAN_ENCAP_LEN,
			    ETHER_ADDR_LEN * 2);
			evl = (struct ether_vlan_header *)buf;
			evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
			evl->evl_tag = htons(vlan->nmif->nm_if_vtag);
			ether_bridge(vlan->nmif, ring, buf, len);
			return (0);
		}
		break;
	default:
		pktcnt.rx_drop++;
		DPRINTF("%s: protocol %#04x not supported, discanding packet.\n",
		    __func__, ntohs(eh->ether_type));
		err = -1;
	}

	return (err);
}

int
ether_output(struct nm_if *nmif, struct in_addr *dst, struct ether_addr *lladdr,
	unsigned short ether_type, char *inbuf, int inlen)
{
	char *buf;
	int err, len;
	struct arp *arp;
	struct ether_header *eh;
	struct ether_vlan_header *evl;
	struct netmap_ring *ring;
	struct nm_if *parentif;

	if (lladdr == NULL) {
		err = arp_search_if(nmif, dst, &arp);
		if (err != 0)
			return (err);
	}

	parentif = NETMAP_PARENTIF(nmif);
	ring = netmap_hw_tx_ring(parentif->nm_if_ifp);
	if (ring == NULL) {
		DPRINTF("%s: no available ring for tx (%s).\n",
		    __func__, parentif->nm_if_name);
		parentif->nm_if_txsync = 1;
		pktcnt.tx_drop++;
		return (-1);
	}
	if (inlen + ETHER_HDR_LEN > ring->nr_buf_size) {
		DPRINTF("%s: buffer too big, cannot tx.\n", __func__);
		pktcnt.tx_drop++;
		return (-1);
	}
	buf = NETMAP_GET_BUF(ring);
	if (buf == NULL) {
		DPRINTF("%s: no available buffer for tx (%s).\n",
		    __func__, parentif->nm_if_name);
		parentif->nm_if_txsync = 1;
		pktcnt.tx_drop++;
		return (-1);
	}

	if (NETMAP_VLANIF(nmif)) {
		/* Copy the ethernet vlan header. */
		evl = (struct ether_vlan_header *)buf;
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = htons(nmif->nm_if_vtag);
		evl->evl_proto = htons(ether_type);
		if (lladdr != NULL)
			memcpy(evl->evl_dhost, lladdr, sizeof(evl->evl_dhost));
		else
			memcpy(evl->evl_dhost, &arp->lladdr,
			    sizeof(evl->evl_dhost));
		memcpy(evl->evl_shost, LLADDR(&nmif->nm_if_dl),
		    sizeof(evl->evl_shost));
		len = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		/* Copy the ethernet header. */
		eh = (struct ether_header *)buf;
		eh->ether_type = htons(ether_type);
		if (lladdr != NULL)
			memcpy(eh->ether_dhost, lladdr,
			    sizeof(eh->ether_dhost));
		else
			memcpy(eh->ether_dhost, &arp->lladdr,
			    sizeof(eh->ether_dhost));
		memcpy(eh->ether_shost, LLADDR(&nmif->nm_if_dl),
		    sizeof(eh->ether_shost));
		len = ETHER_HDR_LEN;
	}

	/* Copy the payload. */
	memcpy(buf + len, inbuf, inlen);
	len += inlen;

	NETMAP_UPDATE_LEN(ring, len);

//DPRINTF("%s: len: %d\n", __func__, len);
//if (verbose) hexdump(buf, len, NULL, 0);

	/* Update the current ring slot. */
	NETMAP_RING_NEXT(ring);

	pktcnt.tx_pkts++;
	parentif->nm_if_txsync = 1;

	return (0);
}
