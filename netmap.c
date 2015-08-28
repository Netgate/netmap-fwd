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

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "counters.h"
#include "ether.h"
#include "event.h"
#include "if.h"
#include "netmap.h"
#include "util.h"

static void
netmap_read(evutil_socket_t fd, short event, void *data)
{
	int i, rx;
	struct netmap_ring *ring;
	struct nm_if *nmif;

	rx = 0;
	nmif = (struct nm_if *)data;
	for (i = 0; i < nmif->nm_if_rx_rings; i++) {
		ring = NETMAP_RXRING(nmif->nm_if_ifp, i);
		while (!nm_ring_empty(ring)) {
			ether_input(nmif, NETMAP_GET_BUF(ring),
			    NETMAP_SLOT_LEN(ring));
			NETMAP_RING_NEXT(ring);
			rx++;
		}
	}
	if_netmap_txsync();
	if (rx > 0)
		netmap_rx_sync(nmif);
}

int
netmap_open(struct nm_if *nmif)
{
	struct nmreq nmreq;
	struct netmap_if *ifp;

	nmif->nm_if_fd = open("/dev/netmap", O_RDWR);
	if (nmif->nm_if_fd == -1) {
		perror("open");
		return (-1);
	}

	memset(&nmreq, 0, sizeof(nmreq));
	strcpy(nmreq.nr_name, nmif->nm_if_name);
	nmreq.nr_version = NETMAP_API;
	nmreq.nr_flags = NR_REG_ALL_NIC;

	if (ioctl(nmif->nm_if_fd, NIOCREGIF, &nmreq) == -1) {
		perror("ioctl");
		netmap_close(nmif);
		return (-1);
	}
dprintf("name: %s\n", nmreq.nr_name);
dprintf("version: %d\n", nmreq.nr_version);
dprintf("offset: %d\n", nmreq.nr_offset);
dprintf("memsize: %d\n", nmreq.nr_memsize);
dprintf("tx_slots: %d\n", nmreq.nr_tx_slots);
dprintf("rx_slots: %d\n", nmreq.nr_rx_slots);
dprintf("tx_rings: %d\n", nmreq.nr_tx_rings);
dprintf("rx_rings: %d\n", nmreq.nr_rx_rings);
dprintf("ringid: %#x\n", nmreq.nr_ringid);
dprintf("flags: %#x\n", nmreq.nr_flags);
	nmif->nm_if_memsize = nmreq.nr_memsize;
	nmif->nm_if_mem = mmap(NULL, nmif->nm_if_memsize,
	    PROT_READ | PROT_WRITE, MAP_SHARED, nmif->nm_if_fd, 0);
	if (nmif->nm_if_mem == MAP_FAILED) {
		perror("mmap");
		netmap_close(nmif);
		return (-1);
	}
	ifp = nmif->nm_if_ifp = NETMAP_IF(nmif->nm_if_mem, nmreq.nr_offset);
	nmif->nm_if_rx_rings = ifp->ni_rx_rings;
	nmif->nm_if_tx_rings = ifp->ni_tx_rings;
	nmif->nm_if_ev_read = event_new(ev_get_base(), nmif->nm_if_fd,
	    EV_READ | EV_PERSIST, netmap_read, nmif);
	event_add(nmif->nm_if_ev_read, NULL);

	return (0);
}

int
netmap_close(struct nm_if *nmif)
{

	if (nmif->nm_if_ev_read != NULL) {
		event_del(nmif->nm_if_ev_read);
		event_free(nmif->nm_if_ev_read);
		nmif->nm_if_ev_read = NULL;
	}
	if (nmif->nm_if_mem != NULL && nmif->nm_if_memsize > 0) {
		munmap(nmif->nm_if_mem, nmif->nm_if_memsize);
		nmif->nm_if_mem = NULL;
		nmif->nm_if_memsize = 0;
	}
	if (nmif->nm_if_fd == -1)
		return (0);
	if (close(nmif->nm_if_fd) == -1) {
		perror("close");
		return (-1);
	}
	nmif->nm_if_fd = -1;

	return (0);
}

inline struct netmap_ring *
netmap_get_tx_ring(struct nm_if *nmif)
{
	int i;
	struct netmap_ring *ring;

	for (i = 0; i < nmif->nm_if_tx_rings; i++) {
		ring = NETMAP_TXRING(nmif->nm_if_ifp, i);
		if (!nm_ring_empty(ring))
			return (ring);
	}

	return (NULL);
}

int
netmap_rx_sync(struct nm_if *nmif)
{

	if (ioctl(nmif->nm_if_fd, NIOCRXSYNC, NULL) == -1) {
		perror("ioctl");
		return (-1);
	}

	return (0);
}

int
netmap_tx_sync(struct nm_if *nmif)
{

	if (ioctl(nmif->nm_if_fd, NIOCTXSYNC, NULL) == -1) {
		perror("ioctl");
		return (-1);
	}

	return (0);
}
