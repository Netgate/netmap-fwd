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

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <netinet/in.h>

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arp.h"
#include "cleanup.h"
#include "cli.h"
#include "if.h"
#include "inet.h"
#include "netmap.h"
#include "util.h"

#define	IFFBITS \
"\020\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5POINTOPOINT\7RUNNING" \
"\10NOARP\11PROMISC\12ALLMULTI\13OACTIVE\14SIMPLEX\15LINK0\16LINK1\17LINK2" \
"\20MULTICAST\22PPROMISC\23MONITOR\24STATICARP"

#define	IFCAPBITS \
"\020\1RXCSUM\2TXCSUM\3NETCONS\4VLAN_MTU\5VLAN_HWTAGGING\6JUMBO_MTU\7POLLING" \
"\10VLAN_HWCSUM\11TSO4\12TSO6\13LRO\14WOL_UCAST\15WOL_MCAST\16WOL_MAGIC" \
"\17TOE4\20TOE6\21VLAN_HWFILTER\23VLAN_HWTSO\24LINKSTATE\25NETMAP" \
"\26RXCSUM_IPV6\27TXCSUM_IPV6"

struct discaps {
	int cap;
	const char *label;
};

static struct discaps discaps[] = {
	{ IFCAP_RXCSUM,	"rxcsum" },
	{ IFCAP_TXCSUM,	"txcsum" },
	{ IFCAP_TSO4,	"tso4" },
	{ IFCAP_TSO6,	"tso6" },
	{ IFCAP_LRO,	"lro" },
};

static STAILQ_HEAD(nm_ifs_, nm_if) nm_ifs;

static int
if_setcaps(struct nm_if *nmif, int value)
{
	int flags, s;
	struct ifreq ifr;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return (-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nmif->nm_if_name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl");
		goto error;
	}
        if (ioctl(s, SIOCGIFCAP, (caddr_t)&ifr) == -1) {
		perror("ioctl");
		goto error;
	}
	flags = ifr.ifr_curcap;
	if (value < 0) {
		value = -value;
		flags &= ~value;
	} else
		flags |= value;
	flags &= ifr.ifr_reqcap;
	ifr.ifr_reqcap = flags;
        if (ioctl(s, SIOCSIFCAP, (caddr_t)&ifr) == -1) {
		perror("ioctl");
		goto error;
	}
	close(s);

	return (0);

error:
	close(s);
	return (-1);
}

static int
if_getdata(struct nm_if *nmif)
{
	int s;
	struct ifreq ifr;
	struct vlanreq vreq;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return (-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nmif->nm_if_name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl");
		goto error;
	}
	nmif->nm_if_flags = (ifr.ifr_flags & 0xffff) |
	    (ifr.ifr_flagshigh << 16);
        if (ioctl(s, SIOCGIFCAP, (caddr_t)&ifr) == -1) {
		perror("ioctl");
		goto error;
	}
	nmif->nm_if_caps = ifr.ifr_curcap;
	if (ioctl(s, SIOCGIFMETRIC, &ifr) == -1) {
		perror("ioctl");
		goto error;
	}
	nmif->nm_if_metric = ifr.ifr_metric;
	if (ioctl(s, SIOCGIFMTU, &ifr) == -1) {
		perror("ioctl");
		goto error;
	}
	nmif->nm_if_mtu = ifr.ifr_mtu;

	/* Get vlan tag and parent. */
	if (nmif->nm_if_dl.sdl_type == IFT_L2VLAN) {
		memset(&vreq, 0, sizeof(vreq));
		ifr.ifr_data = (caddr_t)&vreq;
		if (ioctl(s, SIOCGETVLAN, &ifr) == -1)
			goto error;
		nmif->nm_if_vtag = vreq.vlr_tag;
		strlcpy(nmif->nm_if_vparent, vreq.vlr_parent,
		    sizeof(nmif->nm_if_vparent));
	}
	close(s);

	return (0);

error:
	close(s);
	return (-1);
}

static struct nm_if *
if_add(const char *ifname)
{
	struct nm_if *nmif;

	nmif = (struct nm_if *)malloc(sizeof(*nmif));
	if (nmif == NULL)
		return (NULL);
	memset(nmif, 0, sizeof(*nmif));
	nmif->nm_if_fd = -1;
	STAILQ_INIT(&nmif->nm_if_vlans);
	strlcpy(nmif->nm_if_name, ifname, sizeof(nmif->nm_if_name));
	STAILQ_INSERT_TAIL(&nm_ifs, nmif, nm_if_next);

	return (nmif);
}

static struct inet_addr *
if_add_inet_addr(struct nm_if *nmif, struct ifaddrs *ifa)
{
	struct inet_addr *addr;
	struct sockaddr_in netaddr;

	addr = (struct inet_addr *)malloc(sizeof(*addr));
	if (addr == NULL)
		return (NULL);
	memset(addr, 0, sizeof(*addr));
	memcpy(&addr->addr, ifa->ifa_addr, sizeof(addr->addr));
	memcpy(&addr->mask, ifa->ifa_netmask, sizeof(addr->mask));
	if (ifa->ifa_flags & IFF_BROADCAST)
		memcpy(&addr->broadaddr, ifa->ifa_broadaddr,
		    sizeof(addr->broadaddr));
	addr->nmif = nmif;

	/* Add the network route. */
	if (addr->mask.sin_addr.s_addr != INADDR_BROADCAST) {
		memcpy(&netaddr, &addr->addr, sizeof(netaddr));
		netaddr.sin_addr.s_addr = addr->addr.sin_addr.s_addr &
		    addr->mask.sin_addr.s_addr;
		if (inet_addroute(&netaddr, NULL, &addr->mask, 0, nmif) != 0) {
			free(addr);
			return (NULL);
		}
	}
	/* Add the host route. */
	if (inet_addroute(&addr->addr, NULL, &addr->mask, RTF_HOST,
	    nmif) != 0) {
		free(addr);
		return (NULL);
	}
	/* Add the ARP entry for this internet address. */
	arp_add(nmif, (struct ether_addr *)LLADDR(&nmif->nm_if_dl),
	    &addr->addr.sin_addr, ARP_PERMANENT);

	/* Add the address to list of address. */
	inet_addr_add(addr);
	nmif->nm_if_naddrs++;

	return (addr);
}

static void
if_del(struct nm_if *nmif)
{
	struct nm_if_vlan *vlan, *vtmp;

	STAILQ_FOREACH_SAFE(vlan, &nmif->nm_if_vlans, nm_if_vlan_next, vtmp) {
		STAILQ_REMOVE(&nmif->nm_if_vlans, vlan, nm_if_vlan,
		    nm_if_vlan_next);
		free(vlan);
	}
	STAILQ_REMOVE(&nm_ifs, nmif, nm_if, nm_if_next);
	if (nmif->nm_if_dis_caps != 0)
		if_setcaps(nmif, nmif->nm_if_dis_caps);
	inet_addr_if_free(nmif);
	free(nmif);
}

static struct nm_if *
if_get(const char *ifname)
{
	struct nm_if *nmif;

	STAILQ_FOREACH(nmif, &nm_ifs, nm_if_next) {
		if (strcmp(nmif->nm_if_name, ifname) == 0)
			return (nmif);
	}

	return (NULL);
}

static struct nm_if_vlan *
if_add_vlan(struct nm_if *nmif)
{
	struct nm_if_vlan *vlan;

	vlan = (struct nm_if_vlan *)malloc(sizeof(*vlan));
	if (vlan == NULL)
		return (NULL);
	memset(vlan, 0, sizeof(*vlan));
	vlan->vlan_tag = nmif->nm_if_vtag;
	vlan->nmif = nmif;
	STAILQ_INSERT_TAIL(&nmif->nm_if_parentif->nm_if_vlans, vlan,
	    nm_if_vlan_next);

	return (vlan);
}

static void
if_debug_buf(struct nm_if *nmif, char **buf, int *buflen)
{
	int resid;

	resid = 0;
	printf_buf(buf, buflen, &resid, "%s: ", nmif->nm_if_name);
	printb(buf, buflen, &resid, "flags", nmif->nm_if_flags, IFFBITS);
	printf_buf(buf, buflen, &resid, " metric %d mtu %d\n",
	    nmif->nm_if_metric, nmif->nm_if_mtu);
	printf_buf(buf, buflen, &resid, "\t");
	printb(buf, buflen, &resid, "options", nmif->nm_if_caps, IFCAPBITS);
	printf_buf(buf, buflen, &resid, "\n");
	printf_buf(buf, buflen, &resid, "\tether: %s\n",
	    ether_ntoa((struct ether_addr *)LLADDR(&nmif->nm_if_dl)));
	if (inet_add_if_print(nmif, buf, buflen, &resid) == -1)
		return;
	if (nmif->nm_if_dl.sdl_type == IFT_L2VLAN) {
		printf_buf(buf, buflen, &resid,
		    "\tvlan: %d parent interface: %s\n",
		    nmif->nm_if_vtag, nmif->nm_if_vparent);
	}
}

static void
if_print(struct nm_if *nmif)
{
	char *buf;
	int buflen;

	buflen = BUFSZ;
	buf = (char *)malloc(buflen);
	if (buf == NULL)
		exit(51);
	memset(buf, 0, buflen);
	if_debug_buf(nmif, &buf, &buflen);
	printf("%s", buf);
	free(buf);
}

static int
if_cli_ifconfig(struct cli *cli, struct cli_args *args)
{
	char *buf;
	int buflen;
	struct nm_if *nmif;

	buflen = BUFSZ;
	buf = (char *)malloc(buflen);
	if (buf == NULL)
		exit(51);
	memset(buf, 0, buflen);
	STAILQ_FOREACH(nmif, &nm_ifs, nm_if_next) {
		if (if_getdata(nmif) == -1) {
			free(buf);
			return (-1);
		}
		if_debug_buf(nmif, &buf, &buflen);
		if (cli_obuf_append(cli, buf, strlen(buf)) == -1) {
			free(buf);
			return (-1);
		}
		memset(buf, 0, buflen);
	}
	free(buf);

	return (0);
}

static int
if_check_interface(struct nm_if *nmif)
{

	if (nmif->nm_if_dl.sdl_type != IFT_ETHER &&
	    nmif->nm_if_dl.sdl_type != IFT_L2VLAN &&
	    nmif->nm_if_dl.sdl_type != IFT_BRIDGE)
		return (ENOTSUP);
	if (nmif->nm_if_naddrs == 0)
		return (ENOENT);

	return (0);
}

static int
if_check_vlan(struct nm_if *nmif)
{
	struct nm_if_vlan *vlan;
	struct nm_if *parentif;

	if (nmif->nm_if_dl.sdl_type != IFT_L2VLAN)
		return (0);
	if (*nmif->nm_if_vparent == '\0') {
		printf("vlan with no parent interface\n");
		return (-1);
	}
	parentif = nmif->nm_if_parentif = if_get(nmif->nm_if_vparent);
	if (nmif->nm_if_parentif == NULL) {
		/* Open the parent interface. */
		if (if_open(nmif->nm_if_vparent) == -1)
			return (-1);
		parentif = nmif->nm_if_parentif = if_get(nmif->nm_if_vparent);
	}
	vlan = if_add_vlan(nmif);
	if (vlan == NULL)
		return (-1);
	if (parentif->nm_if_caps & IFCAP_VLAN_HWTAGGING) {
		parentif->nm_if_dis_caps |= IFCAP_VLAN_HWTAGGING;
		printf(
		    "disabling vlan hardware tagging on parent interface (%s)\n",
		    parentif->nm_if_name);
		if (if_setcaps(parentif, -IFCAP_VLAN_HWTAGGING) == -1)
			return (-1);
	}

	return (0);
}

static int
if_getaddrs(struct nm_if *nmif)
{
	struct ifaddrs *ifa, *ifaddrs;
	struct sockaddr *sa;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifaddrs) != 0) {
		perror("getifaddrs");
		return (-1);
	}
	/* Get the link layer address for this interface first. */
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, nmif->nm_if_name) != 0)
			continue;
		if ((sa = ifa->ifa_addr) == NULL)
			continue;
		switch (sa->sa_family) {
		case AF_LINK:
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl == NULL)
				continue;
			if (sdl->sdl_alen == ETHER_ADDR_LEN &&
			    (sdl->sdl_type == IFT_ETHER ||
			    sdl->sdl_type == IFT_L2VLAN ||
			    sdl->sdl_type == IFT_BRIDGE)) {
				memcpy(&nmif->nm_if_dl, sdl,
				    sizeof(nmif->nm_if_dl));
			}
			break;
		default:
			continue;
		}
	}
	/* And now the inet addresses. */
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, nmif->nm_if_name) != 0)
			continue;
		if ((sa = ifa->ifa_addr) == NULL)
			continue;
		switch (sa->sa_family) {
		case AF_INET:
			if (if_add_inet_addr(nmif, ifa) == NULL) {
				printf("error: cannot set the IP address\n");
				freeifaddrs(ifaddrs);
				return (-1);
			}
			break;
		default:
			continue;
		}
	}
	freeifaddrs(ifaddrs);

	return (0);
}

static void
if_cleanup(void *unused)
{
	struct nm_if *nmif, *tmp;

	STAILQ_FOREACH_SAFE(nmif, &nm_ifs, nm_if_next, tmp) {
		if (nmif->nm_if_fd != -1)
			netmap_close(nmif);
		if_del(nmif);
	}
}

void
if_init(void)
{

	STAILQ_INIT(&nm_ifs);
	cleanup_add(if_cleanup, NULL);
	cli_cmd_add("ifconfig", "ifconfig - show interface configuration\n",
	    if_cli_ifconfig, NULL);
}

int
if_open(const char *ifname)
{
	int comma, err, i;
	struct nm_if *nmif;

	/* Check if interface is already open. */
	nmif = if_get(ifname);
	if (nmif != NULL)
		return (0);

	/* Add the interface to the interface list. */
	nmif = if_add(ifname);
	if (nmif == NULL)
		return (-1);
	/* Get the interface addresses. */
	if (if_getaddrs(nmif) == -1) {
		if_del(nmif);
		return (-1);
	}
	err = if_check_interface(nmif);
	if (err) {
		if_del(nmif);
		return (err);
	}
	/* Get the interface vlan information, flags, metric and MTU. */
	if (if_getdata(nmif) == -1) {
		if_del(nmif);
		return (-1);
	}
	err = if_check_vlan(nmif);
	if (err) {
		if_del(nmif);
		return (err);
	}

	if_print(nmif);

	/* Do not switch the interface if interface type != ETHER. */
	if (nmif->nm_if_dl.sdl_type != IFT_ETHER)
		return (0);

	/* Disable unwanted hw features. */
	for (i = 0; i < nitems(discaps); i++)
		if (nmif->nm_if_caps & discaps[i].cap)
			nmif->nm_if_dis_caps |= discaps[i].cap;
	if (nmif->nm_if_dis_caps != 0) {
		comma = 0;
		printf("disabling ");
		for (i = 0; i < nitems(discaps); i++) {
			if ((nmif->nm_if_dis_caps & discaps[i].cap) == 0)
				continue;
			if (comma == 1)
				printf(", ");
			printf("%s", discaps[i].label);
			comma = 1;
		}
		printf(" on physical interface.\n");
		if (if_setcaps(nmif, -nmif->nm_if_dis_caps) == -1)
			return (-1);
	}

	printf("switching interface %s to netmap mode.\n", nmif->nm_if_name);
	if (netmap_open(nmif) != 0) {
		if_del(nmif);
		return (-1);
	}

	return (0);
}

int
if_netmap_txsync(void)
{
	struct nm_if *nmif;

	/* Sync all the tx rings of netmap interfaces. */
	STAILQ_FOREACH(nmif, &nm_ifs, nm_if_next) {
		if (nmif->nm_if_txsync)
			if (netmap_tx_sync(nmif) == -1)
				return (-1);
	}

	return (0);
}

struct nm_if_vlan *
if_find_vlan(struct nm_if *nmif, int vlan_tag)
{
	struct nm_if_vlan *vlan;

	STAILQ_FOREACH(vlan, &nmif->nm_if_vlans, nm_if_vlan_next) {
		if (vlan->vlan_tag == (vlan_tag & EVL_VLID_MASK))
			return (vlan);
	}

	return (NULL);
}
