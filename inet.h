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

#include "radix.h"

struct inet_addr {
	STAILQ_ENTRY(inet_addr)	addr_next;
	struct sockaddr_in	addr;
	struct sockaddr_in	broadaddr;
	struct sockaddr_in	mask;
	struct nm_if		*nmif;
};

struct inet_rtentry {
	struct radix_node	rn[2];
#define	rt_key(r)	(*((struct sockaddr **)(&(r)->rn->rn_key)))
#define	rt_mask(r)	(*((struct sockaddr **)(&(r)->rn->rn_mask)))
	struct sockaddr_in	dst;		/* destination */
	struct sockaddr_in	mask;		/* netmask */
	struct sockaddr_in	gw;		/* gateway */
	struct nm_if		*nmif;		/* interface pointer */
	int			flags;		/* route flags */
};

#define	RTF_UP		0x1		/* route usable */
#define	RTF_GATEWAY	0x2		/* destination is a gateway */
#define	RTF_HOST	0x4		/* host entry (net otherwise) */
#define	RTF_STATIC	0x800		/* manually added */

int inet_init(void);

/* Route functions. */
int inet_addroute(struct sockaddr_in *, struct sockaddr_in *,
	struct sockaddr_in *, int, struct nm_if *);
struct inet_rtentry *inet_match(struct in_addr *);

/* IPv4 functions. */
void inet_addr_add(struct inet_addr *);
void inet_addr_del(struct inet_addr *);
int inet_add_if_print(struct nm_if *, char **, int *, int *);
void inet_addr_if_free(struct nm_if *);
struct inet_addr *inet_get_if_addr(struct nm_if *);
struct inet_addr *inet_our_addr(struct in_addr *);
struct inet_addr *inet_our_broadcast(struct in_addr *);
