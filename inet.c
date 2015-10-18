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
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cleanup.h"
#include "cli.h"
#include "if.h"
#include "inet.h"
#include "util.h"

struct inet {
	struct radix_node_head	*rnh;
	STAILQ_HEAD(inet_addrs_, inet_addr)	inet_addrs;
};

struct inet_walktree_arg {
	char			**buf;
	int			*buflen;
	int			*resid;
};

struct fbits {
	u_long			b_mask;
	char			b_val;
	const char		*b_name;
};

static struct fbits fbits[] = {
	{ RTF_UP,	'U', "UP" },
	{ RTF_GATEWAY,	'G', "GATEWAY" },
	{ RTF_HOST,	'H', "HOST" },
	{ RTF_STATIC,	'S', "STATIC" },
	{ 0 , 0 }
};

static int inet_cli_route(struct cli *, struct cli_args *);
static int inet_cli_route_help(struct cli *, struct cli_args *);

/* Global inet structure. */
static struct inet g_inet;

static int
inet_route_cleanup_cb(struct radix_node *rn, void *varg)
{
	struct inet *inet;
	struct inet_rtentry *entry;

	inet = &g_inet;
	entry = (struct inet_rtentry *)
	    inet->rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, inet->rnh);
	if (entry != NULL)
		free(entry);

	return (0);
}

static void
inet_cleanup(void *unused)
{
	struct inet *inet;

	inet = &g_inet;
	inet->rnh->rnh_walktree(inet->rnh, inet_route_cleanup_cb, NULL);
}

int
inet_init(void)
{
	struct inet *inet;

	inet = &g_inet;

	/* Init the radix table. */
	if (rn_inithead((void **)&inet->rnh, 32) == 0)
		return (-1);
	/* And the IPv4 list. */
	STAILQ_INIT(&inet->inet_addrs);

	/* Register the route cli command. */
	cli_cmd_add("route", "route - list and manipulate the route table\n",
	    inet_cli_route, inet_cli_route_help);

	cleanup_add(inet_cleanup, NULL);

	return (0);
}

int
inet_addroute(struct sockaddr_in *dst, struct sockaddr_in *gw,
	struct sockaddr_in *mask, int flags, struct nm_if *nmif)
{
	struct inet *inet;
	struct inet_rtentry *rt;
	struct radix_node *rn;

	inet = &g_inet;

	rt = malloc(sizeof(*rt));
	if (rt == NULL)
		return (ENOBUFS);

	memset(rt, 0, sizeof(*rt));
	rt->nmif = nmif;
	rt->flags = RTF_UP | flags;
	if (gw != NULL) {
		memcpy(&rt->gw, gw, sizeof(rt->gw));
		rt->flags |= RTF_GATEWAY;
	}

	memcpy(&rt->dst, dst, sizeof(rt->dst));
	memcpy(&rt->mask, mask, sizeof(rt->mask));
	if (rt->flags & RTF_HOST)
		rt->mask.sin_addr.s_addr = INADDR_BROADCAST;
	rn = inet->rnh->rnh_addaddr(&rt->dst, &rt->mask, inet->rnh, rt->rn);
	if (rn == NULL) {
		free(rt);
		return (EEXIST);
	}

	return (0);
}

struct inet_rtentry *
inet_match(struct in_addr *d)
{
	struct inet *inet;
	struct radix_node *rn;
	struct sockaddr_in dst;

	inet = &g_inet;

	memset(&dst, 0, sizeof(dst));
	dst.sin_len = sizeof(dst);
	dst.sin_family = AF_INET;
	dst.sin_port = 0;
	dst.sin_addr.s_addr = d->s_addr;
	rn = inet->rnh->rnh_matchaddr(&dst, inet->rnh);
	if (rn && (rn->rn_flags & RNF_ROOT) == 0)
		return ((struct inet_rtentry *)rn);

	return (NULL);
}

void
inet_addr_add(struct inet_addr *addr)
{
	struct inet *inet;

	inet = &g_inet;
	STAILQ_INSERT_TAIL(&inet->inet_addrs, addr, addr_next);
}

void
inet_addr_del(struct inet_addr *addr)
{
	struct inet *inet;

	inet = &g_inet;
	STAILQ_REMOVE(&inet->inet_addrs, addr, inet_addr, addr_next);
}

int
inet_add_if_print(struct nm_if *nmif, char **buf, int *buflen, int *resid)
{
	struct inet *inet;
	struct inet_addr *addr;

	inet = &g_inet;
	STAILQ_FOREACH(addr, &inet->inet_addrs, addr_next) {
		if (addr->nmif != nmif)
			continue;
		if (printf_buf(buf, buflen, resid, "\tinet %s ",
		    inet_ntoa(addr->addr.sin_addr)) == -1)
			return (-1);
		if (printf_buf(buf, buflen, resid, "netmask %s ",
		    inet_ntoa(addr->mask.sin_addr)) == -1)
			return (-1);
		if (nmif->nm_if_flags & IFF_BROADCAST) {
			if (printf_buf(buf, buflen, resid, "broadcast %s",
			    inet_ntoa(addr->broadaddr.sin_addr)) == -1)
				return (-1);
		}
		if (printf_buf(buf, buflen, resid, "\n") == -1)
			return (-1);
	}

	return (0);
}

void
inet_addr_if_free(struct nm_if *nmif)
{
	struct inet *inet;
	struct inet_addr *addr, *tmp;

	inet = &g_inet;
	STAILQ_FOREACH_SAFE(addr, &inet->inet_addrs, addr_next, tmp) {
		if (addr->nmif != nmif)
			continue;
		inet_addr_del(addr);
		free(addr);
	}
}

struct inet_addr *
inet_get_if_addr(struct nm_if *nmif)
{
	struct inet *inet;
	struct inet_addr *addr;

	inet = &g_inet;
	STAILQ_FOREACH(addr, &inet->inet_addrs, addr_next) {
		if (addr->nmif == nmif)
			return (addr);
	}

	return (NULL);
}

struct inet_addr *
inet_our_addr(struct in_addr *a)
{
	struct inet *inet;
	struct inet_addr *addr;

	inet = &g_inet;
	STAILQ_FOREACH(addr, &inet->inet_addrs, addr_next) {
		if (memcmp(&addr->addr.sin_addr, a,
		    sizeof(addr->addr.sin_addr)) == 0)
			return (addr);
	}

	return (NULL);
}

struct inet_addr *
inet_our_broadcast(struct in_addr *broadcast)
{
	struct inet *inet;
	struct inet_addr *addr;

	inet = &g_inet;
	STAILQ_FOREACH(addr, &inet->inet_addrs, addr_next) {
		if (memcmp(&addr->broadaddr.sin_addr, broadcast,
		    sizeof(addr->broadaddr.sin_addr)) == 0)
			return (addr);
	}

	return (NULL);
}

static int
inet_cli_p_flags(int flags, char *buf, int maxlen)
{
	int len;
	struct fbits *p;

	len = 0;
	for (p = fbits; p->b_mask; p++) {
		if ((p->b_mask & flags) == 0)
			continue;
		if (len + 1 >= maxlen)
			return (-1);
		*(buf + len++) = p->b_val;
	}
	buf[len] = 0;

	return (0);
}

static int
inet_cli_p_flag_names(int flags, char *buf, int maxlen)
{
	int any, len;
	struct fbits *p;

	any = 0;
	len = 1;
	if (len > maxlen)
		return (-1);
	*buf++ = '<';
	for (p = fbits; p->b_mask; p++) {
		if ((p->b_mask & flags) == 0)
			continue;
		if (any) {
			if (len + 1 > maxlen)
				return (-1);
			*buf++ = ',';
		}
		any = 1;
		if (len + strlen(p->b_name) > maxlen)
			return (-1);
		memcpy(buf, p->b_name, strlen(p->b_name));
		buf += strlen(p->b_name);
	}
	if (len + 1 > maxlen)
		return (-1);
	*buf++ = '>';
	*buf = '\0';

	return (0);
}

static int
inet_cli_route_cb(struct radix_node *rn, void *varg)
{
	char dst[64], flags[64];
	int len, masklen;
	struct inet_rtentry *rt;
	struct inet_walktree_arg *arg;

	rt = (struct inet_rtentry *)rn;
	arg = (struct inet_walktree_arg *)varg;
	masklen = ((struct sockaddr_in *)rt_mask(rt))->sin_addr.s_addr;
	if (masklen != 0)
		masklen = 33 - ffs(ntohl(masklen));
	if (rt->flags & RTF_HOST)
		len = snprintf(dst, sizeof(dst), "%s",
		    inet_ntoa(((struct sockaddr_in *)rt_key(rt))->sin_addr));
	else
		len = snprintf(dst, sizeof(dst), "%s/%d",
		    inet_ntoa(((struct sockaddr_in *)rt_key(rt))->sin_addr),
		    masklen);
	if (len >= sizeof(dst))
		return (0);
	if (inet_cli_p_flags(rt->flags, flags, sizeof(flags)) == -1)
		return (0);
	printf_buf(arg->buf, arg->buflen, arg->resid,
	    "%-18.18s %-18.18s %-12.12s %s\n",
	    dst, (rt->flags & RTF_GATEWAY) ? inet_ntoa(rt->gw.sin_addr) : "",
	    flags, rt->nmif->nm_if_name);

	return (0);
}

static int
inet_cli_route_parse_addr(struct cli_arg *arg, struct sockaddr_in *addr,
	struct sockaddr_in *mask, int *mlen)
{
	char *p, tmp[32];
	struct inet *inet;

	inet = &g_inet;

	if (arg == NULL || arg->len > (sizeof(tmp) - 1))
		return (-2);
	memcpy(tmp, arg->arg, arg->len);
	tmp[arg->len] = '\0';

	/* Read the netmask, if any. */
	if (mlen != NULL)
		*mlen = -1;
	p = strchr(tmp, '/');
	if (p != NULL && mask != NULL && mlen != NULL) {
		*p++ = '\0';
		*mlen = atoi(p);
		if (*mlen < 0 || *mlen > 32)
			return (-2);
		memset(mask, 0, sizeof(*mask));
		mask->sin_len = sizeof(*mask);
		mask->sin_family = AF_INET;
		mask->sin_addr.s_addr = htonl(*mlen ? ~((1 << (32 - *mlen)) - 1) : 0);
	}

	memset(addr, 0, sizeof(*addr));
	addr->sin_len = sizeof(*addr);
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(tmp);
	if (addr->sin_addr.s_addr == INADDR_BROADCAST)
		return (-2);

	return (0);
}

static int
inet_cli_route_list(char **buf, int *buflen, int *resid)
{
	struct inet *inet;
	struct inet_walktree_arg arg;

	inet = &g_inet;

	arg.buf = buf;
	arg.buflen = buflen;
	arg.resid = resid;
	if (printf_buf(buf, buflen, resid,
	    "Internet:\n%-18.18s %-18.18s %-12.12s %s\n",
	    "Destination", "Gateway", "Flags", "Netif") == -1)
		return (-1);
	inet->rnh->rnh_walktree(inet->rnh, inet_cli_route_cb, (void *)&arg);

	return (0);
}

static int
inet_cli_route_get(struct cli_arg *arg, char **buf, int *buflen, int *resid)
{
	char flags[64];
	int err, mlen;
	struct inet *inet;
	struct inet_rtentry *rt;
	struct radix_node *rn;
	struct sockaddr_in dst, mask;

	inet = &g_inet;

	err = inet_cli_route_parse_addr(arg, &dst, &mask, &mlen);
	if (err != 0)
		return (err);
	if (mlen != -1)
		rn = inet->rnh->rnh_lookup(&dst, &mask, inet->rnh);
	else
		rn = inet->rnh->rnh_matchaddr(&dst, inet->rnh);

	if (rn == NULL || (rn->rn_flags & RNF_ROOT) != 0)
		return (printf_buf(buf, buflen, resid,
		    "route has not been found\n"));

	if (printf_buf(buf, buflen, resid, "   route to: %s\n",
	    inet_ntoa(dst.sin_addr)) == -1)
		return (-1);
	rt = (struct inet_rtentry *)rn;
	if (printf_buf(buf, buflen, resid, "destination: %s\n",
	    inet_ntoa(((struct sockaddr_in *)rt_key(rt))->sin_addr)) == -1)
		return (-1);
	if ((rt->flags & RTF_HOST) == 0) {
		if (printf_buf(buf, buflen, resid, "       mask: %s\n",
		    inet_ntoa(((struct sockaddr_in *)
		    rt_mask(rt))->sin_addr)) == -1)
			return (-1);
	}
	if (rt->flags & RTF_GATEWAY) {
		if (printf_buf(buf, buflen, resid, "    gateway: %s\n",
		    inet_ntoa(rt->gw.sin_addr)) == -1)
			return (-1);
	}
	if (printf_buf(buf, buflen, resid, "  interface: %s\n",
	    rt->nmif->nm_if_name) == -1)
		return (-1);
	if (inet_cli_p_flag_names(rt->flags, flags, sizeof(flags)) == -1)
		return (-1);
	if (printf_buf(buf, buflen, resid, "      flags: %s\n", flags) == -1)
		return (-1);

	return (0);
}

static int
inet_cli_route_add(struct cli_arg *arg, char **buf, int *buflen, int *resid)
{
	int err, flags, mlen;
	struct inet *inet;
	struct inet_rtentry *rt;
	struct radix_node *rn;
	struct sockaddr_in dst, gw, mask;

	inet = &g_inet;

	err = inet_cli_route_parse_addr(arg, &dst, &mask, &mlen);
	if (err != 0)
		return (err);
	err = inet_cli_route_parse_addr(STAILQ_NEXT(arg, arg_next),
	    &gw, NULL, NULL);
	if (err != 0)
		return (err);

	rn = inet->rnh->rnh_matchaddr(&gw, inet->rnh);
	if (rn == NULL || (rn->rn_flags & RNF_ROOT) != 0)
		return (printf_buf(buf, buflen, resid,
		    "Network is unreachable\n"));

	flags = RTF_STATIC;
	if (mlen == -1) {
		flags |= RTF_HOST;
		memset(&mask, 0, sizeof(mask));
		mask.sin_len = sizeof(mask);
		mask.sin_family = AF_INET;
	} else if (mlen < 32)
		dst.sin_addr.s_addr &= mask.sin_addr.s_addr;

	rt = (struct inet_rtentry *)rn;
	if (inet_addroute(&dst, &gw, &mask, flags, rt->nmif) != 0)
		return (printf_buf(buf, buflen, resid,
		    "cannot add route\n"));

	return (0);
}

static int
inet_cli_route_delete(struct cli_arg *arg, char **buf, int *buflen, int *resid)
{
	int err, mlen;
	struct cli_arg *arg2;
	struct inet *inet;
	struct inet_rtentry *rt;
	struct radix_node *rn;
	struct sockaddr_in dst, gw, mask;

	inet = &g_inet;

	err = inet_cli_route_parse_addr(arg, &dst, &mask, &mlen);
	if (err != 0)
		return (err);
	arg2 = STAILQ_NEXT(arg, arg_next);
	if (arg2 != NULL) {
		err = inet_cli_route_parse_addr(arg2, &gw, NULL, NULL);
		if (err != 0)
			return (err);
	}

	/* Set mask to /32 if !gw and !mask. */
	if (mlen == -1 && arg2 == NULL) {
		memset(&mask, 0, sizeof(mask));
		mask.sin_len = sizeof(mask);
		mask.sin_family = AF_INET;
		mask.sin_addr.s_addr = INADDR_BROADCAST;
	} else if (mlen < 32)
		dst.sin_addr.s_addr &= mask.sin_addr.s_addr;

	rn = inet->rnh->rnh_lookup(&dst, &mask, inet->rnh);
	if (rn == NULL || (rn->rn_flags & RNF_ROOT) != 0)
		return (printf_buf(buf, buflen, resid,
		    "route has not been found\n"));

	rt = (struct inet_rtentry *)rn;

	/* Check if the gateway address matches. */
	if (arg2 != NULL &&
	    rt->gw.sin_addr.s_addr != gw.sin_addr.s_addr) {
		return (printf_buf(buf, buflen, resid,
		    "route has not been found\n"));
	}

	if ((rt->flags & RTF_STATIC) == 0)
		return (printf_buf(buf, buflen, resid,
		    "cannot remove non static route\n"));

	rn = inet->rnh->rnh_deladdr(&dst, &mask, inet->rnh);
	if (rn == NULL)
		return (printf_buf(buf, buflen, resid,
		    "route could not be deleted\n"));
	rt = (struct inet_rtentry *)rn;
	free(rt);

	return (0);
}

static int
inet_cli_route_help(struct cli *cli, struct cli_args *args)
{
	const char *p;
	struct cli_arg *arg;

	if (args->args == 2) {
		p = "help route show\n"
		    "help route add\n"
		    "help route get\n"
		    "help route delete\n";
		if (cli_obuf_append(cli, p, strlen(p)) == -1)
			return (-1);
	} else if (args->args >= 3) {
		/* Get the third argument. */
		arg = STAILQ_FIRST(&args->args_list);	/* help */
		arg = STAILQ_NEXT(arg, arg_next);	/* route */
		arg = STAILQ_NEXT(arg, arg_next);	/* command */
		if (arg == NULL)
			return (-1);
		if (strncasecmp("show", arg->arg, arg->len) == 0) {
			p = "route\n"
			    "route show\n"
			    "print the route table\n";
			if (cli_obuf_append(cli, p, strlen(p)) == -1)
				return (-1);
		} else if (strncasecmp("add", arg->arg, arg->len) == 0) {
			p = "route add network/mask gateway\n"
			    "add a route to the network/mask via the given gateway\n";
			if (cli_obuf_append(cli, p, strlen(p)) == -1)
				return (-1);
		} else if (strncasecmp("get", arg->arg, arg->len) == 0) {
			p = "route get destination\n"
			    "get the route for the given destination\n";
			if (cli_obuf_append(cli, p, strlen(p)) == -1)
				return (-1);
		} else if (strncasecmp("delete", arg->arg, arg->len) == 0) {
			p = "route delete network/mask gateway\n"
			    "remove a route to the network/mask via the given gateway\n";
			if (cli_obuf_append(cli, p, strlen(p)) == -1)
				return (-1);
		}
	}

	return (0);
}

static int
inet_cli_route(struct cli *cli, struct cli_args *args)
{
	char *buf;
	int buflen, err, resid;
	struct cli_arg *arg, *arg2;

	/* Get the second argument. */
	arg = STAILQ_FIRST(&args->args_list);	/* route */
	arg2 = STAILQ_NEXT(arg, arg_next);	/* command */

	/* Allocate the output buffer. */
	resid = 0;
	buflen = BUFSZ;
	buf = (char *)malloc(BUFSZ);
	if (buf == NULL)
		exit(51);
	memset(buf, 0, buflen);

	/* Default to 'command not found'. */
	err = -2;

	/* Print the route table. */
	if (arg2 != NULL && args->args >= 3 &&
	    strncasecmp("get", arg2->arg, arg2->len) == 0) {
		err = inet_cli_route_get(STAILQ_NEXT(arg2, arg_next), &buf,
		    &buflen, &resid);
		if (err == 0)
			err = cli_obuf_append(cli, buf, strlen(buf));
	} else if (arg2 != NULL && args->args >= 4 &&
	    strncasecmp("add", arg2->arg, arg2->len) == 0) {
		err = inet_cli_route_add(STAILQ_NEXT(arg2, arg_next), &buf,
		    &buflen, &resid);
		if (err == 0)
			err = cli_obuf_append(cli, buf, strlen(buf));
	} else if (arg2 != NULL && args->args >= 3 &&
	    strncasecmp("delete", arg2->arg, arg2->len) == 0) {
		err = inet_cli_route_delete(STAILQ_NEXT(arg2, arg_next), &buf,
		    &buflen, &resid);
		if (err == 0)
			err = cli_obuf_append(cli, buf, strlen(buf));
	} else if ((args->args == 1) ||
	    (arg2 != NULL && strncasecmp("show", arg2->arg, arg2->len) == 0)) {

		if (printf_buf(&buf, &buflen, &resid,
		    "Routing tables\n\n") == -1)
			return (-1);

		/* IPv4 */
		err = inet_cli_route_list(&buf, &buflen, &resid);
		if (err == 0)
			err = cli_obuf_append(cli, buf, strlen(buf));
	}
	free(buf);

	return (err);
}
