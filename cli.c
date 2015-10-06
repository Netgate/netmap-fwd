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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/un.h>

#include <net/ethernet.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arp.h"
#include "cleanup.h"
#include "cli.h"
#include "config.h"
#include "counters.h"
#include "event.h"
#include "inet.h"
#include "net.h"
#include "util.h"

#define	CMDMAXSZ		64
#define	MAXCLIBUF		4096

/* CLI client data. */
struct cli {
	STAILQ_ENTRY(cli) cli_next;
	char *buf;
	char *obuf;
	int fd;
	int shutdwait;
	ssize_t oresid;
	ssize_t resid;
	socklen_t slen;
	struct event *ev_rx;
	struct event *ev_tx;
	struct sockaddr_un sun;
};

/* CLI commands. */
struct cli_cmd {
	STAILQ_ENTRY(cli_cmd) cli_cmd_next;
	char cmd[CMDMAXSZ];
	char helptxt[BUFSZ];
	int (*cb)(struct cli *, struct cli_args *);
	int (*help)(struct cli *, struct cli_args *);
};

/* CLI socket settings. */
struct clis {
	int maxclients;
	int nclients;
	int socket;
	struct event *ev;
	STAILQ_HEAD(clis_, cli) clis;
	STAILQ_HEAD(cli_cmds_, cli_cmd) cli_cmds;
};

static void cli_disconnect(struct cli *);

static struct clis clis_g;

static void
cli_cleanup(void *arg)
{
	struct cli *cli, *clitmp;
	struct cli_cmd *cli_cmd, *cmdtmp;
	struct clis *clis;

	clis = (struct clis *)arg;
	/* Disconnect everyone. */
	STAILQ_FOREACH_SAFE(cli, &clis->clis, cli_next, clitmp) {
		cli_disconnect(cli);
	}
	/* Clean the cli commands list. */
	STAILQ_FOREACH_SAFE(cli_cmd, &clis->cli_cmds, cli_cmd_next, cmdtmp) {
		STAILQ_REMOVE(&clis->cli_cmds, cli_cmd, cli_cmd, cli_cmd_next);
		free(cli_cmd);
	}
}

void
cli_cmd_add(const char *cmd, const char *helptxt,
	int (*cb)(struct cli *, struct cli_args *),
	int (*help)(struct cli *, struct cli_args *))
{
	struct cli_cmd *cli_cmd;
	struct clis *clis;

	clis = &clis_g;
	cli_cmd = malloc(sizeof(*cli_cmd));
	if (cli_cmd == NULL)
		exit(51);
	memset(cli_cmd, 0, sizeof(*cli_cmd));
	strlcpy(cli_cmd->cmd, cmd, sizeof(cli_cmd->cmd));
	strlcpy(cli_cmd->helptxt, helptxt, sizeof(cli_cmd->helptxt));
	cli_cmd->cb = cb;
	cli_cmd->help = help;
	STAILQ_INSERT_HEAD(&clis->cli_cmds, cli_cmd, cli_cmd_next);
}

/*
 * Append data to output buffer.
 */
int
cli_obuf_append(struct cli *cli, const char *buf, ssize_t len)
{

	if (len == 0)
		return (0);
	/* XXX */
	if (cli->oresid + len > MAXCLIBUF)
		return (-1);
	memcpy(cli->obuf + cli->oresid, buf, len);
	cli->oresid += len;
	event_add(cli->ev_tx, NULL);

	return (0); 
}

/*
 * Print the cli banner.
 */
static int
cli_banner(struct cli *cli)
{
	const char *buf;

	buf = "netmap-fwd cli interface\n";
	if (cli_obuf_append(cli, buf, strlen(buf)) == -1)
		return (-1);

	return (0);
}

/*
 * Print the cli prompt.
 */
static int
cli_prompt(struct cli *cli)
{
	const char *buf;

	buf = "> ";
	if (cli_obuf_append(cli, buf, strlen(buf)) == -1)
		return (-1);

	return (0);
}

static int
cli_debug(struct cli *cli, struct cli_args *unused)
{
	char buf[128];
	struct clis *clis;

	clis = &clis_g;
	snprintf(buf, sizeof(buf) - 1, "cli clients: %d\n", clis->nclients);
	buf[sizeof(buf) - 1] = 0;
	if (cli_obuf_append(cli, buf, strlen(buf)) == -1)
		return (-1);

	return (0);
}

static int
cli_help(struct cli *cli, struct cli_args *args)
{
	char *buf;
	int buflen, err, resid;
	struct cli_arg *arg, *arg2;
	struct cli_cmd *cli_cmd;
	struct clis *clis;

	clis = &clis_g;
	if (args->args >= 2) {
		arg = STAILQ_FIRST(&args->args_list);
		arg2 = STAILQ_NEXT(arg, arg_next);
		if (arg == NULL || arg2 == NULL)
			return (-1);
		STAILQ_FOREACH(cli_cmd, &clis->cli_cmds, cli_cmd_next) {
			if (strncasecmp(cli_cmd->cmd, arg2->arg, arg2->len) != 0)
				continue;
			if (cli_cmd->help)
				return (cli_cmd->help(cli, args));
			break;
		}
	}

	resid = 0;
	buflen = BUFSZ;
	buf = (char *)malloc(buflen);
	memset(buf, 0, buflen);
	STAILQ_FOREACH(cli_cmd, &clis->cli_cmds, cli_cmd_next) {
		if (printf_buf(&buf, &buflen, &resid, cli_cmd->helptxt) == -1) {
			free(buf);
			return (-1);
		}
	}

	err = cli_obuf_append(cli, buf, strlen(buf));
	free(buf);

	return (err);
}

static int
cli_quit(struct cli *cli, struct cli_args *unused)
{

	/* Return 1 to disconnect. */
	return (1);
}

static int
cli_shutdown(struct cli *cli, struct cli_args *unused)
{
	const char *buf;

	buf = "shutdown netmap-fwd ? [N/y] ";
	if (cli_obuf_append(cli, buf, strlen(buf)) == -1)
		return (-1);

	return (-3);
}

static int
cli_stat(struct cli *cli, struct cli_args *unused)
{
	char *buf;
	int buflen, resid;

	resid = 0;
	buflen = BUFSZ;
	buf = (char *)malloc(buflen);
	if (buf == NULL)
		exit(51);
	memset(buf, 0, buflen);
	printf_buf(&buf, &buflen, &resid,
	    "arp_whohas:      %10d\n"
	    "arp_reply_sent:  %10d\n"
	    "arp_reply:       %10d\n"
	    "arp_request:     %10d\n"
	    "arp_drop:        %10d\n"
	    "icmp_badaddr:    %10d\n"
	    "icmp_echo:       %10d\n"
	    "icmp_error:      %10d\n"
	    "icmp_drop:       %10d\n"
	    "icmp_old:        %10d\n"
	    "icmp_reply:      %10d\n"
	    "icmp_unknown:    %10d\n"
	    "ip_icmp:         %10d\n"
	    "ip_drop:         %10d\n"
	    "ip_fwd:          %10d\n"
	    "rx_arp:          %10d\n"
	    "rx_ip:           %10d\n"
	    "rx_drop:         %10d\n"
	    "tx_drop:         %10d\n"
	    "tx_pkts:         %10d\n",
	    pktcnt.arp_whohas, pktcnt.arp_reply_sent, pktcnt.arp_reply,
	    pktcnt.arp_request, pktcnt.arp_drop, pktcnt.icmp_badaddr,
	    pktcnt.icmp_echo, pktcnt.icmp_error, pktcnt.icmp_drop,
	    pktcnt.icmp_old, pktcnt.icmp_reply, pktcnt.icmp_unknown,
	    pktcnt.ip_icmp, pktcnt.ip_drop, pktcnt.ip_fwd, pktcnt.rx_arp,
	    pktcnt.rx_ip, pktcnt.rx_drop, pktcnt.tx_drop, pktcnt.tx_pkts);
	if (cli_obuf_append(cli, buf, strlen(buf)) == -1) {
		free(buf);
		return (-1);
	}
	free(buf);

	return (0);
}

static struct cli *
cli_alloc(void)
{
	struct cli *cli;

	cli = (struct cli *)malloc(sizeof(*cli));
	if (cli == NULL)
		exit(51);
	memset(cli, 0, sizeof(*cli));
	cli->fd = -1;

	return (cli);
}

static void
cli_disconnect(struct cli *cli)
{
	struct clis *clis;

	clis = &clis_g;
	clis->nclients--;
	STAILQ_REMOVE(&clis->clis, cli, cli, cli_next);
	if (cli->buf != NULL) {
		free(cli->buf);
		cli->buf = NULL;
	}
	if (cli->obuf != NULL) {
		free(cli->obuf);
		cli->obuf = NULL;
	}
	if (cli->ev_rx != NULL) {
		event_del(cli->ev_rx);
		event_free(cli->ev_rx);
		cli->ev_rx = NULL;
	}
	if (cli->ev_tx != NULL) {
		event_del(cli->ev_tx);
		event_free(cli->ev_tx);
		cli->ev_tx = NULL;
	}
	if (cli->fd != -1) {
		close(cli->fd);
		cli->fd = -1;
	}
	free(cli);
}

static void
cli_parse_args(struct cli_args *args, char *buf, ssize_t buflen)
{
	char *a;
	int l;
	struct cli_arg *arg;

	while (buflen > 0) {
		while (buflen > 0 && *buf == ' ') {
			buf++;
			buflen--;
		}
		l = 1;
		a = buf;
		while (buflen > 0) {
			if (*buf == ' ' || buflen == 1) {
				arg = (struct cli_arg *)malloc(sizeof(*arg));
				if (arg == NULL)
					exit(51);
				memset(arg, 0, sizeof(*arg));
				arg->arg = a;
				arg->len = l;
				if (*buf == ' ')
					arg->len--;
				STAILQ_INSERT_TAIL(&args->args_list, arg,
				    arg_next);
				args->args++;
				buf++;
				buflen--;
				break;
			}
			l++;
			buf++;
			buflen--;
		}
	}
}

static void
cli_free_args(struct cli_args *args)
{
	struct cli_arg *arg, *tmp;

	STAILQ_FOREACH_SAFE(arg, &args->args_list, arg_next, tmp) {
		STAILQ_REMOVE(&args->args_list, arg, cli_arg, arg_next);
		free(arg);
	}
}

static int
cli_parse(struct cli *cli, char *buf, ssize_t buflen)
{
	const char *p;
	int err;
	struct clis *clis;
	struct cli_arg *arg;
	struct cli_args args;
	struct cli_cmd *cli_cmd;

	/* Strip the cr/lf if needed. */
	if (buf[buflen - 1] == '\n')
		buf[--buflen] = 0;
	if (buf[buflen - 1] == '\r')
		buf[--buflen] = 0;
	memset(&args, 0, sizeof(args));
	STAILQ_INIT(&args.args_list);
	cli_parse_args(&args, buf, buflen);
	if (STAILQ_EMPTY(&args.args_list)) {
		cli->shutdwait = 0;
		if (cli_prompt(cli) == -1)
			return (-1);
		return (0);
	}
	arg = STAILQ_FIRST(&args.args_list);

	/* Is the shutdown confirmed ? */
	if (cli->shutdwait) {
		if (strncasecmp(arg->arg, "yes", arg->len) == 0) {
			cleanup();
			return (0);
		}
		/* No, it isn't. */
		cli->shutdwait = 0;
		cli_free_args(&args);
		if (cli_prompt(cli) == -1)
			return (-1);
		return (0);
	}

	err = -2; /* unknown command */
	clis = (struct clis *)&clis_g;
	STAILQ_FOREACH(cli_cmd, &clis->cli_cmds, cli_cmd_next) {
		if (strncasecmp(cli_cmd->cmd, arg->arg, arg->len) == 0) {
			arg = STAILQ_NEXT(arg, arg_next);
			if (arg != NULL && strncasecmp(arg->arg, "help",
			    arg->len) == 0 && cli_cmd->help)
				err = cli_cmd->help(cli, &args);
			else
				err = cli_cmd->cb(cli, &args);
			break;
		}
	}
	cli_free_args(&args);

	if (err == -2) {
		p = "invalid command\n";
		if (cli_obuf_append(cli, p, strlen(p)) == -1)
			return (-1);
	} else if (err == -3) {
		cli->shutdwait = 1;
		return (0);
	}

	if (cli_prompt(cli) == -1)
		return (-1);

	return (err);
}

static void
cli_ev_write(struct cli *cli)
{
	ssize_t len;

	if (cli->oresid == 0)
		return;

	len = write(cli->fd, cli->obuf, cli->oresid);
	if (len == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			/* EAGAIN */
			return;
		}
		DPRINTF("cannot write to cli (%d): %s\n",
		    cli->fd, strerror(errno));
		cli_disconnect(cli);
		return;
	}
	cli->oresid -= len;
	if (cli->oresid > 0) {
		memcpy(cli->obuf, cli->obuf + len, cli->oresid);
		event_add(cli->ev_tx, NULL);
	}
}

static void
cli_ev_read(struct cli *cli)
{
	int more;
	ssize_t i, len;

	if (cli->resid == MAXCLIBUF) {
		DPRINTF(
		    "dropping cli connection - unsupported cli command (%d)\n",
		    cli->fd);
		cli_disconnect(cli);
		return;
	}

	len = read(cli->fd, cli->buf + cli->resid, MAXCLIBUF - cli->resid);
	if (len == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			/* EAGAIN */
			return;
		}
		DPRINTF("cannot read from cli connection (%d): %s\n",
		    cli->fd, strerror(errno));
		cli_disconnect(cli);
		return;
	} else if (len == 0) {
		DPRINTF("cli connection closed (%d)\n", cli->fd);
		cli_disconnect(cli);
		return;
	}
	cli->resid += len;

	/* Loop until we consume all the cli buffer. */
	while (cli->resid > 0) {
		more = 0;
		for (i = 0; i < cli->resid; i++) {
			if (cli->buf[i] == '\n') {
				switch (cli_parse(cli, cli->buf, i + 1)) {
				case -1:
					DPRINTF(
					    "dropping cli connection - cannot parse cli command (%d)\n",
					    cli->fd);
					/* fallthrough */
				case 1:
					/* Disconnect. */
					cli_disconnect(cli);
					return;
				}
				if (i + 1 < cli->resid)
					memcpy(cli->buf, cli->buf + i + 1,
					     cli->resid - i + 1);
				cli->resid -= i + 1;
				more = 1;
			}
		}
		if (more == 0)
			break;
	}
}

static void
cli_ev_rdwr(evutil_socket_t fd, short event, void *data)
{
	struct cli *cli;

	(void)fd;
	cli = (struct cli *)data;

	if (event & EV_TIMEOUT) {
		DPRINTF("debug: %s timeout\n", __func__);
		cli_disconnect(cli);
		return;
	}
	if (event & EV_READ)
		cli_ev_read(cli);
	if (event & EV_WRITE)
		cli_ev_write(cli);
}

static void
cli_connect(evutil_socket_t socket, short event, void *data)
{
	struct cli *cli;
	struct clis *clis;

	(void)event;
	clis = (struct clis *)data;

	cli = cli_alloc();

	/* Accept the connection. */
	cli->slen = sizeof(struct sockaddr_un);
	cli->fd = accept(socket, (struct sockaddr *)&cli->sun, &cli->slen);
	if (cli->fd < 0) {
		DPRINTF("debug: unable to accept new cli connection: %s\n",
		    strerror(errno));
		free(cli);
		return;
	}
	if (net_fd_config(cli->fd,
	    NET_KEEPALIVE | NET_NO_LINGER | NET_NONBLOCK) == -1) {
		DPRINTF("debug: drop cli connection, cannot set fd options\n");
		while (close(cli->fd) != 0 && errno == EINTR);
		free(cli);
		return;
	}

	if (++clis->nclients > clis->maxclients) {
		DPRINTF("debug: drop cli connection, too many connections\n");
		while (close(cli->fd) != 0 && errno == EINTR);
		clis->nclients--;
		free(cli);
		return;
	}
	DPRINTF("debug: new cli connection\n");

	/* Alloc the tx and rx buffers for this cli connection. */
	cli->buf = (char *)malloc(MAXCLIBUF);
	if (cli->buf == NULL)
		exit(51);
	cli->obuf = (char *)malloc(MAXCLIBUF);
	if (cli->obuf == NULL)
		exit(51);

	/* Setup the events for cli fd. */
	cli->ev_rx = event_new(ev_get_base(), cli->fd, EV_READ | EV_PERSIST,
	    cli_ev_rdwr, cli);
	cli->ev_tx = event_new(ev_get_base(), cli->fd, EV_WRITE,
	    cli_ev_rdwr, cli);
	event_add(cli->ev_rx, NULL);

	/* Send the cli banner. */
	if (cli_banner(cli) == -1)
		cli_disconnect(cli);
	if (cli_prompt(cli) == -1)
		cli_disconnect(cli);

	STAILQ_INSERT_HEAD(&clis->clis, cli, cli_next);
}

void
cli_init(void)
{
	struct clis *clis;

	clis = &clis_g;
	clis->socket = -1;
	clis->nclients = 0;
	clis->maxclients = config_get_int("cli_max_clients");
	if (clis->maxclients == 0)
		clis->maxclients = 10;

	/* Initialize the clients list and the cli commands list. */
	STAILQ_INIT(&clis->clis);
	STAILQ_INIT(&clis->cli_cmds);

	/* Add the default cli commands. */
	cli_cmd_add("?", "", cli_help, NULL);
	cli_cmd_add("cli", "cli - show cli status\n", cli_debug, NULL);
	cli_cmd_add("help", "help - get help about cli commands\n", cli_help,
	    NULL);
	cli_cmd_add("quit", "quit - disconnect from cli interface\n", cli_quit,
	    NULL);
	cli_cmd_add("shutdown", "shutdown - shutdown netmap-fwd\n",
	    cli_shutdown, NULL);
	cli_cmd_add("status", "status - show general status\n", cli_stat, NULL);

	/* Add the cleanup callback. */
	cleanup_add(cli_cleanup, clis);
}

int
cli_open(void)
{
	const char *spath;
	struct clis *clis;

	clis = &clis_g;

	/* Open the cli socket. */
	spath = config_get_str("cli_socket_path");
	if (spath == NULL)
		spath = "/var/run/netmap-fwd.sock";
	clis->socket = unix_listen(spath, 5);
	if (clis->socket == -1)
		return (-1);

	/* Setup the connect event for cli socket. */
	clis->ev = event_new(ev_get_base(), clis->socket,
	    EV_READ | EV_PERSIST, cli_connect, clis);
	event_add(clis->ev, NULL);

	return (0);
}
