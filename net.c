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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "net.h"

int
net_fd_config(int fd, int flags)
{
	int fl, keepalive;
	struct linger linger;

	/* Set keepalive. */
	if (flags & NET_KEEPALIVE) {
		keepalive = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&keepalive,
		    sizeof(keepalive)) == -1)
			return(-1);
	}

	/* Turn off linger. */
	if (flags & NET_NO_LINGER) {
		memset(&linger, 0, sizeof(linger));
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&linger,
		    sizeof(linger)) == -1)
			return(-1);
	}

	/* Set the FD as nonblock. */
	if (flags & NET_NONBLOCK) {
		if ((fl = fcntl(fd, F_GETFL)) == -1)
			return (-1);
		if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1)
			return (-1);
	}

	return(0);
}

int
set_nonblock(int fd) {
    return(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK));
}

int
unix_listen(const char *path, int backlog) {
	struct sockaddr_un sun;
	int s;

	(void)unlink(path);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strncpy(sun.sun_path, path, sizeof(sun.sun_path));
	s = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (s == -1)
		goto fail;
	if (bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) == -1 ||
	    listen(s, backlog) == -1)
		goto fail;
	if (chmod(path, 0600) == -1)
		goto fail;

	return (s);

fail:
	printf("cannot create socket [%s][%s]\n", path, strerror(errno));
	if (s > 0)
		(void)close(s);
	return (-1);
}
