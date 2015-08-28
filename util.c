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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#define	MAXBUFSZ	(BUFSZ * 1024)

extern int verbose;

void
dprintf(const char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

int
printf_buf(char **buf, int *buflen, int *resid, const char *fmt, ...)
{
	char *tmp;
	int len, tmplen;
	va_list ap;

	len = 0;
	tmplen = BUFSZ;
	tmp = (char *)malloc(tmplen);
	do {
 		if (len > tmplen) {
			tmplen += BUFSZ;
			tmp = realloc(tmp, tmplen);
			if (tmp == NULL)
				exit(51);
		}
		memset(tmp, 0, tmplen);
		va_start(ap, fmt);
		len = vsnprintf(tmp, tmplen, fmt, ap);
		va_end(ap);
		if (len >= MAXBUFSZ) {
			free(tmp);
			return (-1);
		}
	} while (len > tmplen);
	while (len + *resid > *buflen) {
		*buflen += BUFSZ;
		if (*buflen > MAXBUFSZ) {
			free(tmp);
			return (-1);
		}
		if (len + *resid < *buflen) {
			*buf = realloc(*buf, *buflen);
			if (*buf == NULL)
				exit(51);
			memset(*buf + *resid, 0, *buflen - *resid);
		}
	}
	memcpy(*buf + *resid, tmp, len);
	*resid += len;
	free(tmp);

	return (0);
}

/*
 * Print a value a la the %b format of the kernel's printf
 */
void
printb(char **buf, int *buflen, int *resid, const char *s, unsigned v,
	const char *bits)
{
        int i, any = 0;
        char c;

	if (bits && *bits == 8)
		printf_buf(buf, buflen, resid, "%s=%o", s, v);
	else
		printf_buf(buf, buflen, resid, "%s=%x", s, v);
	bits++;
	if (bits) {
		printf_buf(buf, buflen, resid, "<");
		while ((i = *bits++) != '\0') {
			if (v & (1 << (i-1))) {
				if (any)
					printf_buf(buf, buflen, resid, ",");
				any = 1;
				for (; (c = *bits) > 32; bits++)
					printf_buf(buf, buflen, resid, "%c", c);
			} else
				for (; *bits > 32; bits++)
					;
		}
		printf_buf(buf, buflen, resid, ">");
	}
}

int
pidfile_create(const char *pidfile)
{
	int fd, len;
	char text_pid[81];
	pid_t pid;

	fd = open(pidfile, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd < 0) {
		/*
		 * File is already locked.  Check to see if the process
		 * holding the lock still exists.
		 */
		fd = open(pidfile, O_RDWR, 0);
		if (fd < 0) {
			printf("%s: Can't open lock file: %s: %s\n",
			    __func__, pidfile, strerror(errno));
			return(-1);
		}
		len = read(fd, text_pid, sizeof(text_pid) - 1);
		if (len <= 0) {
			(void)close(fd);
			printf("%s: Can't read lock file: %s: %s\n",
			    __func__, pidfile, strerror(errno));
			return(-1);
		}
		text_pid[len] = 0;
		pid = atol(text_pid);

		if (kill(pid, 0) == 0 || errno != ESRCH) {
			(void)close(fd);	/* process is still running */
			return(-1);
		}
		/*
		 * The process that locked the file isn't running, so
		 * we'll lock it ourselves.
		 */
		printf("%s: Stale lock on %s PID=%ld... overriding.\n",
		    __func__, pidfile, (long)pid);
		if (lseek(fd, (off_t)0, SEEK_SET) < 0) {
			(void)close(fd);
			printf("%s: Can't seek lock file: %s: %s\n",
			    __func__, pidfile, strerror(errno));
			return(-1);
		}
		/* fall out and finish the locking process */
	}
	pid = getpid();
	(void)snprintf(text_pid, sizeof(text_pid), "%10ld\n", (long)pid);
	len = strlen(text_pid);
	if (write(fd, text_pid, len) != len) {
		(void)close(fd);
		(void)unlink(pidfile);
		printf("%s: Can't write lock file: %s: %s\n",
		    __func__, pidfile, strerror(errno));
		return(-1);
	}
	(void)close(fd);

	return(0);
}
