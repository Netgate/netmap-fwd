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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <ucl.h>

struct config {
	char *buf;
	ssize_t len;
	ucl_object_t *obj;
};

static struct config config_g;

int
config_parse(const char *config_file)
{
	int fd;
	struct config *cfg;
	struct stat st;
	struct ucl_parser *parser;

	cfg = &config_g;

	/* Open and mmap the config file. */
	fd = open(config_file, O_RDONLY);
	if (fd == -1) {
		printf("%s: cannot open the config file: %s\n",
		    __func__, strerror(errno));
		return (-1);
	}
	memset(&st, 0, sizeof(st));
	if (fstat(fd, &st) == -1) {
		printf("%s: cannot stat the config file: %s\n",
		    __func__, strerror(errno));
		close(fd);
		return (-1);
	}
	if (!S_ISREG(st.st_mode)) {
		printf("%s: the config file is not a regular file\n",
		    __func__);
		close(fd);
		return (-1);
	}
	cfg->len = st.st_size;
	cfg->buf = mmap(NULL, cfg->len, PROT_READ,
	    MAP_PRIVATE | MAP_PREFAULT_READ, fd, 0);
	if (cfg->buf == MAP_FAILED) {
		printf("%s: cannot mmap config file: %s\n",
		    __func__, strerror(errno));
		close(fd);
		return (-1);
	}

	/* Parse the config file. */
	parser = ucl_parser_new(0);
	ucl_parser_add_chunk(parser, (const unsigned char *)cfg->buf, cfg->len);
	if (ucl_parser_get_error(parser)) {
		printf("%s: cannot parse config file: %s\n",
		    __func__, ucl_parser_get_error(parser));
		munmap(cfg->buf, cfg->len);
		close(fd);
		return (-1);
	}
	cfg->obj = ucl_parser_get_object(parser);

	/* Close the config file. */
	ucl_parser_free(parser);
	munmap(cfg->buf, cfg->len);
	close(fd);

	return (0);
}

int
config_get_int(const char *key)
{
	const ucl_object_t *cur, *obj;
	struct config *cfg;
	ucl_object_iter_t itkey, itval;

	cfg = &config_g;
	if (cfg->obj == NULL)
		return (0);

	/* Iterate over the object. */
	itkey = NULL;
	while ((obj = ucl_iterate_object(cfg->obj, &itkey, true))) {
		if (strcasecmp(key, ucl_object_key(obj)) != 0)
			continue;
		itval = NULL;
		cur = ucl_iterate_object(obj, &itval, false);
		return ((int)ucl_object_toint(cur));
	}

	return (0);
}

const char *
config_get_str(const char *key)
{
	const ucl_object_t *cur, *obj;
	struct config *cfg;
	ucl_object_iter_t itkey, itval;

	cfg = &config_g;
	if (cfg->obj == NULL)
		return (0);

	/* Iterate over the object. */
	itkey = NULL;
	while ((obj = ucl_iterate_object(cfg->obj, &itkey, true))) {
		if (strcasecmp(key, ucl_object_key(obj)) != 0)
			continue;
		itval = NULL;
		cur = ucl_iterate_object(obj, &itval, false);
		return (ucl_object_tostring(cur));
	}

	return (NULL);
}
