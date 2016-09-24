/*
 * Copyright (C) 2016  173210 <root.3.173210@live.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "fcntl.h"
#include "lib.h"

struct noisyFile {
	int fileno;
	const char * restrict path;
};

struct noisyFile *noisyGetStdout()
{
	struct noisyFile * const context = noisyMalloc(sizeof(*context));
	if (context != NULL) {
		context->fileno = STDOUT_FILENO;
		context->path = "stdout";
	}

	return context;
}

int noisyIsatty(const struct noisyFile * restrict context)
{
	return isatty(context->fileno);
}

struct noisyFile *noisyOpen(const char * restrict path, int flag)
{
	struct noisyFile * const context = noisyMalloc(sizeof(*context));
	if (context != NULL) {
		context->fileno = open (path, flag);
		if (context->fileno < 0) {
			perror(path);
			free(context);
			return NULL;
		}

		context->path = path;
	}

	return context;
}

int noisyClose(struct noisyFile * restrict context)
{
	int result;

	result = close(context->fileno);
	if (result != 0)
		perror(context->path);

	free(context);
	return result;
}

off_t noisyLseek(const struct noisyFile * restrict context,
	       off_t offset, int whence)
{
	const off_t result = lseek(context->fileno, offset, whence);
	if (result < 0)
		perror(context->path);

	return result;
}

ssize_t noisyPread(const struct noisyFile * restrict context,
		   void * restrict buffer, size_t size, off_t offset)
{
	const ssize_t result = pread(context->fileno, buffer, size, offset);
	if (result != (ssize_t)size) {
		if (errno != 0)
			perror(context->path);
		else
			fprintf(stderr, "%s: unknown error while reading\n",
				context->path);
	}

	return result;
}

ssize_t noisyRead(const struct noisyFile * restrict context,
		  void * restrict buffer, size_t size)
{
	const ssize_t result = read(context->fileno, buffer, size);
	if (result != (ssize_t)size) {
		if (errno != 0)
			perror(context->path);
		else
			fprintf(stderr, "%s: unknown error while reading\n",
				context->path);
	}

	return result;
}

ssize_t noisyWrite(const struct noisyFile * restrict context,
		   const void * restrict buffer, size_t size)
{
	const ssize_t result = write(context->fileno, buffer, size);
	if (result != (ssize_t)size) {
		if (errno != 0)
			perror(context->path);
		else
			fprintf(stderr, "%s: unknown error while writing\n",
				context->path);
	}

	return result;
}
