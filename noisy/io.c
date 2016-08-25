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

#include <stdio.h>
#include <stdlib.h>
#include "io.h"
#include "lib.h"

struct noisyFile {
	FILE * restrict file;
	const char * restrict path;
};

struct noisyFile *noisyGetStdout()
{
	struct noisyFile * const context = noisyMalloc(sizeof(*context));
	if (context != NULL) {
		context->file = stdout;
		context->path = "stdout";
	}

	return context;
}

struct noisyFile *noisyFopen(const char * restrict path,
			   const char * restrict mode)
{
	struct noisyFile * const context = noisyMalloc(sizeof(*context));
	if (context != NULL) {
		context->file = fopen (path, mode);
		if (context->file == NULL) {
			perror(path);
			free(context);
			return NULL;
		}

		context->path = path;
	}

	return context;
}

int noisyFclose(struct noisyFile * restrict context)
{
	int result;

	if (context->file != stdout) {
		result = fclose(context->file);
		if (result != 0)
			perror(context->path);
	} else {
		result = 0;
	}

	free(context);
	return result;
}

int noisyFseek(const struct noisyFile * restrict context, long offset, int whence)
{
	const int result = fseek(context->file, offset, whence);
	if (result != 0)
		perror(context->path);

	return result;
}

long noisyFtell(const struct noisyFile * restrict context)
{
	const long result = ftell(context->file);
	if (result < 0)
		perror(context->path);

	return result;
}

size_t noisyFread(void * restrict buffer, size_t size, size_t number,
		 const struct noisyFile * restrict context)
{
	const size_t result = fread(buffer, size, number, context->file);
	if (result != number) {
		if (feof(context->file))
			fprintf(stderr, "%s: unexpected end of file\n",
					context->path);
		else
			perror(context->path);
	}

	return result;
}

size_t noisyFwrite(const void * restrict buffer, size_t size, size_t number,
	const struct noisyFile * restrict context)
{
	const size_t result = fwrite(buffer, size, number, context->file);
	if (result != number)
		perror(context->path);

	return result;
}

int noisyFputc(int c, const struct noisyFile * restrict context)
{
	const int result = putc(c, context->file);
	if (result != c)
		perror(context->path);

	return result;
}
