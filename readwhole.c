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

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "noisy/fcntl.h"
#include "noisy/lib.h"
#include "readwhole.h"

void *readWhole(const char * restrict path, size_t * restrict size)
{
	struct noisyFile * const file = noisyOpen(path, O_RDONLY);
	if (file == NULL)
		goto failOpen;

	off_t localSize = noisyLseek(file, 0, SEEK_END);
	if (localSize < 0)
		goto failSeek;

	void * const buffer = noisyMalloc(localSize);
	if (buffer == NULL)
		goto failMalloc;

	if (noisyPread(file, buffer, localSize, 0) != localSize)
		goto failRead;

	noisyClose(file);

	if (size != NULL)
		*size = localSize;

	return buffer;

failRead:
	free(buffer);
failMalloc:
failSeek:
	noisyClose(file);
failOpen:
	return NULL;
}
