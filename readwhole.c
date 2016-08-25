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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "noisy/io.h"
#include "noisy/lib.h"
#include "readwhole.h"

void *readWhole(const char * restrict path, size_t * restrict size)
{
	struct noisyFile * const file = noisyFopen(path, "rb");
	if (file == NULL)
		goto failOpen;

	if (noisyFseek(file, 0, SEEK_END) != 0)
		goto failSeek;

	const long localSize = noisyFtell(file);
	if (localSize < 0)
		goto failTell;

	if (noisyFseek(file, 0, SEEK_SET) != 0)
		goto failSeek;

	void * const buffer = noisyMalloc(localSize);
	if (buffer == NULL)
		goto failMalloc;

	if (noisyFread(buffer, localSize, 1, file) != 1)
		goto failRead;

	noisyFclose(file);

	if (size != NULL)
		*size = localSize;

	return buffer;

failRead:
	free(buffer);
failMalloc:
failTell:
failSeek:
	noisyFclose(file);
failOpen:
	return NULL;
}
