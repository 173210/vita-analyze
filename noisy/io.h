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

#ifndef NOISY_IO_H
#define NOISY_IO_H

#include <stddef.h>

struct noisyFile;
extern const struct noisyFile noisyStdout;

struct noisyFile *noisyGetStdout();
struct noisyFile *noisyFopen(const char * restrict path,
			 const char * restrict mode);

int noisyFclose(struct noisyFile * restrict context);
int noisyFseek(const struct noisyFile * restrict context, long offset, int whence);
long noisyFtell(const struct noisyFile * restrict context);
size_t noisyFread(void * restrict buffer, size_t size, size_t number,
		 const struct noisyFile * restrict context);
size_t noisyFwrite(const void * restrict buffer, size_t size, size_t number,
	const struct noisyFile * restrict context);
int noisyFputc(int c, const struct noisyFile * restrict context);

#endif
