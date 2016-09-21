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

#ifndef NOISY_FCNTL_H
#define NOISY_FCNTL_H

#include <stddef.h>
#include <sys/types.h>

struct noisyFile;

struct noisyFile *noisyGetStdout(void);
struct noisyFile *noisyOpen(const char * restrict path, int flag);

int noisyClose(struct noisyFile * restrict context);

off_t noisyLseek(const struct noisyFile * restrict context,
		 off_t offset, int whence);
ssize_t noisyPread(const struct noisyFile * restrict context,
		   void * restrict buffer, size_t size, off_t offset);
ssize_t noisyRead(const struct noisyFile * restrict context,
		  void * restrict buffer, size_t size);
ssize_t noisyWrite(const struct noisyFile * restrict context,
		   const void * restrict buffer, size_t size);

#endif
