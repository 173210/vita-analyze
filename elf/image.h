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

#ifndef ELF_IMAGE_H
#define ELF_IMAGE_H

#include <stddef.h>
#include "info.h"

struct elfImage {
	void * restrict buffer;
	const char *path;
	size_t size;
};

struct elfImageModuleInfo {
	const SceModuleInfo *ptr;
	Elf32_Addr vaddr;
};

struct elfImageExp {
	const struct elfExp *top;
	const struct elfExp *btm;
};

struct elfImageImp {
	const struct elfImp *top;
	const struct elfImp *btm;
};

int elfImageFindInfo(const struct elfImage * restrict image,
		     const SceKernelModuleInfo * restrict kernelInfo,
		     Elf32_Addr * restrict infoVaddr,
		     struct elfImageExp * restrict exp,
		     struct elfImageImp * restrict imp);

int elfImageRead(struct elfImage * restrict image, const char * restrict path);

int elfImageValidate(const struct elfImage * restrict image);

Elf32_Off elfImageVaddrToOff(const struct elfImage * restrict image,
			     Elf32_Addr vaddr, Elf32_Word size,
			     Elf32_Word * restrict max);

const void *elfImageVaddrToPtr(const struct elfImage * restrict image,
			       Elf32_Addr vaddr, Elf32_Word size,
			       Elf32_Word * restrict max);

static inline const void *elfImageOffToPtr(
	const struct elfImage * restrict image, Elf32_Off offset)
{
	return (char *)image->buffer + offset;
}

#endif
