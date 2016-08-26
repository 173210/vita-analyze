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
#include <string.h>
#include "../overflow.h"
#include "../readwhole.h"
#include "elf.h"
#include "driver.h"
#include "image.h"
#include "info.h"

int elfImageFindInfo(const struct elfImage * restrict image,
		     const SceKernelModuleInfo * restrict kernelInfo,
		     Elf32_Addr * restrict infoVaddr,
		     struct elfImageExp * restrict exp,
		     struct elfImageImp * restrict imp)
{
	const void * const buffer = image->buffer;
	const Elf32_Word phoff = ((Elf32_Ehdr *)buffer)->e_phoff;
	const Elf32_Phdr * const phdr = (void *)((char *)buffer + phoff);
	const char * const segment = (char *)buffer + phdr->p_offset;

	if (phdr->p_filesz < sizeof(SceModuleInfo)) {
		fprintf(stderr, "%s: too small segment 0\n", image->path);
		return -1;
	}

	for (Elf32_Word index = 0;
	     index < phdr->p_filesz - sizeof(SceModuleInfo);
	     index += 4) {
		const SceModuleInfo * const info = (void *)(segment + index);

		if (strcmp(info->name, kernelInfo->module_name) != 0)
			continue;

		Elf32_Word expSize;
		if (wsubOverflow(info->expBtm, info->expTop,
				  &expSize))
			continue;

		/* Make a guess that exports are right after SceModuleInfo. */
		const Elf32_Word expTopOff = index + sizeof(SceModuleInfo);

		Elf32_Word expBtmOff;
		if (waddOverflow(expTopOff, expSize, &expBtmOff))
			continue;

		if (expBtmOff > phdr->p_filesz)
			continue;

		Elf32_Word impSize;
		if (wsubOverflow(info->impBtm, info->impTop,
				  &impSize))
			continue;

		/* Make a guess that imports are right after exports */
		const Elf32_Word impTopOff = expBtmOff;

		Elf32_Word impBtmOff;
		if (waddOverflow(impTopOff, impSize, &impBtmOff))
			continue;

		if (impBtmOff > phdr->p_filesz)
			continue;

		const struct elfExp * const expTop
			= (void *)(segment + expTopOff);
		const struct elfExp * const expBtm
			= (void *)(segment + expBtmOff);

		const struct elfImp * const impTop
			= (void *)(segment + impTopOff);
		const struct elfImp * const impBtm
			= (void *)(segment + impBtmOff);

		*infoVaddr = phdr->p_vaddr + index;

		exp->top = expTop;
		exp->btm = expBtm;

		imp->top = impTop;
		imp->btm = impBtm;

		return 0;
	}

	fprintf(stderr, "%s: sceModuleInfo not found\n", image->path);
	return -1;
}

int elfImageRead(struct elfImage * restrict image, const char * restrict path)
{
	image->buffer = readWhole(path, &image->size);
	if (image->buffer == NULL)
		return -1;

	image->path = path;

	return 0;
}

static int validatePhdr(const struct elfImage * restrict image)
{
	const void * const buffer = image->buffer;
	const Elf32_Ehdr * const ehdr = buffer;
	const Elf32_Phdr *phdr = (void *)((char *)buffer + ehdr->e_phoff);
	int result = 0;

	for (Elf32_Word index = 0; index < ehdr->e_phnum; index++) {
		if (phdr->p_offset > image->size) {
			fprintf(stderr, "%s: segment %u offset %u is out of range\n",
				image->path, index, phdr->p_offset);
			result = -1;
		} else if (phdr->p_filesz > image->size - phdr->p_offset) {
			fprintf(stderr, "%s: segment %u too large\n",
				image->path, index);
			result = -1;
		}
	}

	return result;
}

int elfImageValidate(const struct elfImage * restrict image)
{
	int result = 0;

	if (image->size < sizeof(Elf32_Ehdr)) {
		fprintf(stderr, "%s: too small file\n", image->path);
		return -1;
	}

	const Elf32_Ehdr * const ehdr = image->buffer;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "%s: invalid magic\n", image->path);
		result = -1;
	}

	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		fprintf(stderr, "%s: invalid data encoding, expected 2's complement, little endian",
			image->path);
		result = -1;
	}

	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stderr, "%s: invalid version %u, expected %u\n",
			image->path, ehdr->e_ident[EI_VERSION], EV_CURRENT);
		result = -1;
	}

	if (result != 0)
		return result;

	if (ehdr->e_shnum > 0)
		fprintf(stderr, "%s: warning: all existing sections will be ignored\n",
			image->path);

	if (ehdr->e_phoff > image->size) {
		fprintf(stderr, "%s: program header offset %u is out of range\n",
			image->path, ehdr->e_phoff);
		result = -1;
	}

	if (ehdr->e_phentsize != sizeof(Elf32_Phdr)) {
		fprintf(stderr, "%s: invalid program header size %zu, expected %zu\n",
			image->path,
			(size_t)ehdr->e_phentsize, sizeof(Elf32_Phdr));
		result = -1;
	}

	if (ehdr->e_phnum <= 0) {
		fprintf(stderr, "%s: no program header found\n", image->path);
		result = -1;
	}

	if (result == 0) {
		if (ehdr->e_phnum > (image->size - ehdr->e_phoff)
				    / sizeof(Elf32_Phdr)
		    || ehdr->e_phnum == PN_XNUM) {
			fprintf(stderr, "%s: too many program headers\n",
				image->path);
			result = -1;
		}

		const int phdrResult = validatePhdr(image);
		if (result == 0)
			result = phdrResult;
	}

	return result;
}

Elf32_Off elfImageVaddrToOff(const struct elfImage * restrict image,
			     Elf32_Addr vaddr, Elf32_Word size,
			     Elf32_Word * restrict max)
{
	const void * const buffer = image->buffer;
	const Elf32_Ehdr * const ehdr = buffer;
	const Elf32_Phdr * const phdrsTop
		= (void *)((char *)buffer + ehdr->e_phoff);
	const Elf32_Phdr * const phdrsBtm = phdrsTop + ehdr->e_phnum;

	for (const Elf32_Phdr *phdr = phdrsTop; phdr != phdrsBtm; phdr++) {
		Elf32_Word offset;
		if (wsubOverflow(vaddr, phdr->p_vaddr, &offset))
			continue;

		Elf32_Word localMax;
		if (wsubOverflow(phdr->p_filesz, offset, &localMax))
			continue;

		if (localMax < size)
			continue;

		if (max != NULL)
			*max = localMax;

		return phdr->p_offset + offset;
	}

	return 0;
}

const void *elfImageVaddrToPtr(const struct elfImage * restrict image,
			       Elf32_Addr vaddr, Elf32_Word size,
			       Elf32_Word * restrict max)
{
	const Elf32_Off offset = elfImageVaddrToOff(image, vaddr, size, max);
	return offset > 0 ? elfImageOffToPtr(image, offset) : NULL;
}

int elfImageGetPhndxByVaddr(const struct elfImage * restrict image,
			    Elf32_Addr vaddr, Elf32_Word size,
			    Elf32_Word * restrict result,
			    Elf32_Word * restrict max)
{
	const void * const buffer = image->buffer;
	const Elf32_Ehdr * const ehdr = buffer;
	const Elf32_Phdr * const phdrs
		= (void *)((char *)buffer + ehdr->e_phoff);

	for (Elf32_Word ndx = 0; ndx < ehdr->e_phnum; ndx++) {
		Elf32_Word offset;
		if (wsubOverflow(vaddr, phdrs[ndx].p_vaddr, &offset))
			continue;

		Elf32_Word localMax;
		if (wsubOverflow(phdrs[ndx].p_filesz, offset, &localMax))
			continue;

		if (localMax < size)
			continue;

		*result = ndx;

		if (max != NULL)
			*max = localMax;

		return 0;
	}

	return -1;
}
