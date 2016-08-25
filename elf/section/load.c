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

#include "../elf.h"
#include "../image.h"
#include "load.h"

Elf32_Word elfSectionLoadCount(struct elfImage * restrict image)
{
	const void * const buffer = image->buffer;
	const Elf32_Ehdr * const ehdr = buffer;
	return ehdr->e_phnum;
}

void elfSectionLoadMake(struct elfImage * restrict image, Elf32_Word name,
			Elf32_Shdr * restrict shdr, void ** restrict section)
{
	const void * const buffer = image->buffer;
	const Elf32_Ehdr * const ehdr = buffer;
	const Elf32_Phdr * const phdrsTop
		= (void *)((char *)buffer + ehdr->e_phoff);
	const Elf32_Phdr * const phdrsBtm = phdrsTop + ehdr->e_phnum;

	for (const Elf32_Phdr *phdr = phdrsTop; phdr != phdrsBtm; phdr++) {
		shdr->sh_name = name;
		shdr->sh_type = SHT_PROGBITS;

		shdr->sh_flags = SHF_ALLOC;
		if ((phdr->p_flags & PF_W) != 0)
			shdr->sh_flags |= SHF_WRITE;
		if ((phdr->p_flags & PF_X) != 0)
			shdr->sh_flags |= SHF_EXECINSTR;

		shdr->sh_addr = phdr->p_vaddr;
		shdr->sh_offset = phdr->p_offset;
		shdr->sh_size = phdr->p_memsz;
		shdr->sh_link = 0;
		shdr->sh_info = 0;
		shdr->sh_addralign = phdr->p_align;
		shdr->sh_entsize = 0;

		*section = NULL;

		shdr++;
		section++;
	}
}
