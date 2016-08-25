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

#ifndef ELF_SECTION_STRTAB_H
#define ELF_SECTION_STRTAB_H

#include "../elf.h"

struct elfSectionStrtab {
	char * restrict buffer;
	Elf32_Word size;
};

void elfSectionStrtabInit(struct elfSectionStrtab * restrict context);

int elfSectionStrtabAdd(Elf32_Word * restrict index,
			struct elfSectionStrtab * restrict context,
			Elf32_Word n, const char * restrict f, ...);

void elfSectionStrtabFinalize(const struct elfSectionStrtab * restrict context,
			      Elf32_Word name, Elf32_Off offset,
			      Elf32_Shdr * restrict shdr,
			      void ** restrict buffer);

#endif
