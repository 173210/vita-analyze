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

#ifndef ELF_SECTOPN_SYMTAB_H

#include "../elf.h"
#include "../image.h"
#include "../info.h"
#include "strtab.h"

int elfSectionSymtabMake(const struct elfImage * restrict image,
			 const SceKernelModuleInfo * restrict kernelInfo,
			 struct elfSectionStrtab * restrict strtab,
			 Elf32_Word strtabIndex,
			 Elf32_Word name, Elf32_Off offset,
			 Elf32_Shdr * restrict shdr,
			 void ** restrict buffer);

#endif
