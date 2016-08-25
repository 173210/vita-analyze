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

#ifndef ELFDRIVER_H
#define ELFDRIVER_H

#include <stdint.h>
#include "elf.h"

struct elfExp {
	Elf32_Half size;
	uint8_t version[2];
	Elf32_Half attribute;
	Elf32_Half nFuncs;
	Elf32_Word nVars;
	Elf32_Word unknown;
	Elf32_Word moduleNid;
	Elf32_Addr name;
	Elf32_Addr nids;
	Elf32_Addr entries;
};

struct elfImp {
	Elf32_Half size;
	Elf32_Half version;
	Elf32_Half attribute;
	Elf32_Half nFuncs;
	Elf32_Half nVars;
	Elf32_Half nTls;
	Elf32_Word unknown0;
	Elf32_Word nid;
	Elf32_Addr name;
	Elf32_Word unknown1;
	Elf32_Addr funcNids;
	Elf32_Addr funcEntries;
	Elf32_Addr varNids;
	Elf32_Addr varEntries;
	Elf32_Addr tlsNids;
	Elf32_Addr tlsEntries;
};

#endif
