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
#include "null.h"

void elfSectionNullMake(Elf32_Shdr * restrict shdr, Elf32_Word name)
{
	shdr->sh_name = name;
	shdr->sh_type = SHT_NULL;
	shdr->sh_flags = 0;
	shdr->sh_addr = 0;
	shdr->sh_offset = 0;
	shdr->sh_size = 0;
	shdr->sh_link = 0;
	shdr->sh_info = 0;
	shdr->sh_addralign = 0;
	shdr->sh_entsize = 0;
}
