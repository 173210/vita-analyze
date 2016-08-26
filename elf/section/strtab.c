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

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "../elf.h"
#include "strtab.h"

void elfSectionStrtabInit(struct elfSectionStrtab * restrict context)
{
	context->buffer = NULL;
	context->size = 0;
}

int elfSectionStrtabAdd(Elf32_Word * restrict index,
			struct elfSectionStrtab * restrict context,
			Elf32_Word n, const char * restrict f, ...)
{
	const size_t newSize = context->size + n;
	char * const new = realloc(context->buffer, newSize);
	if (new == NULL) {
		perror(NULL);
		return -1;
	}

	va_list list;
	va_start(list, f);
	const int result = vsnprintf(new + context->size, n, f, list);
	va_end(list);

	if (result < 0) {
		perror(NULL);
		return result;
	}

	*index = context->size;
	context->buffer = new;
	context->size = newSize;

	return result;
}

void elfSectionStrtabDispose(const struct elfSectionStrtab * restrict context)
{
	free(context->buffer);
}

void elfSectionStrtabFinalize(const struct elfSectionStrtab * restrict context,
			      Elf32_Word name, Elf32_Off offset,
			      Elf32_Shdr * restrict shdr,
			      void ** restrict buffer)
{
	shdr->sh_name = name;
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = 0;
	shdr->sh_addr = 0;
	shdr->sh_offset = offset;
	shdr->sh_size = context->size;
	shdr->sh_link = 0;
	shdr->sh_info = 0;
	shdr->sh_addralign = 1;
	shdr->sh_entsize = 0;
	*buffer = context->buffer;
}
