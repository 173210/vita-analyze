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

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../noisy/fcntl.h"
#include "../noisy/lib.h"
#include "../overflow.h"
#include "../readwhole.h"
#include "section/load.h"
#include "section/null.h"
#include "section/strtab.h"
#include "section/symtab.h"
#include "elf.h"
#include "driver.h"
#include "image.h"
#include "info.h"

static SceKernelModuleInfo *readInfo(const char *path)
{
	size_t size;
	SceKernelModuleInfo * const info = readWhole(path, &size);
	SceKernelModuleInfo *result = info;
	if (info != NULL) {
		if (size != info->size) {
			fprintf(stderr, "%s: real size and size recorded in the file doesn't match\n",
				path);

			result = NULL;
		}

		if (memchr(info->module_name, 0, sizeof(info->module_name))
		    == NULL) {
			fprintf(stderr, "%s: name is not null terminated ('\\0')\n",
				path);

			result = NULL;
		}
	}

	return result;
}

int elfInit(struct elf * restrict context, const char * restrict path)
{
	int result;

	result = elfImageRead(&context->source, path);
	if (result == 0) {
		result = elfImageValidate(&context->source);
		if (result != 0)
			free(context->source.buffer);

		context->shnum = 0;
	}

	return result;
}


int elfMakeSections(struct elf * restrict context,
		    const char * restrict infoPath)
{
	enum shnames {
		ELF_SH_NULL,
		ELF_SH_LOAD,
		ELF_SH_SHSTRTAB,
		ELF_SH_SYMTAB,
		ELF_SH_STRTAB,
		ELF_SH_NUM
	};

#define NAME(string) { string, sizeof(string) }
	static struct {
		const char *string;
		size_t size;
	} names[ELF_SH_NUM] = {
		[ELF_SH_NULL] = NAME(""),
		[ELF_SH_LOAD] = NAME("load"),
		[ELF_SH_SHSTRTAB] = NAME(".shstrtab"),
		[ELF_SH_SYMTAB] = NAME(".symtab"),
		[ELF_SH_STRTAB] = NAME(".strtab")
	};
	struct elfSectionStrtab shstrtab;
	struct elfSectionStrtab strtab;
	Elf32_Word shstrtabNames[ELF_SH_NUM];
	Elf32_Word num;
	int result;

	const Elf32_Word loads = elfSectionLoadCount(&context->source);

	if (waddOverflow(loads, 4, &num))
		goto failTooMany;

	Elf32_Word shsize;
	if (wmulOverflow(num, sizeof(*context->shdrs), &shsize))
		goto failTooMany;

	Elf32_Word tabSize;
	if (wmulOverflow(num, sizeof(*context->sections), &tabSize))
		goto failTooMany;

	Elf32_Shdr * const shdrs = noisyMalloc(shsize);
	if (shdrs == NULL)
		goto failShdrs;

	void ** const sections = noisyMalloc(tabSize);
	if (sections == NULL)
		goto failSections;

	elfSectionStrtabInit(&shstrtab);

	for (enum shnames ndx = 0; ndx < ELF_SH_NUM; ndx++) {
		result = elfSectionStrtabAdd(&shstrtabNames[ndx], &shstrtab,
					     names[ndx].size,
					     names[ndx].string);
		if (result < 0)
			goto failShstrtab;
	}

	Elf32_Word ndx = 0;

	elfSectionNullMake(shstrtabNames[ELF_SH_NULL],
			   shdrs + ndx, sections + ndx);

	ndx++;
	assert(ndx == ELF_LOADNDX);
	elfSectionLoadMake(&context->source, shstrtabNames[ELF_SH_LOAD],
			   shdrs + ndx, sections + ndx);

	ndx += loads;
	elfSectionStrtabFinalize(&shstrtab, shstrtabNames[ELF_SH_SHSTRTAB],
				 context->source.size + shsize,
				 shdrs + ndx, sections + ndx);
	context->shstrndx = ndx;

	elfSectionStrtabInit(&strtab);

	SceKernelModuleInfo * const info = readInfo(infoPath);
	if (info == NULL)
		return -1;

	ndx++;
	result = elfSectionSymtabMake(&context->source, info, &strtab, ndx + 1,
				      shstrtabNames[ELF_SH_SYMTAB],
				      shdrs[ndx - 1].sh_offset
				      + shdrs[ndx - 1].sh_size,
				      shdrs + ndx, sections + ndx);
	if (result != 0)
		goto failSymtab;

	free(info);

	ndx++;
	elfSectionStrtabFinalize(&strtab,
				 shstrtabNames[ELF_SH_STRTAB],
				 shdrs[ndx - 1].sh_offset
				 + shdrs[ndx - 1].sh_size,
				 shdrs + ndx, sections + ndx);

	context->shdrs = shdrs;
	context->sections = sections;
	context->shnum = ndx + 1;

	return result;

failTooMany:
	fputs("too many sections", stderr);
	return -1;

failSections:
	free(shdrs);
failShdrs:
	return -1;

failSymtab:
	free(info);
failShstrtab:
	free(sections);
	free(shdrs);
	return result;
}

int elfWrite(struct elf *context)
{
	Elf32_Ehdr ehdr;

	memcpy(&ehdr, context->source.buffer, sizeof(ehdr));

	/* BFD doesn't accept sections if e_type is ET_CORE.
	   According to "SYSTEM V APPLICATION BINARY INTERFACE" edition 4.1,
	   the type should be executable or shared if symbol values have virtual
	   address. */
	ehdr.e_type = ET_EXEC;

	ehdr.e_shoff = context->source.size;
	ehdr.e_shentsize = sizeof(Elf32_Shdr);
	ehdr.e_shnum = context->shnum;
	ehdr.e_shstrndx = context->shstrndx;

	struct noisyFile * const noisyStdout = noisyGetStdout();
	if (noisyStdout == NULL)
		goto failInit;

	if (noisyIsatty(noisyStdout)) {
		fputs("stdout is tty. refusing to output ELF.\n", stderr);
		goto fail;
	}

	if (noisyWrite(noisyStdout, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
		goto fail;

	const ssize_t left = context->source.size - sizeof(ehdr);
	if (noisyWrite(noisyStdout,
		       (char *)context->source.buffer + sizeof(ehdr), left)
	    != left)
		goto fail;

	const Elf32_Word shsize = context->shnum * sizeof(*context->shdrs);
	if (noisyWrite(noisyStdout, context->shdrs, shsize) != shsize)
		goto fail;

	Elf32_Off offset = context->source.size + shsize;
	for (Elf32_Word ndx = 0; ndx < context->shnum; ndx++) {
		if (context->sections[ndx] == NULL)
			continue;

		while (offset < context->shdrs[ndx].sh_offset) {
			static const char padding = 0;
			if (noisyWrite(noisyStdout, &padding, sizeof(padding))
			    != sizeof(padding))
				goto fail;

			offset += sizeof(padding);
		}

		if (noisyWrite(noisyStdout, context->sections[ndx],
				context->shdrs[ndx].sh_size)
		    != 1)
			goto fail;

		offset += context->shdrs[ndx].sh_size;
	}

	noisyClose(noisyStdout);
	return 0;

fail:
	if (noisyStdout != NULL)
		noisyClose(noisyStdout);
failInit:
	return -1;
}

void elfDeinit(const struct elf * restrict context)
{
	if (context->shnum > 0) {
		for (Elf32_Word ndx = 0; ndx < context->shnum; ndx++)
			free(context->sections[ndx]);

		free(context->shdrs);
		free(context->sections);
	}

	free(context->source.buffer);
}
