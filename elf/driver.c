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
#include "../noisy/io.h"
#include "../noisy/lib.h"
#include "../overflow.h"
#include "../readwhole.h"
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

		for (int ndx = 0; ndx < ELF_SH_NUM; ndx++)
			context->sections[ndx] = NULL;
	}

	return result;
}


int elfMakeSections(struct elf * restrict context,
		    const char * restrict infoPath)
{
#define NAME(string) { string, sizeof(string) }
	static struct {
		const char *string;
		size_t size;
	} names[ELF_SH_NUM] = {
		[ELF_SH_NULL] = NAME(""),
		[ELF_SH_SHSTRTAB] = NAME(".shstrtab"),
		[ELF_SH_SYMTAB] = NAME(".symtab"),
		[ELF_SH_STRTAB] = NAME(".strtab")
	};
	struct elfSectionStrtab shstrtab;
	struct elfSectionStrtab strtab;
	Elf32_Word shstrtabNames[ELF_SH_NUM];
	int result;

	elfSectionStrtabInit(&shstrtab);

	for (int ndx = 0; ndx < ELF_SH_NUM; ndx++) {
		result = elfSectionStrtabAdd(&shstrtabNames[ndx], &shstrtab,
					     names[ndx].size,
					     names[ndx].string);
		if (result < 0)
			goto failShstrtab;
	}

	elfSectionNullMake(shstrtabNames[ELF_SH_NULL],
			   context->shdrs + ELF_SH_NULL,
			   context->sections + ELF_SH_NULL);

	elfSectionStrtabFinalize(&shstrtab, shstrtabNames[ELF_SH_SHSTRTAB],
				 context->source.size + sizeof(context->shdrs),
				 context->shdrs + ELF_SH_SHSTRTAB,
				 context->sections + ELF_SH_SHSTRTAB);

	elfSectionStrtabInit(&strtab);

	SceKernelModuleInfo * const info = readInfo(infoPath);
	if (info == NULL)
		goto failInfo;

	result = elfSectionSymtabMake(&context->source, info, &strtab,
				      ELF_SH_STRTAB,
				      shstrtabNames[ELF_SH_SYMTAB],
				      context->shdrs[ELF_SH_SHSTRTAB].sh_offset
				      + context->shdrs[ELF_SH_SHSTRTAB].sh_size,
				      context->shdrs + ELF_SH_SYMTAB,
				      context->sections + ELF_SH_SYMTAB);
	if (result != 0)
		goto failSymtab;

	free(info);

	elfSectionStrtabFinalize(&strtab,
				 shstrtabNames[ELF_SH_STRTAB],
				 context->shdrs[ELF_SH_SYMTAB].sh_offset
				 + context->shdrs[ELF_SH_SYMTAB].sh_size,
				 context->shdrs + ELF_SH_STRTAB,
				 context->sections + ELF_SH_STRTAB);

	return result;

failSymtab:
	free(info);
failInfo:
	elfSectionStrtabDispose(&strtab);
failShstrtab:
	elfSectionStrtabDispose(&shstrtab);
	return result;
}

int elfWrite(struct elf *context)
{
	Elf32_Ehdr ehdr;

	memcpy(&ehdr, context->source.buffer, sizeof(ehdr));

	/* BFD doesn't accept sections if e_type is ET_CORE. */
	ehdr.e_type = ET_NONE;

	ehdr.e_shoff = context->source.size;
	ehdr.e_shentsize = sizeof(Elf32_Shdr);
	ehdr.e_shnum = ELF_SH_NUM;
	ehdr.e_shstrndx = ELF_SH_SHSTRTAB;

	struct noisyFile *noisyStdout = noisyGetStdout();
	if (noisyStdout == NULL)
		goto failInit;

	if (noisyFwrite(&ehdr, sizeof(ehdr), 1, noisyStdout) != 1)
		goto fail;

	if (noisyFwrite((char *)context->source.buffer + sizeof(ehdr),
		       context->source.size - sizeof(ehdr), 1, noisyStdout) != 1)
		goto fail;

	if (noisyFwrite(context->shdrs, sizeof(context->shdrs), 1, noisyStdout)
	    != 1)
		goto fail;

	Elf32_Off offset = context->source.size + sizeof(context->shdrs);
	for (int ndx = 0; ndx < ELF_SH_NUM; ndx++) {
		if (context->sections[ndx] == NULL)
			continue;

		while (offset < context->shdrs[ndx].sh_offset) {
			if (noisyFputc(0, noisyStdout) != 0)
				goto fail;

			offset++;
		}

		if (noisyFwrite(context->sections[ndx],
				context->shdrs[ndx].sh_size, 1, noisyStdout)
		    != 1)
			goto fail;

		offset += context->shdrs[ndx].sh_size;
	}

	noisyFclose(noisyStdout);
	return 0;

fail:
	noisyFclose(noisyStdout);
failInit:
	return -1;
}

void elfDeinit(const struct elf * restrict context)
{
	for (Elf32_Word ndx = 0; ndx < ELF_SH_NUM; ndx++)
		free(context->sections[ndx]);

	free(context->source.buffer);
}
