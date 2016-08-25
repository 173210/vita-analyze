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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf.h"
#include "elfdriver.h"
#include "info.h"
#include "overflow.h"
#include "safeio.h"

static void *readWhole(const char * restrict path, size_t * restrict size)
{
	struct safeFile * const file = safeFopen(path, "rb");
	if (file == NULL)
		goto failOpen;

	if (safeFseek(file, 0, SEEK_END) != 0)
		goto failSeek;

	const long localSize = safeFtell(file);
	if (localSize < 0)
		goto failTell;

	if (safeFseek(file, 0, SEEK_SET) != 0)
		goto failSeek;

	void * const buffer = malloc(localSize);
	if (buffer == NULL)
		goto failMalloc;

	if (safeFread(buffer, localSize, 1, file) != 1)
		goto failRead;

	safeFclose(file);

	if (size != NULL)
		*size = localSize;

	return buffer;

failRead:
	free(buffer);
failMalloc:
failTell:
failSeek:
	safeFclose(file);
failOpen:
	return NULL;
}

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

enum {
	ELF_SH_NULL,
	ELF_SH_SHSTRTAB,
	ELF_SH_SYMTAB,
	ELF_SH_STRTAB,
	ELF_SH_NUM
};

struct elfImage {
	void * restrict buffer;
	const char *path;
	size_t size;
};

struct elf {
	Elf32_Shdr shdrs[ELF_SH_NUM];
	void *sections[ELF_SH_NUM];
	struct elfImage source;
};

static int elfImageRead(struct elfImage * restrict image,
			const char * restrict path)
{
	image->buffer = readWhole(path, &image->size);
	if (image->buffer == NULL)
		return -1;

	image->path = path;

	return 0;
}

static int elfImageValidatePhdr(const struct elfImage * restrict image)
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

static int elfImageValidate(const struct elfImage * restrict image)
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
				    / sizeof(Elf32_Phdr)) {
			fprintf(stderr, "%s: too many program headers\n",
				image->path);
			result = -1;
		}

		const int phdrResult = elfImageValidatePhdr(image);
		if (result == 0)
			result = phdrResult;
	}

	return result;
}

static int elfInit(struct elf * restrict context,
			   const char * restrict path)
{
	int result;

	result = elfImageRead(&context->source, path);
	if (result == 0) {
		result = elfImageValidate(&context->source);
		if (result != 0)
			free(context->source.buffer);
	}

	return result;
}

struct elfShtStrtab {
	char * restrict buffer;
	Elf32_Word size;
};

static void elfShtStrtabInit(struct elfShtStrtab * restrict context)
{
	context->buffer = NULL;
	context->size = 0;
}

static int elfShtStrtabAdd(Elf32_Word * restrict index,
			   struct elfShtStrtab * restrict context,
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

static void elfShtStrtabFinalize(const struct elfShtStrtab * restrict context,
			      Elf32_Shdr * restrict shdr,
			      void ** restrict buffer,
			      Elf32_Word name, Elf32_Off offset)
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

static void elfShtNullMake(Elf32_Shdr * restrict shdr, Elf32_Word name)
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

static int elfImageFindModuleInfo(
	Elf32_Addr *vaddr,
	const struct elfImage * restrict image,
	const SceKernelModuleInfo * restrict info,
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
		const SceModuleInfo * const moduleInfo
			= (void *)(segment + index);

		if (strcmp(moduleInfo->name, info->module_name) != 0)
			continue;

		Elf32_Word expSize;
		if (wsubOverflow(moduleInfo->expBtm, moduleInfo->expTop,
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
		if (wsubOverflow(moduleInfo->impBtm, moduleInfo->impTop,
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

		*vaddr = phdr->p_vaddr + index;

		exp->top = expTop;
		exp->btm = expBtm;

		imp->top = impTop;
		imp->btm = impBtm;

		return 0;
	}

	fprintf(stderr, "%s: sceModuleInfo not found\n", image->path);
	return -1;
}

static int elfGuessSttFunc(Elf32_Addr vaddr)
{
	return (vaddr & 1) == 0 ? STT_FUNC : STT_ARM_TFUNC;
}

static Elf32_Off elfImageVaddrToOff(const struct elfImage * restrict image,
				    Elf32_Addr vaddr,
				    Elf32_Word * restrict size)
{
	const void * const buffer = image->buffer;
	const Elf32_Ehdr * const ehdr = buffer;
	const Elf32_Phdr * const phdrsTop
		= (void *)((char *)buffer + ehdr->e_phoff);
	const Elf32_Phdr * const phdrsBtm = phdrsTop + ehdr->e_phnum;

	for (const Elf32_Phdr *phdr = phdrsTop; phdr != phdrsBtm; phdr++) {
		Elf32_Word topOff;
		if (wsubOverflow(vaddr, phdr->p_vaddr, &topOff))
			continue;

		if (wsubOverflow(phdr->p_filesz, topOff, size))
			continue;

		return phdr->p_offset + topOff;
	}

	return 0;
}

static const void *elfImageOffToPtr(const struct elfImage * restrict image,
				    Elf32_Off offset)
{
	return (char *)image->buffer + offset;
}

static const void *elfImageVaddrToPtr(const struct elfImage * restrict image,
				      Elf32_Addr vaddr,
				      Elf32_Word * restrict size)
{
	const Elf32_Off offset = elfImageVaddrToOff(image, vaddr, size);
	return offset > 0 ? elfImageOffToPtr(image, offset) : NULL;
}

static Elf32_Sword elfImageExpSum(const struct elfImageExp * restrict exp,
				  const struct elfImage * restrict image)
{
	Elf32_Word sum;

	sum = 0;

	for (const struct elfExp *cursor = exp->top;
	     cursor != exp->btm;
	     cursor++) {
		if (waddOverflow(sum, cursor->nFuncs, &sum))
			goto failOverflow;

		if (waddOverflow(sum, cursor->nVars, &sum))
			goto failOverflow;
	}

	if (sum >= 0x80000000)
		goto failOverflow;

	return sum;

failOverflow:
	fprintf(stderr, "%s: too many exports\n", image->path);
	return -1;
}

static int elfShtSymtabMakeExp(const struct elfImageExp * restrict exp,
			       const struct elfImage * restrict image,
			       Elf32_Sym * restrict syms,
			       struct elfShtStrtab * restrict strtab)
{
	const char *name;
	Elf32_Word nameSize;
	int result;

	for (const struct elfExp *cursor = exp->top;
	     cursor != exp->btm;
	     cursor++) {
		const Elf32_Word total = cursor->nFuncs + cursor->nVars;

		if (cursor->name == 0) {
			name = "export";
			nameSize = sizeof("export");
		} else {
			name = elfImageVaddrToPtr(image, cursor->name,
						  &nameSize);
			if (name == NULL)
				goto failNamePtr;

			if (memchr(name, 0, nameSize) == NULL)
				goto failNameTooLong;
		}

		Elf32_Word words;
		if (wmulOverflow(total, 4, &words))
			goto failTooMany;

		Elf32_Word nidsMax;
		const Elf32_Word *nid =
			elfImageVaddrToPtr(image, cursor->nids, &nidsMax);
		if (nid == NULL)
			goto failNidsPtr;

		if (nidsMax < words)
			goto failTooMany;

		Elf32_Word entriesMax;
		const Elf32_Word *entry =
			elfImageVaddrToPtr(image, cursor->entries, &entriesMax);
		if (entry == NULL)
			goto failEntriesPtr;

		if (entriesMax < words)
			goto failTooMany;

		for (Elf32_Half count = 0;
		     count < cursor->nFuncs;
		     count++) {
			result = elfShtStrtabAdd(
				&syms->st_name, strtab, nameSize + 9,
				"%s_%08X", name, *nid);
			if (result < 0)
				goto failStrtab;

			syms->st_value = *entry;
			syms->st_size = 0;
			syms->st_info = ELF32_ST_INFO(
				STB_GLOBAL, elfGuessSttFunc(*entry));
			syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
			syms->st_shndx = 0;

			syms++;
			nid++;
			entry++;
		}

		for (Elf32_Half count = 0;
		     count < cursor->nVars;
		     count++) {
			result = elfShtStrtabAdd(
				&syms->st_name, strtab, nameSize + 9,
				"%s_%08X", name, *nid);
			if (result < 0)
				goto failStrtab;

			syms->st_value = *entry;
			syms->st_size = 4;
			syms->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
			syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
			syms->st_shndx = 0;

			syms++;
			nid++;
			entry++;
		}
	}

	return 0;

failNamePtr:
	fprintf(stderr, "%s: export name is not located in file\n",
		image->path);
	return -1;

failNameTooLong:
	fprintf(stderr, "%s: export name is too long\n",
		image->path);
	return -1;

failTooMany:
	fprintf(stderr, "%s: %s: too many exports\n", image->path, name);
	return -1;

failNidsPtr:
	fprintf(stderr, "%s: %s: export nid table is not located in file\n",
		image->path, name);
	return -1;

failEntriesPtr:
	fprintf(stderr, "%s: %s: export entry table is not located in file\n",
		image->path, name);
	return -1;

failStrtab:
	return result;
}

static Elf32_Sword elfImageImpSum(const struct elfImageImp * restrict imp,
				  const struct elfImage * restrict image)
{
	Elf32_Word sum;

	sum = 0;

	for (const struct elfImp *cursor = imp->top;
	     cursor != imp->btm;
	     cursor = (void *)((char *)cursor + cursor->size)) {
		/* TODO: DEBUG */
		fprintf(stderr,
			"size: %u\n"
			"version: 0x%04X\n"
			"attribute: 0x%04X\n"
			"nFuncs: 0x%04X\n"
			"nVars: 0x%04X\n"
			"nTls: 0x%04X\n"
			"unknown0: 0x%08X\n"
			"nid: 0x%08X\n"
			"name: 0x%08X\n"
			"unknown1: 0x%08X\n"
			"funcNids: 0x%08X\n"
			"funcEntries: 0x%08X\n"
			"varNids: 0x%08X\n"
			"varEntries: 0x%08X\n"
			"tlsNids: 0x%08X\n"
			"tlsEntries: 0x%08X\n",
			cursor->size,
			cursor->version,
			cursor->attribute,
			cursor->nFuncs,
			cursor->nVars,
			cursor->nTls,
			cursor->unknown0,
			cursor->nid,
			cursor->name,
			cursor->unknown1,
			cursor->funcNids,
			cursor->funcEntries,
			cursor->varNids,
			cursor->varEntries,
			cursor->tlsNids,
			cursor->tlsEntries);

		if (waddOverflow(sum, cursor->nFuncs, &sum))
			goto failOverflow;

		if (waddOverflow(sum, cursor->nVars, &sum))
			goto failOverflow;

		if (cursor->size >= sizeof(struct elfImp))
			if (waddOverflow(sum, cursor->nTls, &sum))
				goto failOverflow;
	}

	if (sum > 0x80000000)
		goto failOverflow;

	return sum;

failOverflow:
	fprintf(stderr, "%s: too many imports\n", image->path);
	return -1;
}

static int elfShtSymtabMakeTable(const struct elfImage * restrict image,
				 const char * restrict name,
				 Elf32_Word nameSize,
				 Elf32_Addr nids, Elf32_Addr entries,
				 Elf32_Word n,
				 Elf32_Word st_size, Elf32_Word stt,
				 Elf32_Sym * restrict syms,
				 struct elfShtStrtab * restrict strtab)
{
	const char *error;
	int result;

	if (n <= 0)
		goto success;

	Elf32_Word words;
	if (wmulOverflow(n, 4, &words)) {
		error = "too many entries";
		goto fail;
	}

	Elf32_Word nidsMax;
	const Elf32_Word *nid = elfImageVaddrToPtr(image, nids, &nidsMax);
	if (nid == NULL) {
		error = "DEBUG: nid table is not located in file";
		goto fail;
	}

	if (nidsMax < words) {
		error = "nid table doesn't fit in file";
		goto fail;
	}

	Elf32_Word entriesMax;
	const Elf32_Word *entry
		= elfImageVaddrToPtr(image, entries, &entriesMax);
	if (entry == NULL) {
		error = "entry table is not located in file";
		goto fail;
	}

	if (entriesMax < words) {
		error = "entry table doesn't fit in file";
		goto fail;
	}

	while (n > 0) {
		result = elfShtStrtabAdd(&syms->st_name, strtab, nameSize + 9,
					 "%s_%08X", name, *nid);
		if (result < 0)
			goto failSymbol;

		syms->st_value = *entry;
		syms->st_size = st_size;
		syms->st_info = ELF32_ST_INFO(STB_GLOBAL, stt);
		syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
		syms->st_shndx = 0;

		syms++;
		nid++;
		entry++;
		n--;
	}

success:
	return 0;

failSymbol:
	fprintf(stderr, "%s: %s: failed to construct symbol name for function 0x%08X\n",
		image->path, name, *nid);
	return result;

fail:
	fprintf(stderr, "%s: %s: %s\n", image->path, name, error);
	return -1;
}

static int elfShtSymtabMakeImp(const struct elfImageImp * restrict imp,
			       const struct elfImage * restrict image,
			       Elf32_Sym * restrict syms,
			       struct elfShtStrtab * restrict strtab)
{
	const char *name;
	Elf32_Word nameSize;
	int result;

	for (const struct elfImp *cursor = imp->top;
	     cursor != imp->btm;
	     cursor++) {
		if (cursor->name == 0) {
			name = "import";
			nameSize = sizeof("import");
		} else {
			name = elfImageVaddrToPtr(image, cursor->name,
						  &nameSize);
			if (name == NULL)
				goto failNamePtr;

			if (memchr(name, 0, nameSize) == NULL)
				goto failNameTooLong;
		}

		result = elfShtSymtabMakeTable(
			image, name, nameSize,
			cursor->funcNids, cursor->funcEntries,
			cursor->nFuncs, 16, STT_FUNC, syms, strtab);
		if (result != 0)
			goto failTable;

		syms += cursor->nFuncs;
		result = elfShtSymtabMakeTable(
			image, name, nameSize,
			cursor->varNids, cursor->varEntries,
			cursor->nVars, 0, STT_OBJECT, syms, strtab);
		if (result != 0)
			goto failTable;

		if (cursor->size >= sizeof(*cursor)) {
			syms += cursor->nVars;
			result = elfShtSymtabMakeTable(
				image, name, nameSize,
				cursor->tlsNids, cursor->tlsEntries,
				cursor->nTls, 4, STT_TLS, syms, strtab);
			if (result != 0)
				goto failTable;
		}
	}

	return 0;

failNamePtr:
	fprintf(stderr, "%s: export name is not located in file\n",
		image->path);
	return -1;

failNameTooLong:
	fprintf(stderr, "%s: export name is too long\n",
		image->path);
	return -1;

failTable:
	return -1;
}

static int elfImageModuleInfoSymMake(Elf32_Addr vaddr,
				     Elf32_Sym * restrict sym,
				     struct elfShtStrtab * restrict strtab)
{
	const int result = elfShtStrtabAdd(
		&sym->st_name, strtab, sizeof("module_info"), "module_info");
	if (result < 0)
		return result;

	sym->st_value = vaddr;
	sym->st_size = sizeof(SceModuleInfo);
	sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
	sym->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
	sym->st_shndx = 0;

	return 0;
}

static Elf32_Word elfImageInfoSymSum(const SceKernelModuleInfo *info)
{
	Elf32_Word sum;

	sum = 0;
	if (info->module_start != 0)
		sum++;

	if (info->module_stop != 0)
		sum++;

	return sum;
}

static int elfImageInfoSymMake(const SceKernelModuleInfo *info,
			       Elf32_Sym * restrict syms,
			       struct elfShtStrtab * restrict strtab)
{
	int result;

	if (info->module_start != 0) {
		result = elfShtStrtabAdd(
			&syms->st_name, strtab,
			sizeof("module_start"), "module_start");
		if (result < 0)
			return result;

		syms->st_value = info->module_start;
		syms->st_size = 0;
		syms->st_info = ELF32_ST_INFO(
			STB_GLOBAL, elfGuessSttFunc(info->module_start));
		syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
		syms->st_shndx = 0;
		syms++;
	}

	if (info->module_stop != 0) {
		result = elfShtStrtabAdd(&syms->st_name, strtab,
					 sizeof("module_stop"), "module_stop");
		if (result < 0)
			return result;

		syms->st_value = info->module_stop;
		syms->st_size = 0;
		syms->st_info = ELF32_ST_INFO(
			STB_GLOBAL, elfGuessSttFunc(info->module_stop));
		syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
		syms->st_shndx = 0;
	}

	return 0;
}

static int elfShtSymtabMake(Elf32_Shdr * restrict shdr,
			    void ** restrict buffer,
			    const struct elfImage * restrict image,
			    const SceKernelModuleInfo * restrict info,
			    struct elfShtStrtab * restrict strtab,
			    Elf32_Word strtabIndex,
			    Elf32_Word name, Elf32_Off offset)
{
	struct elfImageExp exp;
	struct elfImageImp imp;
	Elf32_Addr moduleInfo;
	int result;

	result = elfImageFindModuleInfo(&moduleInfo, image, info, &exp, &imp);
	if (result != 0)
		goto failNoModuleInfo;

	const Elf32_Word infoSymSum = elfImageInfoSymSum(info);

	const Elf32_Sword expSum = elfImageExpSum(&exp, image);
	if (expSum < 0)
		goto failNoExp;

	const Elf32_Sword impSum = elfImageImpSum(&imp, image);
	if (impSum < 0)
		goto failNoImp;

	shdr->sh_name = name;
	shdr->sh_type = SHT_SYMTAB;
	shdr->sh_flags = 0;
	shdr->sh_addr = 0;
	shdr->sh_link = strtabIndex;
	shdr->sh_addralign = 4;
	shdr->sh_entsize = sizeof(Elf32_Sym);

	/* TODO: fail0verflow */
	shdr->sh_info = 1 + infoSymSum + expSum + impSum;
	shdr->sh_size = shdr->sh_info * shdr->sh_entsize;

	const Elf32_Off mod = offset % shdr->sh_addralign;
	if (mod)
		offset += shdr->sh_addralign - mod;

	shdr->sh_offset = offset;

	Elf32_Sym * const syms = malloc(shdr->sh_size);
	if (syms == NULL) {
		perror(NULL);
		result = -1;
		goto failMalloc;
	}

	Elf32_Sym *cursor = syms;

	result = elfImageModuleInfoSymMake(moduleInfo, cursor, strtab);
	if (result < 0)
		goto failSym;

	cursor++;
	result = elfImageInfoSymMake(info, cursor, strtab);
	if (result < 0)
		goto failSym;

	cursor += infoSymSum;
	result = elfShtSymtabMakeExp(&exp, image, cursor, strtab);
	if (result < 0)
		goto failSym;

	cursor += expSum;
	result = elfShtSymtabMakeImp(&imp, image, syms + 3 + expSum, strtab);
	if (result < 0)
		goto failSym;

	*buffer = syms;
	return 0;

failSym:
	free(syms);
failMalloc:
failNoExp:
failNoImp:
failNoModuleInfo:
	return result;
}

static int elfMakeSections(struct elf * restrict context,
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
	struct elfShtStrtab shstrtab;
	struct elfShtStrtab strtab;
	Elf32_Word shstrtabNames[ELF_SH_NUM];
	int result;

	elfShtStrtabInit(&shstrtab);

	for (unsigned int index = 0; index < ELF_SH_NUM; index++) {
		result = elfShtStrtabAdd(&shstrtabNames[index], &shstrtab,
					 names[index].size,
					 names[index].string);
		if (result < 0)
			return result;
	}

	elfShtNullMake(context->shdrs + ELF_SH_NULL,
			   shstrtabNames[ELF_SH_NULL]);

	elfShtStrtabFinalize(&shstrtab, context->shdrs + ELF_SH_SHSTRTAB,
			     context->sections + ELF_SH_SHSTRTAB,
			     shstrtabNames[ELF_SH_SHSTRTAB],
			     context->source.size + sizeof(context->shdrs));


	elfShtStrtabInit(&strtab);

	SceKernelModuleInfo * const info = readInfo(infoPath);
	if (info == NULL)
		return -1;

	result = elfShtSymtabMake(context->shdrs + ELF_SH_SYMTAB,
				  context->sections + ELF_SH_SYMTAB,
				  &context->source, info,
				  &strtab, ELF_SH_STRTAB,
				  shstrtabNames[ELF_SH_SYMTAB],
				  context->shdrs[ELF_SH_SHSTRTAB].sh_offset
				  + context->shdrs[ELF_SH_SHSTRTAB].sh_size);

	free(info);

	elfShtStrtabFinalize(&strtab, context->shdrs + ELF_SH_STRTAB,
			     context->sections + ELF_SH_STRTAB,
			     shstrtabNames[ELF_SH_STRTAB],
			     context->shdrs[ELF_SH_SYMTAB].sh_offset
			     + context->shdrs[ELF_SH_SYMTAB].sh_size);

	return result;
}

static int elfWrite(struct elf *context)
{
	Elf32_Ehdr ehdr;

	memcpy(&ehdr, context->source.buffer, sizeof(ehdr));
	ehdr.e_shoff = context->source.size;
	ehdr.e_shentsize = sizeof(Elf32_Shdr);
	ehdr.e_shnum = ELF_SH_NUM;
	ehdr.e_shstrndx = ELF_SH_SHSTRTAB;

	struct safeFile *safeStdout = safeGetStdout();
	if (safeStdout == NULL)
		goto failInit;

	if (safeFwrite(&ehdr, sizeof(ehdr), 1, safeStdout) != 1)
		goto fail;

	if (safeFwrite((char *)context->source.buffer + sizeof(ehdr),
		       context->source.size - sizeof(ehdr), 1, safeStdout) != 1)
		goto fail;

	if (safeFwrite(context->shdrs, sizeof(context->shdrs), 1, safeStdout)
	    != 1)
		goto fail;

	Elf32_Off offset = context->source.size + sizeof(context->shdrs);
	for (Elf32_Word index = 0; index < ELF_SH_NUM; index++) {
		if (context->shdrs[index].sh_size <= 0)
			continue;

		while (offset < context->shdrs[index].sh_offset) {
			if (safeFputc(0, safeStdout) != 0)
				goto fail;

			offset++;
		}

		if (safeFwrite(context->sections[index],
			       context->shdrs[index].sh_size, 1, safeStdout)
		    != 1)
			goto fail;

		offset += context->shdrs[index].sh_size;
	}

	safeFclose(safeStdout);
	return 0;

fail:
	safeFclose(safeStdout);
failInit:
	return -1;
}

static void elfDeinit(const struct elf * restrict context)
{
	free(context->source.buffer);
}

int main(int argc, char *argv[])
{
	struct elf elf;

	if (argc != 3)
		goto failInval;

	if (elfInit(&elf, argv[1]) != 0)
		goto failElfInit;

	if (elfMakeSections(&elf, argv[2]) != 0)
		goto failElfMakeSections;

	if (elfWrite(&elf) != 0)
		goto failElfWrite;

	elfDeinit(&elf);
	return EXIT_SUCCESS;

failInval:
	fprintf(stderr, "usage: %s <DUMP.ELF> <INFO.BIN>\n",
		argc > 0 ? argv[0] : "<EXECUTABLE>");

	return EXIT_FAILURE;

failElfMakeSections:
failElfWrite:
	elfDeinit(&elf);
failElfInit:
	return EXIT_FAILURE;
}
