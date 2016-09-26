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

#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../noisy/lib.h"
#include "../../vita-import/helper.h"
#include "../../vita-import/vita-import.h"
#include "../../overflow.h"
#include "../driver.h"
#include "../elf.h"
#include "symtab.h"

static int guessSttFunc(Elf32_Addr vaddr)
{
	return (vaddr & 1) == 0 ? STT_FUNC : STT_ARM_TFUNC;
}

static Elf32_Sword expSymSumUp(const struct elfImageExp * restrict exp,
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

static Elf32_Sword impSymSumUp(const struct elfImageImp * restrict imp,
			       const struct elfImage * restrict image)
{
	Elf32_Word sum;

	sum = 0;

	for (const struct elfImp *cursor = imp->top;
	     cursor != imp->btm;
	     cursor = (void *)((char *)cursor + cursor->size)) {
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

static int notypeSymMake(Elf32_Sym * restrict sym,
			  struct elfSectionStrtab * restrict strtab)
{
	const int result = elfSectionStrtabAdd(
		&sym->st_name, strtab, sizeof(""), "");
	if (result < 0)
		return result;

	sym->st_value = 0;
	sym->st_size = 0;
	sym->st_info = ELF32_ST_INFO(STB_LOCAL, STT_NOTYPE);
	sym->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
	sym->st_shndx = SHN_UNDEF;

	return 0;
}

static int infoSymMake(Elf32_Addr vaddr, Elf32_Sym * restrict sym,
			     struct elfSectionStrtab * restrict strtab)
{
	const int result = elfSectionStrtabAdd(
		&sym->st_name, strtab, sizeof("module_info"), "module_info");
	if (result < 0)
		return result;

	sym->st_value = vaddr;
	sym->st_size = sizeof(SceModuleInfo);
	sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
	sym->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);
	sym->st_shndx = ELF_LOADNDX;

	return 0;
}

static int expSymMake(const SceKernelModuleInfo * restrict kernelInfo,
		      const struct elfImageExp * restrict exp,
		      const struct elfImage * restrict image,
		      vita_imports_t * restrict vitaImp,
		      Elf32_Sym * restrict syms,
		      struct elfSectionStrtab * restrict strtab)
{
	static const char nullName[] = "null";
	const char *name;
	Elf32_Word nameSize;
	int result;

	/* The NID can vary with the firmware, so use the name instead. */
	vita_imports_lib_t * const lib
		= vitaImportsFindLibByName(vitaImp, kernelInfo->module_name);
	if (lib == NULL)
		fprintf(stderr, "warning: library \"%s\" not found\n",
			kernelInfo->module_name);

	for (const struct elfExp *cursor = exp->top;
	     cursor != exp->btm;
	     cursor++) {
		const Elf32_Word total = cursor->nFuncs + cursor->nVars;
		Elf32_Word maximum;

		if (cursor->name == 0) {
			name = nullName;
			nameSize = sizeof(nullName);
		} else {
			name = elfImageVaddrToPtr(image, cursor->name, 0,
						  &maximum);
			if (name == NULL)
				goto failNamePtr;

			nameSize = strnlen(name, maximum);
			if (nameSize >= maximum)
				goto failNameTooLong;

			nameSize++;
		}

		vita_imports_module_t *module;
		if (lib == NULL) {
			module = NULL;
		} else {
			module = vita_imports_find_module(lib, cursor->nid);
			if (module == NULL)
				fprintf(stderr, "warning: module \"%s\" (NID: 0x%08X) not found\n",
					name, cursor->nid);
		}

		Elf32_Word words;
		if (wmulOverflow(total, 4, &words))
			goto failTooMany;

		const Elf32_Word *nid =
			elfImageVaddrToPtr(image, cursor->nids, words, NULL);
		if (nid == NULL)
			goto failNidsPtr;

		const Elf32_Word *entry =
			elfImageVaddrToPtr(image, cursor->entries, words, NULL);
		if (entry == NULL)
			goto failEntriesPtr;

		for (Elf32_Half count = 0;
		     count < cursor->nFuncs;
		     count++) {
			const char *entryName = NULL;
			Elf32_Word entryNameSize;
			if (name == nullName) {
#define ENTRY(nid, name) { nid, sizeof(name), name }
				static const struct {
					Elf32_Word nid;
					size_t size;
					const char name[14];
				} funcs[] = {
					ENTRY(0x79F8E492, "module_stop"),
					ENTRY(0x913482A9, "module_exit"),
					ENTRY(0x935CD196, "module_start")
				};
#undef ENTRY

				for (unsigned int i = 0;
				     i < sizeof(funcs) / sizeof(*funcs);
				     i++) {
					if (funcs[i].nid == *nid) {
						entryName = funcs[i].name;
						entryNameSize = funcs[i].size;
						break;
					}
				}
			} else if (module != NULL) {
				const vita_imports_stub_t * const stub
					= vita_imports_find_function(
						module, *nid);
				if (stub == NULL) {
					fprintf(stderr, "warning: function NID 0x%08X not found\n",
						*nid);
				} else {
					entryName = stub->name;
					entryNameSize = strlen(stub->name) + 1;
				}
			}

			result = entryName == NULL ?
				elfSectionStrtabAdd(
					&syms->st_name, strtab, nameSize + 9,
					"%s_%08X", name, *nid) :
				elfSectionStrtabAdd(
					&syms->st_name, strtab,
					entryNameSize, entryName);
			if (result < 0)
				goto failStrtab;

			syms->st_value = *entry;
			syms->st_size = 0;
			syms->st_info = ELF32_ST_INFO(
				STB_GLOBAL, guessSttFunc(*entry));
			syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);

			Elf32_Word phndx;
			if (elfImageGetPhndxByVaddr(image, *entry, 0,
						    &phndx, NULL))
				syms->st_shndx = SHN_ABS;
			else
				syms->st_shndx = ELF_LOADNDX + phndx;

			syms++;
			nid++;
			entry++;
		}

		for (Elf32_Half count = 0;
		     count < cursor->nVars;
		     count++) {
			const char *entryName = NULL;
			Elf32_Word entryNameSize;
			if (name == nullName) {
				if (*nid == 0x6C2224BA) {
					entryName = "module_info";
					entryNameSize = sizeof("module_info");
				}
			} else if (module != NULL) {
				const vita_imports_stub_t * const stub
					= vita_imports_find_variable(
						module, *nid);
				if (stub == NULL) {
					fprintf(stderr, "warning: variable NID 0x%08X not found\n",
						*nid);
				} else {
					entryName = stub->name;
					entryNameSize = strlen(stub->name) + 1;
				}
			}

			result = entryName == NULL ?
				elfSectionStrtabAdd(
					&syms->st_name, strtab, nameSize + 9,
					"%s_%08X", name, *nid) :
				elfSectionStrtabAdd(
					&syms->st_name, strtab,
					entryNameSize, entryName);
			if (result < 0)
				goto failStrtab;

			syms->st_value = *entry;
			syms->st_size = 4;
			syms->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
			syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);

			Elf32_Word phndx;
			if (elfImageGetPhndxByVaddr(image, *entry, 4,
						    &phndx, NULL))
				syms->st_shndx = SHN_ABS;
			else
				syms->st_shndx = ELF_LOADNDX + phndx;

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

static int makeTable(const struct elfImage * restrict image,
		     const char * restrict name, Elf32_Word nameSize,
		     vita_imports_module_t * restrict module,
		     vita_imports_stub_t *(* findStub)(
				vita_imports_module_t *mod, uint32_t NID),
		     Elf32_Addr nids, Elf32_Addr entries,
		     Elf32_Word n, Elf32_Word st_size, Elf32_Word stt,
		     Elf32_Sym * restrict syms,
		     struct elfSectionStrtab * restrict strtab)
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

	const Elf32_Word *nid = elfImageVaddrToPtr(image, nids, words, NULL);
	if (nid == NULL) {
		error = "nid table is not located in file";
		goto fail;
	}

	const Elf32_Word *entry
		= elfImageVaddrToPtr(image, entries, words, NULL);
	if (entry == NULL) {
		error = "entry table is not located in file";
		goto fail;
	}

	while (n > 0) {
		const vita_imports_stub_t *stub;
		stub = module == NULL || findStub == NULL ?
			NULL : findStub(module, *nid);

		result = stub == NULL ?
			elfSectionStrtabAdd(&syms->st_name, strtab,
				nameSize + 9, "%s_%08X", name, *nid) :
			elfSectionStrtabAdd(&syms->st_name, strtab,
				nameSize + 9, stub->name);
		if (result < 0)
			goto failSymbol;

		syms->st_value = *entry;
		syms->st_size = st_size;
		syms->st_info = ELF32_ST_INFO(STB_GLOBAL, stt);
		syms->st_other = ELF32_ST_VISIBILITY(STV_DEFAULT);

		Elf32_Word phndx;
		if (elfImageGetPhndxByVaddr(image, *entry, st_size,
					    &phndx, NULL))
			syms->st_shndx = SHN_ABS;
		else
			syms->st_shndx = ELF_LOADNDX + phndx;

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

static int impSymMake(const struct elfImageImp * restrict imp,
		      const struct elfImage * restrict image,
		      vita_imports_t *vitaImp,
		      Elf32_Sym * restrict syms,
		      struct elfSectionStrtab * restrict strtab)
{
	const char *name;
	Elf32_Word nameSize;
	int result;

	for (const struct elfImp *cursor = imp->top;
	     cursor != imp->btm;
	     cursor++) {
		if (cursor->name == 0) {
			name = "null";
			nameSize = sizeof("null");
		} else {
			Elf32_Word maximum;

			name = elfImageVaddrToPtr(image, cursor->name, 0,
						  &maximum);
			if (name == NULL)
				goto failNamePtr;

			nameSize = strnlen(name, maximum);
			if (nameSize >= maximum)
				goto failNameTooLong;

			nameSize++;
		}

		vita_imports_module_t * const module
			= vitaImportsFindModuleInAll(vitaImp, cursor->nid);
		if (module == NULL)
			fprintf(stderr, "warning: module \"%s\" (NID: 0x%08X) not found\n",
				name, cursor->nid);

		result = makeTable(image, name, nameSize, module,
				   vita_imports_find_function,
				   cursor->funcNids, cursor->funcEntries,
				   cursor->nFuncs, 16, STT_FUNC, syms, strtab);
		if (result != 0)
			goto failTable;

		syms += cursor->nFuncs;
		result = makeTable(image, name, nameSize, module,
				   vita_imports_find_variable,
				   cursor->varNids, cursor->varEntries,
				   cursor->nVars, 0, STT_OBJECT, syms, strtab);
		if (result != 0)
			goto failTable;

		if (cursor->size >= sizeof(*cursor)) {
			syms += cursor->nVars;
			result = makeTable(
				image, name, nameSize, NULL, NULL,
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

int elfSectionSymtabMake(const struct elfImage * restrict image,
			 const SceKernelModuleInfo * restrict kernelInfo,
			 struct elfSectionStrtab * restrict strtab,
			 Elf32_Word strtabNdx,
			 Elf32_Word name, Elf32_Off offset,
			 Elf32_Shdr * restrict shdr,
			 void ** restrict buffer)
{
	struct elfImageExp exp;
	struct elfImageImp imp;
	Elf32_Addr info;
	int result;

	result = elfImageFindInfo(image, kernelInfo, &info, &exp, &imp);
	if (result != 0)
		goto failNoInfo;

	const Elf32_Sword expSum = expSymSumUp(&exp, image);
	if (expSum < 0)
		goto failNoExp;

	const Elf32_Sword impSum = impSymSumUp(&imp, image);
	if (impSum < 0)
		goto failNoImp;

	shdr->sh_name = name;
	shdr->sh_type = SHT_SYMTAB;
	shdr->sh_flags = 0;
	shdr->sh_addr = 0;
	shdr->sh_link = strtabNdx;
	shdr->sh_info = 1;
	shdr->sh_addralign = 4;
	shdr->sh_entsize = sizeof(Elf32_Sym);

	Elf32_Word nSyms;
	if (waddOverflow(2, expSum, &nSyms))
		goto failTooMany;

	if (waddOverflow(nSyms, impSum, &nSyms))
		goto failTooMany;

	if (wmulOverflow(nSyms, shdr->sh_entsize, &shdr->sh_size))
		goto failTooMany;

	const Elf32_Off mod = offset % shdr->sh_addralign;
	if (mod)
		offset += shdr->sh_addralign - mod;

	shdr->sh_offset = offset;

	Elf32_Sym * const syms = noisyMalloc(shdr->sh_size);
	if (syms == NULL) {
		result = -1;
		goto failMalloc;
	}

	Elf32_Sym *cursor = syms;

	result = notypeSymMake(cursor, strtab);
	if (result < 0)
		goto failSym;

	cursor++;
	result = infoSymMake(info, cursor, strtab);
	if (result < 0)
		goto failSym;

	cursor++;
	vita_imports_t * const imports = vitaImportsLoad();
	if (imports == NULL)
		goto failSym;

	result = expSymMake(kernelInfo, &exp, image, imports, cursor, strtab);
	if (result < 0)
		goto failSym;

	cursor += expSum;
	result = impSymMake(&imp, image, imports, cursor, strtab);
	if (result < 0)
		goto failSym;

	vita_imports_free(imports);

	*buffer = syms;
	return 0;

failSym:
	free(syms);
failMalloc:
failNoExp:
failNoImp:
failNoInfo:
	return result;

failTooMany:
	fprintf(stderr, "%s: too many symbols\n", image->path);
	return -1;
}
