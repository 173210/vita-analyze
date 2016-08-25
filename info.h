/**
 * \file
 * \brief Header file related to module management, ported for vita-analyze
 *
 * Copyright (C) 2015-2016 PSP2SDK Project
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef INFO_H
#define INFO_H

/* Sce types */
typedef Elf32_Word SceUInt;
typedef Elf32_Word SceSize;

typedef struct
{
	SceUInt size;	//< this structure size (0x18)
	SceUInt perms;	//< probably rwx in low bits
	Elf32_Addr vaddr;	//< address in memory
	SceUInt memsz;	//< size in memory
	SceUInt flags;	//< meanig unknown
	SceUInt res;	//< unused?
} SceKernelSegmentInfo;

typedef struct
{
	SceUInt size;	//< 0x1B8 for Vita 1.x
	SceUInt handle;	//< kernel module handle?
	SceUInt flags;	//< some bits. could be priority or whatnot
	char module_name[28];
	SceUInt unk28;
	Elf32_Addr module_start;
	SceUInt unk30;
	Elf32_Addr module_stop;
	Elf32_Addr exidxTop;
	Elf32_Addr exidxBtm;
	SceUInt unk40;
	SceUInt unk44;
	Elf32_Addr tlsInit;
	SceSize tlsInitSize;
	SceSize tlsAreaSize;
	char path[256];
	SceKernelSegmentInfo segments[4];
	SceUInt type;	//< 6 = user-mode PRX?
} SceKernelModuleInfo;

//! Module Information
typedef struct {
	Elf32_Half attr;	//!< Attribute
	Elf32_Half ver;	//!< Version
	char name[27];	//!< Name
	uint8_t type;	//!< Type
	Elf32_Addr gp;	//!< Global Pointer
	Elf32_Word expTop;	//!< Offset of the top of export table
	Elf32_Word expBtm;	//!< Offset of the bottom of export table
	Elf32_Word impTop;	//!< Offset of the top of import table
	Elf32_Word impBtm;	//!< Offset of the bottom of import table
	Elf32_Word nid;	//!< NID
	Elf32_Word unk[3];	//!< Unknown
	Elf32_Word start;	//!< Offset of module_start function
	Elf32_Word stop;	//!< Offset of module_stop function
	Elf32_Word exidxTop;	//!< Offset of the top of exidx section
	Elf32_Word exidxBtm;	//!< Offset of the bottom of exidx section
	Elf32_Word extabTop;	//!< Offset of the top of extab section
	Elf32_Word extabBtm;	//!< Offset of the bottom of extab section
} _sceModuleInfo;

//! The type of structure stored in .sceModuleInfo.rodata section
typedef const _sceModuleInfo SceModuleInfo;

#endif
