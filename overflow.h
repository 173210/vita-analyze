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

#ifndef OVERFLOW_H
#define OVERFLOW_H

#include <stdbool.h>
#include "elf/elf.h"

static inline bool waddOverflow(Elf32_Word h, Elf32_Word i, Elf32_Word *result)
{
#ifdef __GNUC__
	return __builtin_add_overflow(h, i, result);
#else
	if (h > 0xFFFFFFFF - i)
		return true;

	*result = h + i;
	return false;
#endif
}

static inline bool wsubOverflow(Elf32_Word h, Elf32_Word i, Elf32_Word *result)
{
#ifdef __GNUC__
	return __builtin_sub_overflow(h, i, result);
#else
	if (h < i)
		return true;

	*result = h - i;
	return false;
#endif
}

static inline bool wmulOverflow(Elf32_Word h, Elf32_Word i, Elf32_Word *result)
{
#ifdef __GNUC__
	return __builtin_mul_overflow(h, i, result);
#else
	if (h > 0xFFFFFFFF / i)
		return true;

	* result = h * i;
	return false;
#endif
}

#endif
