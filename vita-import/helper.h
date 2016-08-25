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

#ifndef VITA_IMPORT_HELPER_H
#define VITA_IMPORT_HELPER_H

#include <stdint.h>
#include "vita-import.h"

vita_imports_t *vitaImportsLoad();
vita_imports_lib_t *vitaImportsFindLibByName(vita_imports_t * restrict imp,
					     const char *name);

vita_imports_module_t *vitaImportsFindModuleInAll(vita_imports_t * restrict imp,
						  uint32_t nid);

#endif
