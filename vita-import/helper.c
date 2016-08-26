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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "helper.h"
#include "vita-import.h"

vita_imports_t *vitaImportsLoad()
{
	static const char suffix[] = "/share/db.json";

	const char *vitasdk = getenv("VITASDK");
	if (vitasdk == NULL)
		return NULL;

	char name[strlen(vitasdk) + sizeof(suffix)];
	sprintf(name, "%s%s", vitasdk, suffix);

	return vita_imports_load(name, 0);
}

vita_imports_lib_t *vitaImportsFindLibByName(vita_imports_t * restrict imp,
					     const char *name)
{
	for (int ndx = 0; ndx < imp->n_libs; ndx++)
		if (strcmp(imp->libs[ndx]->name, name) == 0)
			return imp->libs[ndx];

	return NULL;
}

vita_imports_module_t *vitaImportsFindModuleInAll(vita_imports_t * restrict imp,
						  uint32_t nid)
{
	for (int ndx = 0; ndx < imp->n_libs; ndx++) {
		vita_imports_module_t * const module
			= vita_imports_find_module(imp->libs[ndx], nid);
		if (module != NULL)
			return module;
	}

	return NULL;
}
