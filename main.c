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

#include <stdio.h>
#include <stdlib.h>
#include "elf/driver.h"

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
	fprintf(stderr, "usage: %s <DUMP.ELF> <INFO.BIN>\n"
		"\n"
		"Copyright (C) 2016  173210 <root.3.173210@live.com>\n"
		"\n"
		"This program comes with ABSOLUTELY NO WARRANTY.\n"
		"This is free software, and you are welcome to redistribute it "
		"under certain conditions; see LICENSE for details.\n",
		argc > 0 ? argv[0] : "<EXECUTABLE>");

	return EXIT_FAILURE;

failElfMakeSections:
failElfWrite:
	elfDeinit(&elf);
failElfInit:
	return EXIT_FAILURE;
}
