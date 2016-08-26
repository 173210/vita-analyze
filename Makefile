OBJS := elf/section/null.o elf/section/strtab.o elf/section/symtab.o	\
	elf/driver.o elf/image.o noisy/io.o noisy/lib.o vita-import/helper.o	\
	vita-import/vita-import.o vita-import/vita-import-parse.o	\
	main.o readwhole.o

CFLAGS = -std=c11 -Og -Wall -Wextra -pedantic -pie -fPIC -g -flto #-fstack-protector-all -fno-sanitize-recover -fsanitize=address $(shell pkg-config jansson --cflags) #-fsanitize=address,undefined

LDFLAGS = $(CFLAGS) $(shell pkg-config jansson --libs)

vita-analyze: $(OBJS)
	$(LINK.o) $^ $(OUTPUT_OPTION)

clean:
	$(RM) vita-analyze $(OBJS)
