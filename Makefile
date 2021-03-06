OBJS := elf/section/load.o elf/section/null.o elf/section/strtab.o	\
	elf/section/symtab.o elf/driver.o elf/image.o noisy/fcntl.o noisy/lib.o	\
	vita-import/helper.o	\
	vita-import/vita-import.o vita-import/vita-import-parse.o	\
	main.o readwhole.o

CFLAGS = -std=c11 -O2 -Wall -Wextra -pedantic -pie -fPIC -flto -fsanitize=undefined -fstack-protector-all -fno-sanitize-recover $(shell pkg-config jansson --cflags) #-fsanitize=address,undefined

LDFLAGS = $(CFLAGS) -fwhole-program

vita-analyze: $(OBJS)
	$(LINK.o) $^ $(shell pkg-config jansson --libs) $(OUTPUT_OPTION)

clean:
	$(RM) vita-analyze $(OBJS)
