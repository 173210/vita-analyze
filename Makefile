OBJS := main.o safeio.o vita-import.o vita-import-parse.o

CFLAGS := -std=c11 -Og -Wall -Wextra -pedantic -pie -fPIC -g -flto -fstack-protector-all -fno-sanitize-recover -fsanitize=address #-fsanitize=address,undefined

vita-analyze: $(OBJS)
	$(LINK.o) $^ $(OUTPUT_OPTION)

clean:
	$(RM) vita-analyze $(OBJS)
