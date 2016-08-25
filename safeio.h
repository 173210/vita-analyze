#ifndef SAFEIO_H
#define SAFEIO_H

#include <stddef.h>

struct safeFile;
extern const struct safeFile safeStdout;

struct safeFile *safeGetStdout();
struct safeFile *safeFopen(const char * restrict path,
			 const char * restrict mode);

int safeFclose(struct safeFile * restrict context);
int safeFseek(const struct safeFile * restrict context, long offset, int whence);
long safeFtell(const struct safeFile * restrict context);
size_t safeFread(void * restrict buffer, size_t size, size_t number,
		 const struct safeFile * restrict context);
size_t safeFwrite(const void * restrict buffer, size_t size, size_t number,
	const struct safeFile * restrict context);
int safeFputc(int c, const struct safeFile * restrict context);

#endif
