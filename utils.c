#include <stdio.h>
#include <stdint.h>
#include "utils.h"


long load_file(void *ptr, size_t size, const char *fname, bool back_mapping)
{
	FILE *f = fopen(fname, "rb");
	if (!f || ferror(f)) {
		fprintf(stderr, "Error: \"%s\" not found\n", fname);
		return -5;
	}

	fseek(f, 0, SEEK_END);
	long flen = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (flen > size) {
		fprintf(stderr,
			"Error: Could not fit RAM image (%ld bytes) into %lu\n",
			flen, size);
		return -6;
	}

	if (back_mapping)
		ptr = ptr + size - flen;

	if (fread(ptr, flen, 1, f) != 1) {
		fprintf(stderr, "Error: Could not load image.\n");
		return -7;
	}
	fclose(f);
	return flen;
}
