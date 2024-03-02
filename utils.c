#include <assert.h>
#include <unistd.h>

#include "utils.h"

#define MAXLEN 255

void get_filename(FILE *fp, char *fname)
{
	assert(fp);
	char proclink[MAXLEN];
	int fno = fileno(fp);
	snprintf(proclink, MAXLEN, "/proc/self/fd/%d", fno);
	ssize_t r = readlink(proclink, fname, MAXLEN);
	assert(r>=0);
	fname[r] = '\0';
}

long get_file_size(FILE *fp)
{
	assert(fp);
	long cur_pos = ftell(fp);
	assert(!fseek(fp, 0, SEEK_END));
	long flen = ftell(fp);
	assert(!fseek(fp, cur_pos, SEEK_SET));
	return flen;
}

long load_file(FILE *fp, void *ptr, size_t size, bool back_mapping)
{
	fseek(fp, 0, SEEK_SET);
	if (!fp || ferror(fp)) {
		char fname[MAXLEN];
		get_filename(fp, fname);
		fprintf(stderr, "Error: \"%s\" not found\n", fname);
		return -5;
	}

	long flen = get_file_size(fp);
	if (size > 0 && flen > size) {
		fprintf(stderr,
			"Error: Could not fit RAM image (%ld bytes) into %lu\n",
			flen, size);
		return -6;
	}

	if (size > 0 && back_mapping)
		ptr = ptr + size - flen;

	if (fread(ptr, flen, 1, fp) != 1) {
		fprintf(stderr, "Error: Could not load image.\n");
		return -7;
	}
	return flen;
}
