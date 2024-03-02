#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

void get_filename(FILE *fp, char *fname);
long get_file_size(FILE *fp);
long load_file(FILE *fp, void *ptr, size_t size, bool back_mapping);

#endif // _UTILS_H