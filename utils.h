#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdbool.h>

long load_file(void *ptr, size_t size, const char *fname, bool back_mapping);

#endif // _UTILS_H