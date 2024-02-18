#ifndef _PATCHES_APFS_H
#define _PATCHES_APFS_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

void patch_apfs_kext(void *real_buf, void *apfs_buf, size_t apfs_len, bool have_union, bool have_ssv);

#endif
