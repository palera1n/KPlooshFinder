#if 0
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/kext.h"

bool patch_md0_check(struct pf_patch_t *patch, uint32_t *stream) {
    // Find: cmp wN, 0x64
    uint32_t *cmp = pf_find_next(stream, 10, 0x7101901f, 0xfffffc1f);
    if (!cmp) {
        return false;
    }
    // Change first cmp to short-circuit
    *stream = (*stream & 0xffc003ff) | (0x64 << 10);
    return true;
}

void patch_all_kexts(void *real_buf, void *kext_buf, size_t kext_len) {
    uint32_t matches[] = {
        0x7101b41f, // cmp wN, 0x6d
    };
    uint32_t masks[] = {
        0xfffffc1f,
    };
    struct pf_patch_t md0_patch = pf_construct_patch(matches, masks, sizeof(matches) / sizeof(uint32_t), (void *) patch_md0_check);

    struct pf_patch_t patches[] = {
        md0_patch
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(kext_buf, kext_len, patchset);
}
#endif
