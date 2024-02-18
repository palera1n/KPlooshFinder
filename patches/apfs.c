#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/apfs.h"
#include "formats/macho.h"

bool apfs_have_union = false;
bool apfs_have_ssv = false;
bool found_apfs_rename = false;
void* apfs_rbuf;

bool patch_apfs_mount(struct pf_patch_t *patch, uint32_t *stream) {
    // cmp x0, x8
    uint32_t* f_apfs_privcheck = pf_find_next(stream, 0x10, 0xeb08001f, 0xffffffff);
    
    if (!f_apfs_privcheck) {
        printf("%s: failed to find f_apfs_privcheck", __FUNCTION__);
        return false;
    }

    printf("%s: Found APFS mount\n", __FUNCTION__);

    *f_apfs_privcheck = 0xeb00001f; // cmp x0, x0
    return true;
}

bool patch_apfs_rename(struct pf_patch_t *patch, uint32_t *stream) {
    if (apfs_have_ssv) return false;

    if (
        !pf_maskmatch32(stream[-1], 0xf80003a0, 0xfec003a0) /*st(u)r x*, [x29/sp, *]*/ 
        && !pf_maskmatch32(stream[-1], 0xaa0003fc, 0xffffffff) /* mov x28, x0 */) {
            return false;
    }

    if (found_apfs_rename) {
        printf("%s: Found twice\n", __FUNCTION__);
        return false;
    }

    printf("%s: Found APFS rename\n", __FUNCTION__);
    found_apfs_rename = true;

    if (pf_maskmatch32(stream[2], 0x36000000, 0xff000000)) {
        /* tbz -> b */
        stream[2] = 0x14000000 | (uint32_t)pf_signextend_32(stream[2] >> 5, 14);
    } else if (pf_maskmatch32(stream[2], 0x37000000, 0xff000000)) {
        /* tbnz -> nop */
        stream[2] = nop;
    } else {
        printf("%s: unreachable!\n", __FUNCTION__);
        return false;
    }
    return true;
}

void patch_apfs_kext(void *real_buf, void *apfs_buf, size_t apfs_len, bool have_union, bool have_ssv) {
    apfs_have_union = have_union;
    apfs_have_ssv = have_ssv;
    apfs_rbuf = real_buf;

    // r2: /x 0000403908011b3200000039000000b9:0000c0bfffffffff0000c0bf000000ff
    uint32_t matches[] = {
        0x39400000, // ldr{b|h} w*, [x*]
        0x321b0108, // orr w8, w8, 0x20
        0x39000000, // str{b|h} w*, [x*]
        0xb9000000  // str w*, [x*]
    };
    uint32_t masks[] = {
        0xbfc00000,
        0xffffffff,
        0xbfc00000,
        0xff000000,
    };

    struct pf_patch_t mount_patch = pf_construct_patch(matches, masks, sizeof(matches) / sizeof(uint32_t), (void *) patch_apfs_mount);

    // r2: /x a00300f80000403900003037:a003c0fe0000feff0000f8ff
    uint32_t i_matches[] = {
        0xf80003a0, // st(u)r x*, [x29/sp, *]
        0x39400000, // ldrb w*, [x*]
        0x36300000, // tb(n)z w*, 6, *
    };
    uint32_t i_masks[] = {
        0xfec003a0,
        0xfffe0000,
        0xfef80000,
    };
    struct pf_patch_t rename_patch = pf_construct_patch(i_matches, i_masks, sizeof(i_matches) / sizeof(uint32_t), (void *) patch_apfs_rename);

    struct pf_patch_t patches[] = {
        mount_patch,
        rename_patch
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(apfs_buf, apfs_len, patchset);
}
