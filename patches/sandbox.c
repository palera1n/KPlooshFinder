#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "formats/macho.h"
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/sandbox.h"

uint32_t *vnode_lookup;
uint32_t *vnode_put;
uint32_t *vfs_context_current;
void *sandbox_rbuf = 0;
void *kernel_buf;

bool sandbox_has_protobox = false;
bool found_protobox = false;

bool patch_vnode_lookup(struct pf_patch_t *patch, uint32_t *stream) {
    if(vnode_lookup) {
        return false;
    }

    uint32_t *try = &stream[8] + ((stream[8] >> 5) & 0xfff);
    if (!pf_maskmatch32(try[0], 0xaa0003e0, 0xffe0ffff) ||   // MOV x0, Xn
        !pf_maskmatch32(try[1], 0x94000000, 0xfc000000) ||    // BL _sfree
        !pf_maskmatch32(try[3], 0xb4000000, 0xff000000) ||    // CBZ
        !pf_maskmatch32(try[4], 0x94000000, 0xfc000000)) {   // BL _vnode_put
        return false;
    }

    printf("%s: Found vnode_lookup\n", __FUNCTION__);
    vfs_context_current = pf_follow_branch(sandbox_rbuf, &stream[1]);
    vnode_lookup = pf_follow_branch(sandbox_rbuf, &stream[6]);
    vnode_put = pf_follow_branch(sandbox_rbuf, &try[4]);
    pf_disable_patch(patch);
    return true;
}

bool patch_protobox(struct pf_patch_t *patch, uint32_t *stream)
{
    if (!sandbox_has_protobox) return false;
    uint32_t adrp1 = stream[0],
             add1  = stream[1];
    const char *str1 = pf_follow_xref(sandbox_rbuf, &stream[0]);
    if (!str1) return false;

    uint32_t adrp2 = stream[4],
             add2  = stream[5];
    const char *str2 = pf_follow_xref(sandbox_rbuf, &stream[4]);
    if (!str2) return false;

    if (!strcmp(str1, "Restore") && !strcmp(str2, "Darwin")) {
        // Make protobox think this device is in "Restore" mode
        // This will disable protobox
        stream[2] = 0xD2800020; // mov x0, #1
        printf("%s: Found protobox\n",  __FUNCTION__);
        found_protobox = true;
        pf_disable_patch(patch);
        return true;
    }

    return false;
}

void patch_sandbox_kext(void *real_buf, void *sandbox_buf, size_t sandbox_len, bool has_protobox) {
    sandbox_rbuf = real_buf;
    sandbox_has_protobox = has_protobox;

    uint32_t matches[] = {
        0x35000000, // CBNZ
        0x94000000, // BL _vfs_context_current
        0xAA0003E0, // MOV Xn, X0
        0xD1006002, // SUB
        0x00000000, // MOV X0, Xn || MOV W1, #0
        0x00000000, // MOV X0, Xn || MOV W1, #0
        0x94000000, // BL _vnode_lookup
        0xAA0003E0, // MOV Xn, X0
        0x35000000  // CBNZ
    };
    uint32_t masks[] = {
        0xFF000000,
        0xFC000000,
        0xFFFFFFE0,
        0xFFFFE01F,
        0x00000000,
        0x00000000,
        0xFC000000,
        0xFFFFFFE0,
        0xFF000000
    };
    struct pf_patch_t vnode_lookup_patch = pf_construct_patch(matches, masks, sizeof(matches) / sizeof(uint32_t), (void *) patch_vnode_lookup);


    // Protobox on is an additional sandbox mechanism in iOS 16+ that introduces syscall masks, which is used to have syscall whitelists on some system processes
    // When injecting into them or using something like Frida, it can prevent certain functionality
    // Additionally it makes these processes crash on sandbox violations, meaning that calling even something simple like mach_thread_self in watchdogd will crash the process
    // We disable it by making the code that enables it think the device is in Restore mode, as this check involves calling is_release_type with a string it's easy to find
    uint32_t protobox_matches[] = {
        0x90000000, // adrp x0, "Restore"@PAGE
        0x91000000, // add x0, "Restore"@PAGEOFF
        0x94000000, // bl _is_release_type
        0x37000000, // tbnz w0, #0, ???
        0x90000000, // adrp x0, "Darwin"@PAGE
        0x91000000, // add x0, "Darwin"@PAGEOFF
        0x94000000, // bl _is_release_type
        0x36000000, // tb(n)z w0, #0, ???
    };
    uint32_t protobox_masks[] = {
        0x9f00001f,
        0xff8003ff,
        0xfc000000,
        0xff00001f,
        0x9f00001f,
        0xff8003ff,
        0xfc000000,
        0xfe00001f,
    };
    struct pf_patch_t protobox_patch = pf_construct_patch(protobox_matches, protobox_masks, sizeof(protobox_matches) / sizeof(uint32_t), (void *) patch_protobox);

    struct pf_patch_t patches[] = {
        vnode_lookup_patch,
        protobox_patch
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches)/sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(sandbox_buf, sandbox_len, patchset);
}
