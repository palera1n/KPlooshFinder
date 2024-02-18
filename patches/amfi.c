#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/amfi.h"

uint32_t *amfi_ret;
uint32_t offsetof_p_flags = UINT32_MAX;
void *amfi_rbuf = 0;
bool amfi_has_constraints = false;
bool found_launch_constraints = false;
bool found_amfi_mac_syscall = false;
bool found_trustcache = false;

bool patch_amfi_execve_tail(struct pf_patch_t *patch, uint32_t *stream) {
    if (amfi_ret) {
        printf("%s: found twice!", __FUNCTION__);
        return false;
    }

    amfi_ret = pf_find_next(stream, 0x80, ret, 0xffffffff);
    
    if (!amfi_ret) {
        printf("%s: failed to find amfi_ret\n", __FUNCTION__);
        return false;
    }

    printf("%s: Found AMFI execve hook\n", __FUNCTION__);
    return true;
}

bool patch_amfi_sha1(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t* cmp = pf_find_next(stream, 0x10, 0x7100081f, 0xffffffff); // cmp w0, 2
    if (!cmp) {
        printf("%s: failed to find cmp\n", __FUNCTION__);
        return false;
    }

    printf("%s: Found AMFI hashtype check\n", __FUNCTION__);

    *cmp = 0x6b00001f; // cmp w0, w0
    pf_disable_patch(patch);
    return true;
}

void amfi_find_offset_p_flags(uint32_t *proc_issetugid) {
    if (!proc_issetugid) {
        printf("%s called with no argument", __FUNCTION__);
        return;
    }
    // FIND LDR AND READ OFFSET
    if((*proc_issetugid & 0xffc003c0) != 0xb9400000)
    {
        printf("%s failed to find LDR\n", __FUNCTION__);
        return;
    }
    offsetof_p_flags = ((*proc_issetugid>>10)&0xFFF)<<2;
}

bool patch_amfi_mac_syscall(struct pf_patch_t *patch, uint32_t *stream) {
    if(found_amfi_mac_syscall)
    {
        printf("%s: amfi_mac_syscall found twice!\n", __FUNCTION__);
        return false;
    }
    // Our initial masking match is extremely broad and we have two of them so
    // we have to mark both as non-required, which means returning false does
    // nothing. But we panic on failure, so if we survive, we patched successfully.
    found_amfi_mac_syscall = true;

    bool foundit = false;
    uint32_t *rep = stream;
    for(size_t i = 0; i < 25; ++i)
    {
        uint32_t op = *rep;
        if(op == 0x321c03e2 /* orr w2, wzr, 0x10 */ || op == 0x52800202 /* movz w2, 0x10 */)
        {
            foundit = true;
            printf("%s: Found AMFI mac_syscall\n", __FUNCTION__);
            break;
        }
        rep++;
    }
    if (!foundit) {
        printf("%s: Failed to find w2 in mac_syscall\n", __FUNCTION__);
        return false;
    }

    uint32_t *copyin = pf_find_next(rep + 1, 2, 0x94000000, 0xfc000000); // bl
    if (!copyin) {
        printf("%s: Failed to find copyin in mac_syscall\n", __FUNCTION__);
        return false;
    }
    uint32_t *bl = pf_find_next(copyin + 1, 10, 0x94000000, 0xfc000000);
    if (!bl) {
        printf("%s: Failed to find check_dyld_policy_internal in mac_syscall\n", __FUNCTION__);
        return false;
    }
    uint32_t *check_dyld_policy_internal = pf_follow_branch(amfi_rbuf, bl);
    if (!check_dyld_policy_internal) {
        printf("%s: Failed to follow call to check_dyld_policy_internal\n", __FUNCTION__);
        return false;
    }
    
    // Find call to proc_issetuid
    uint32_t *ref = pf_find_next(check_dyld_policy_internal, 10, 0x94000000, 0xfc000000);
    if (!pf_maskmatch32(ref[1], 0x34000000, 0xff00001f)) {
        printf("%s: CBZ missing after call to proc_issetuid\n", __FUNCTION__);
        return false;
    }
    // Save offset of p_flags
    amfi_find_offset_p_flags(pf_follow_branch(amfi_rbuf, ref));
    // Follow CBZ
    ref++;
    ref += pf_signextend_32(*ref >> 5, 19); // uint32 takes care of << 2
    // Check for new developer_mode_state()
    bool dev_mode = pf_maskmatch32(ref[0], 0x94000000, 0xfc000000);
    if (dev_mode) {
        if(!pf_maskmatch32(ref[1], 0x34000000, 0xff00001f)) {
            printf("%s: CBZ missing after call to developer_mode_state\n", __FUNCTION__);
            return false;
        }
        ref[0] = 0x52800020; // mov w0, 1
        ref += 2;
    }
    // This can be either proc_has_get_task_allow() or proc_has_entitlement()
    bool entitlement = pf_maskmatch32(ref[0], 0x90000001, 0x9f00001f) && pf_maskmatch32(ref[1], 0x91000021, 0xffc003ff);
    if (entitlement) { // adrp+add to x1
        // This is proc_has_entitlement(), so make sure it's the right entitlement
        const char *str = (const char*) pf_follow_xref(amfi_rbuf, ref);
        if(strcmp(str, "get-task-allow") != 0) {
            printf("%s: Wrong entitlement passed to proc_has_entitlement\n", __FUNCTION__);
        }
        ref += 2;
    }

    // Move from high reg, bl, and either tbz, 0 or cmp, 0
    uint32_t op = ref[2];
    if (!pf_maskmatch32(ref[0], 0xaa1003e0, 0xfff003ff) || !pf_maskmatch32(ref[1], 0x94000000, 0xfc000000) || (!pf_maskmatch32(op, 0x36000000, 0xfff8001f) && op != 0x7100001f)) {
        printf("%s: CMP/TBZ missing after call to %s\n", __FUNCTION__, entitlement ? "proc_has_entitlement" : "proc_has_get_task_allow");
        return false;
    }

    ref[1] = 0x52800020; // mov w0, 1
    return true;
}

bool patch_amfi_mac_syscall_low(struct pf_patch_t *patch, uint32_t *stream) {
    // Unlike the other matches, the case we want is *not* the fallthrough one here.
    // So we need to follow the b.eq for 0x5a here.
    return patch_amfi_mac_syscall(patch, stream + 1 + pf_signextend_32(stream[1] >> 5, 19)); // uint32 takes care of << 2
}

bool patch_launch_constraints(struct pf_patch_t *patch, uint32_t *stream) {
    if (!amfi_has_constraints) return false;

    if (found_launch_constraints) {
        printf("%s: Found launch constraints more than once\n", __FUNCTION__);
        return false;
    }

    printf("%s: Found launch constraints\n", __FUNCTION__);

    uint32_t *stp = pf_find_prev(stream, 0x200, 0xa9007bfd, 0xffc07fff); // stp x29, x30, [sp, ...]
    if(!stp)
    {
        printf("%s: failed to find stack frame\n", __FUNCTION__);
        return false;
    }

    uint32_t *start = pf_find_prev(stp, 10, 0xa98003e0, 0xffc003e0); // stp xN, xM, [sp, ...]!
    if(!start)
    {
        start = pf_find_prev(stp, 10, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
        if(!start)
        {
            printf("%s: failed to find start of function\n", __FUNCTION__);
        }
    }

    start[0] = 0x52800000; // mov w0, 0
    start[1] = ret;
    found_launch_constraints = true;
    return true;
}

bool patch_trustcache_old(struct pf_patch_t *patch, uint32_t *stream) {
    if(found_trustcache) {
        printf("%s: Found more then one trustcache call\n", __FUNCTION__);
        return false;
    }
    found_trustcache = true;

    uint32_t *bl = stream - 1;
    if(pf_maskmatch32(*bl, 0xaa0003f0, 0xffff03f0)) { // mov x{16-31}, x0 
        --bl;
    }
    if(!pf_maskmatch32(*bl, 0x94000000, 0xfc000000)) { // bl
        printf("%s: Missing bl\n", __FUNCTION__);
        return false;
    }

    // Follow the call
    uint32_t *lookup_in_static_trust_cache = pf_follow_branch(amfi_rbuf, bl);
    // Skip any redirects
    while((*lookup_in_static_trust_cache & 0xfc000000) == 0x14000000) {
        lookup_in_static_trust_cache = pf_follow_branch(amfi_rbuf, lookup_in_static_trust_cache);
    }
    // We legit, trust me bro.
    lookup_in_static_trust_cache[0] = 0xd2802020; // mov x0, 0x101
    lookup_in_static_trust_cache[1] = ret;

    printf("%s: Found trustcache\n", __FUNCTION__);
    return true;
}

bool patch_trustcache_new(struct pf_patch_t *patch, uint32_t *stream) {
    if(found_trustcache) {
        printf("%s: Found more then one trustcache function\n", __FUNCTION__);
        return false;
    }
    found_trustcache = true;

    // Seek backwards to start of func. This func uses local stack space,
    // so we should always have a "sub sp, sp, 0x..." instruction.
    uint32_t *start = pf_find_prev(stream, 20, 0xd10003ff, 0xffc003ff);
    if(!start) {
        printf("%s: Failed to find start of function\n", __FUNCTION__);
        return false;
    }

    // Just replace the entire func, no prisoners today.
    start[0] = 0xd2800020; // mov x0, 1
    start[1] = 0xb4000042; // cbz x2, .+0x8
    start[2] = 0xf9000040; // str x0, [x2]
    start[3] = ret;

    printf("%s: Found trustcache\n", __FUNCTION__);
    return true;
}

void patch_amfi_kext(void *real_buf, void *amfi_buf, size_t amfi_len, bool has_constraints) {
    amfi_rbuf = real_buf;
    amfi_has_constraints = has_constraints;

    // r2: /x 080240b90000003409408452:1ffeffff1f0080ffffffffff
    uint32_t matches[] = {
        0xb9400208, // ldr w8, [x{16-31}]
        0x34000000, // cbz w0, {forward}
        0x52844009, // movz w9, 0x2200
    };
    uint32_t masks[] = {
        0xfffffe1f,
        0xff80001f,
        0xffffffff,
    };
    struct pf_patch_t execve_tail_patch = pf_construct_patch(matches, masks, sizeof(matches) / sizeof(uint32_t), (void *) patch_amfi_execve_tail);

    // r2: /x 0200d036:1f00f8ff
    uint32_t i_matches[] = {
        0x36d00002, // tbz w2, 0x1a, *
    };
    uint32_t i_masks[] = {
        0xfff8001f,
    };
    struct pf_patch_t sha1_patch = pf_construct_patch(i_matches, i_masks, sizeof(i_matches) / sizeof(uint32_t), (void *) patch_amfi_sha1);

    // r2: /x 3f6c0171000000543f68017101000054:ffffffff1f0000ffffffffff1f0000ff
    uint32_t ii_matches[] = {
        0x71016c3f, // cmp w1, 0x5b
        0x54000000, // b.eq
        0x7101683f, // cmp w1, 0x5a
        0x54000001, // b.ne
    };
    uint32_t ii_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
    };
    struct pf_patch_t mac_syscall_patch = pf_construct_patch(ii_matches, ii_masks, sizeof(ii_matches) / sizeof(uint32_t), (void *) patch_amfi_mac_syscall);

    // r2: /x 20680151:e0ffffff
    uint32_t iii_matches[] = {
        0x51016820, // sub wN, w1, 0x5a
    };
    uint32_t iii_masks[] = {
        0xffffffe0,
    };
    struct pf_patch_t mac_syscall_patch_alt = pf_construct_patch(iii_matches, iii_masks, sizeof(iii_matches) / sizeof(uint32_t), (void *) patch_amfi_mac_syscall);

    // r2: /x 3f7801710c0000543f680171000000543f6c017101000054:ffffffff1f0000ffffffffff1f0000ffffffffff1f0000ff
    uint32_t iiii_matches[] = {
        0x7101683f, // cmp w1, 0x5a
        0x54000000, // b.eq
        0x71016c3f, // cmp w1, 0x5b
        0x54000001, // b.ne
    };
    uint32_t iiii_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
    };
    struct pf_patch_t mac_syscall_patch_low = pf_construct_patch(iiii_matches, iiii_masks, sizeof(iiii_matches) / sizeof(uint32_t), (void *) patch_amfi_mac_syscall_low);

    uint32_t constraint_matches[] = {
        0xaa0003f0, // mov x{16-31}, x0
        0x910003e0, // add x0, sp, ...
        0x94000000, // bl
        0xaa0003f0, // mov x{16-31}, x0
        0x910003e0, // add x0, sp, ...
        0x94000000, // bl
        0x2a0003e8, // mov w8, w0
        0xa902a3f0, // stp x{16-31}, x8 [sp, #0x28]
        0xa901c3f0, // stp x{16-31}, x{16-31} [sp, #0x18]
    };
    uint32_t constraint_masks[] = {
        0xffff03f0,
        0xffc003ff,
        0xfc000000,
        0xffff03f0,
        0xffc003ff,
        0xfc000000,
        0xffffffff,
        0xfffffff0,
        0xffffc3f0,
    };
    struct pf_patch_t launch_constraints = pf_construct_patch(constraint_matches, constraint_masks, sizeof(constraint_matches) / sizeof(uint32_t), (void *) patch_launch_constraints);

    // r2: /x 28208052
    uint32_t trustcache_matches_old[] = {
        0x52802028 // mov w8, 0x101
    };
    uint32_t trustcache_masks_old[] = {
        0xffffffff
    };

    struct pf_patch_t trustcache_old = pf_construct_patch(trustcache_matches_old, trustcache_masks_old, sizeof(trustcache_matches_old) / sizeof(uint32_t), (void *) patch_trustcache_old);

    // r2: /x e0030091e10313aa000000949f020071e0179f1a:ffffffffffffffff000000fcffffffffffffffff
    uint32_t trustcache_matches_new[] = {
        0x910003e0, // mov x0, sp
        0xaa1303e1, // mov x1, x19
        0x94000000, // bl trustCacheQueryGetFlags
        0x7100029f, // cmp w20, 0
        0x1a9f17e0  // cset w0, eq
    };
    uint32_t trustcache_masks_new[] = {
        0xffffffff,
        0xffffffff,
        0xfc000000,
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t trustcache_new = pf_construct_patch(trustcache_matches_new, trustcache_masks_new, sizeof(trustcache_matches_new) / sizeof(uint32_t), (void *) patch_trustcache_new);

    struct pf_patch_t patches[] = {
        execve_tail_patch,
        sha1_patch,
        mac_syscall_patch,
        mac_syscall_patch_alt,
        mac_syscall_patch_low,
        launch_constraints,
        trustcache_old,
        trustcache_new
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(amfi_buf, amfi_len, patchset);
}
