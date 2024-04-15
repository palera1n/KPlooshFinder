#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/apfs.h"
#include "formats/macho.h"

bool apfs_have_union = false;
bool apfs_has_mount_check = false;
bool apfs_have_ssv = false;
bool found_apfs_rename = false;
bool found_apfs_mount = false;
void* apfs_rbuf;

bool patch_apfs_mount(struct pf_patch_t *patch, uint32_t *stream) {
    const char *str = pf_follow_xref(apfs_rbuf, stream);
    if(strcmp(str, "%s:%d: not allowed to mount as root\n") != 0)
    {
        return false;
    }

    static bool has_found_f_apfs_privcheck = false;
    if(has_found_f_apfs_privcheck)
    {
        printf("%s: f_apfs_privcheck found twice!\n", __FUNCTION__);
        return false;
    }

    // cmp x0, x8
    uint32_t* f_apfs_privcheck = pf_find_prev(stream, 0x10, 0xeb08001f, 0xFFFFFFFF);
    if (!f_apfs_privcheck) {
        printf("%s: failed to find f_apfs_privcheck\n", __FUNCTION__);
        return false;
    }
    printf("%s: Found APFS mount\n", __FUNCTION__);
    *f_apfs_privcheck = 0xeb00001f; // cmp x0, x0
    has_found_f_apfs_privcheck = true;
    found_apfs_mount = true;
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

bool has_found_apfs_vfsop_mount = false;
bool patch_apfs_remount(struct pf_patch_t *patch, uint32_t *stream) {
    if (!apfs_has_mount_check) return false;
    uint32_t tbnz_offset = (stream[1] >> 5) & 0x3fff;
    uint32_t *tbnz_stream = stream + 1 + tbnz_offset;
    uint32_t *adrp = pf_find_next(tbnz_stream, 20, 0x90000000, 0x9f00001f); // adrp

    if (!adrp) return false;
    if ((adrp[1] & 0xff80001f) != 0x91000000) return false;
    const char *str = pf_follow_xref(apfs_rbuf, &adrp[0]);
    if (!str) return false;

    if (!strstr(str, "Updating mount to read/write mode is not allowed\n")) {
	    return false;
    }

    stream[1] = 0x52800000; /* mov w0, 0 */
    has_found_apfs_vfsop_mount = true;
    
    printf("%s: Found APFS remount\n", __FUNCTION__);
    
    return true;
}

bool personalized_hash_patched = false;
bool personalized_root_hash_patch(struct pf_patch_t *patch, uint32_t *stream) {
    // ios 16.4 broke this a lot, so we're just gonna find the string and do stuff with that

    uint32_t* cbz1 = pf_find_prev(stream, 0x10, 0x34000000, 0x7e000000);

    if (!cbz1) {
        printf("kpf_apfs_personalized_hash: failed to find first cbz\n");
        return false;
    }

    uint32_t* cbz_fail = pf_find_prev(cbz1 + 1, 0x50, 0x34000000, 0x7e000000);

    if (!cbz_fail) {
        printf("kpf_apfs_personalized_hash: failed to find fail cbz\n");
        return false;
    }

    uint64_t addr_fail = macho_ptr_to_va(apfs_rbuf, cbz_fail) + (pf_signextend_32(cbz_fail[0] >> 5, 19) << 2);

    uint32_t *fail_stream = macho_va_to_ptr(apfs_rbuf, addr_fail);

    uint32_t *success_stream = stream;
    uint32_t *temp_stream = stream;

    for (int i = 0; i < 0x500; i++) {
        if ((temp_stream[0] & 0x9f000000) == 0x90000000 && // adrp
            (temp_stream[1] & 0xff800000) == 0x91000000) { // add
                const char *str = pf_follow_xref(apfs_rbuf, temp_stream);
                if (strcmp(str, "%s:%d: %s successfully validated on-disk root hash\n") == 0) {
                    success_stream = pf_find_prev(temp_stream, 0x10, 0x35000000, 0x7f000000);

                    if (success_stream) {
                        success_stream++;
                    } else {
                        success_stream = pf_find_prev(temp_stream, 0x10, 0xf90003e0, 0xffc003e0); // str x*, [sp, #0x*]

                        if (!success_stream) {
                            printf("kpf_apfs_personalized_hash: failed to find start of block\n");
                        }
                    }

                    break;
                }
        }

       temp_stream++;
    }

    if (!success_stream) {
        printf("kpf_apfs_personalized_hash: failed to find success!\n");
        return false;
    }

    uint64_t addr_success = macho_ptr_to_va(apfs_rbuf, success_stream);

    //printf("addrs: success is 0x%" PRIx64 ", fail is 0x%" PRIx64 ", target is 0x%" PRIx64 "\n", addr_success, macho_ptr_to_va(apfs_rbuf, cbz_fail), addr_fail);

    uint32_t branch_success = 0x14000000 | (((addr_success - addr_fail) >> 2) & 0x03ffffff);

    // printf("branch is 0x%x (BE)\n", branch_success);

    fail_stream[0] = branch_success;

    personalized_hash_patched = true;
    printf("%s: found apfs_personalized_hash\n", __FUNCTION__);

    return true;
}

bool root_livefs_patch(struct pf_patch_t *patch, uint32_t *stream)  {
    if (!apfs_have_ssv) return false;
    printf("%s: Found root_livefs\n", __FUNCTION__);
    stream[2] = 0xd503201f; // nop
    return true;
}


bool apfs_seal_broken_patch(struct pf_patch_t* patch, uint32_t* stream) {
    printf("%s: Found root seal broken\n", __FUNCTION__);
    
    stream[3] = nop;

    return true;
}

void patch_apfs_kext(void *real_buf, void *apfs_buf, size_t apfs_len, bool have_union, bool have_ssv, bool has_mount_check) {
    apfs_have_union = have_union;
    apfs_have_ssv = have_ssv;
    apfs_has_mount_check = has_mount_check;
    apfs_rbuf = real_buf;

    // r2: /x 0000403908011b3200000039000000b9:0000c0bfffffffff0000c0bf000000ff
    uint32_t matches[] = {
        0x90000000, // adrp x0, "%s:%d: not allowed to mount as root\n"@PAGE
        0x91000000, // add x0, x0, "%s:%d: not allowed to mount as root\n"@PAGEOFF
        0x94000000, // bl _panic
        0x12000020, // mov w*, #1 // orr w*, wzr, #1
        0x14000000, // b ?
    };
    uint32_t masks[] = {
        0x9f00001f,
        0xffc003ff,
        0xfc000000,
        0x9f7ffc20,
        0xfc000000,
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

    // when mounting an apfs volume, there is a check to make sure the volume is
    // not both root volume and read/write
    // we just nop the check out
    // example from iPad 6 16.1.1:
    // 0xfffffff0064023a8      e8b340b9       ldr w8, [sp, 0xb0]  ; 5
    // 0xfffffff0064023ac      08791f12       and w8, w8, 0xfffffffe
    // 0xfffffff0064023b0      e8b300b9       str w8, [sp, 0xb0]
    // r2: /x a00340b900781f12a00300b9:a003feff00fcffffa003c0ff
    uint32_t remount_matches[] = {
	    0x94000000, // bl
        0x37700000, // tbnz w0, 0xe, *
    };
        
    uint32_t remount_masks[] = {
	    0xfc000000,
        0xfff8001f,
    };

    struct pf_patch_t remount_patch = pf_construct_patch(remount_matches, remount_matches, sizeof(remount_masks) / sizeof(uint32_t), (void *) patch_apfs_remount);

    // the kernel will panic when it cannot authenticate the personalized root hash
    // so we force it to succeed
    // insn 4 can be either an immediate or register mov
    // example from iPhone X 15.5b4:
    // 0xfffffff008db82d8      889f40f9       ldr x8, [x28, 0x138] ; 0xf6 ; 246
    // 0xfffffff008db82dc      1f0100f1       cmp x8, 0
    // 0xfffffff008db82e0      8003889a       csel x0, x28, x8, eq
    // 0xfffffff008db82e4      01008052       mov w1, 0
    // r2: /x 080240f91f0100f10002889a01008052:1f02c0ffffffffff1ffeffffffffffff
    uint32_t personalized_matches[] = {
        0xf9400208, // ldr x8, [x{16-31}, *]
        0xf100011f, // cmp x8, 0
        0x9a880200, // csel x0, x{16-31}, x8, eq
        0x52800001, // mov w1, 0
    };

    uint32_t personalized_masks[] = {
        0xffc0021f,
        0xffffffff,
        0xfffffe1f,
        0xffffffff
    };

    struct pf_patch_t personalized_patches_1 = pf_construct_patch(personalized_matches, personalized_masks, sizeof(personalized_masks) / sizeof(uint32_t), (void *) personalized_root_hash_patch);

    // other mov
    // r2: /x 080240f91f0100f10002889ae10300aa:1f02c0ffffffffff1ffeffffffffe0ff
    personalized_matches[3] = 0xaa0003e1;
    personalized_masks[3] = 0xffe0ffff;

    struct pf_patch_t personalized_patches_2 = pf_construct_patch(personalized_matches, personalized_masks, sizeof(personalized_masks) / sizeof(uint32_t), (void *) personalized_root_hash_patch);

    uint32_t livefs_matches[] = {
        0xF9406108, // LDR             X8, [X8,#0xC0]
        0x3940E108, // LDRB            W8, [X8,#0x38]
        0x37280008, // TBNZ            W8, #5, loc_FFFFFFF008E60F1C
    };
    uint32_t livefs_masks[] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFF8001F,
    };
    struct pf_patch_t livefs_patch = pf_construct_patch(livefs_matches, livefs_masks, sizeof(livefs_masks) / sizeof(uint32_t), (void *) root_livefs_patch);

    // the kernel will panic when the volume seal is broken
    // so we nop out the tbnz so it doesnt panic
    // example from iPhone 8 16.4 RC:
    // 0xfffffff006174658      606a41f9       ldr x0, [x19, 0x2d0] ; 0xed ; 237
    // 0xfffffff00617465c      600000b4       cbz x0, 0xfffffff006174668
    // 0xfffffff006174660      4ef70394       bl 0xfffffff006272398
    // 0xfffffff006174664      00017037       tbnz w0, 0xe, 0xfffffff006174684
    // 0xfffffff006174668      20008052       mov w0, 1
    // r2: /x 600240f9600000b4000000940000703720008052:ff03c0ffffffffff000000fc1f00f8ffffffffff
    uint32_t seal_matches[] = {
        0xf9400260, // ldr x0, [x19, *]
        0xb4000060, // cbz x0, 0xc
        0x94000000, // bl
        0x37700000, // tbnz w0, 0xe, *
        0x52800020  // mov w0, 1
    };
        
    uint32_t seal_masks[] = {
        0xffc003ff,
        0xffffffff,
        0xfc000000,
        0xfff8001f,
        0xffffffff
    };
    struct pf_patch_t seal_patch = pf_construct_patch(seal_matches, seal_masks, sizeof(seal_masks) / sizeof(uint32_t), (void *) apfs_seal_broken_patch);


    struct pf_patch_t patches[] = {
        mount_patch,
        rename_patch,
        remount_patch,
        personalized_patches_1,
        personalized_patches_2,
        livefs_patch,
        seal_patch
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(apfs_buf, apfs_len, patchset);
}
