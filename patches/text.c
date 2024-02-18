#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "formats/macho.h"
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/text.h"
#include "patches/shellcode.h"

void *text_rbuf;
void *text_sect_buf;
uint64_t text_sect_addr;
bool text_has_rootvp = false;
bool text_has_cryptex = false;
bool text_has_kmap = false;

bool found_mac_mount = false;
bool found_mac_unmount = false;
bool found_vm_map_protect = false;
bool found_vm_fault_enter = false;
bool found_fsctl_internal = false;
bool found_vnode_open_close = false;
bool found_shared_region_root_dir = false;
bool found_dyld = false;
bool nvram_inline_patch = false;
bool found_task_conversion_eval_ldr = false;
bool found_task_conversion_eval_bl = false;
bool found_task_conversion_eval_imm = false;
bool found_convert_port_to_map = false;
bool found_devmode = false;
bool text_has_devmode = false;

uint32_t *fsctl_patchpoint = NULL;
uint64_t vnode_open_addr = 0;
uint64_t vnode_close_addr = 0;
uint32_t *vnode_gaddr;
uint32_t repatch_ldr_x19_vnode_pathoff;
uint64_t ret0_gadget;
uint32_t *shellcode_area;
uint32_t *dyld_hook_patchpoint;
uint32_t *nvram_patchpoint;
uint32_t *rootdev_patchpoint;
extern void* kernel_buf;

bool patch_mac_mount(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t* mac_mount = stream;
    // search for tbnz w*, 5, *
    // and nop it (enable MNT_UNION mounts)
    uint32_t* mac_mount_1 = pf_find_prev(mac_mount, 0x40, 0x37280000, 0xfffe0000);
    if (!mac_mount_1) {
        mac_mount_1 = pf_find_next(mac_mount, 0x40, 0x37280000, 0xfffe0000);
    }

    if (!mac_mount_1) {
        return false;
    }
    mac_mount_1[0] = nop;

    // search for ldrb w8, [x8, 0x71]
    mac_mount_1 = pf_find_prev(mac_mount, 0x40, 0x3941c508, 0xffffffff);
    if (!mac_mount_1) {
        mac_mount_1 = pf_find_next(mac_mount, 0x40, 0x3941c508, 0xffffffff);
    }

    if (!mac_mount_1) {
        return false;
    }
    // replace with a mov x8, xzr
    // this will bypass the (vp->v_mount->mnt_flag & MNT_ROOTFS) check
    mac_mount_1[0] = 0xaa1f03e8;
    found_mac_mount = true;
    printf("%s: Found mac_mount\n", __FUNCTION__);
    pf_disable_patch(patch);
    return true;
}

bool patch_mac_unmount(struct pf_patch_t *patch, uint32_t *stream) {
    uint8_t rn;
    if (pf_maskmatch32(stream[-1], 0xaa0003e0, 0xffe0ffff) &&  // mov x0, xN
        pf_maskmatch32(stream[3], 0x94000000, 0xfc000000)) {   // bl vnode_rele_internal
        rn = (stream[-1] >> 16) & 0x1f;
        stream += 3;
    } else if (pf_maskmatch32(stream[3], 0xaa0003e0, 0xffe0ffff) &&    // mov x0, xN
               pf_maskmatch32(stream[4], 0x94000000, 0xfc000000)) {    // bl vnode_rele_internal
        rn = (stream[3] >> 16) & 0x1f;
        stream += 4;
    } else {
        // not a match
        return false;
    }

    if (stream[1] != (0xaa0003e0 | (rn << 16)) ||              // mov x0, xN
        !pf_maskmatch32(stream[2], 0x94000000, 0xfc000000)) {  // bl lck_mtx_lock_spin || BL vnode_put
        // Also not a match
        return false;
    }

    // This is probably it...

    // Find call to vnode_getparent
    // mov x0, xN
    // bl vnode_getparent
    // mov xN, x0
    uint32_t* mov = pf_find_prev(stream - 3, 0x20, 0xaa0003e0, 0xffffffe0);

    uint8_t parent_rn = 0;
    if (mov &&
        pf_maskmatch32(mov[-2], 0xaa0003e0, 0xffe0ffff) && // mov x0, xN
        pf_maskmatch32(mov[-1], 0x94000000, 0xfc000000)) { // bl vnode_getparent

        parent_rn = *mov & 0x1f;
    }

    // Check that we have code to release parent_vnode below
    // mov w1, 2
    uint32_t* parent_lock = pf_find_next(stream, 0x100, 0x52800041, 0xffffffff);
    if (!parent_lock) parent_lock = pf_find_next(stream, 0x100, 0x321f03e1, 0xffffffff);
    if (!parent_lock) {
        return false;
    }

    uint32_t* call;
    if (pf_maskmatch32(parent_lock[-1], 0xaa0003e0, 0xffe0ffff) &&   // mov x0, xN
        pf_maskmatch32(parent_lock[1], 0x94000000, 0xfc000000)) {    // bl lock_vnode_and_post
        call = parent_lock+1;
        if (!parent_rn) parent_rn = (parent_lock[-1] >> 16) & 0x1f;
    } else if (pf_maskmatch32(parent_lock[1], 0xaa0003e0, 0xffe0ffff) &&   // mov x0, xN
               pf_maskmatch32(parent_lock[2], 0x94000000, 0xfc000000)) {   // bl lock_vnode_and_post
        if (!parent_rn) parent_rn = (parent_lock[1] >> 16) & 0x1f;
        call = parent_lock + 2;
    } else {
        return false;
    }

    if (call[1] != (0xaa0003e0 | (parent_rn << 16)) || !pf_maskmatch32(call[2], 0x94000000, 0xfc000000)) {
        return false;
    }

    printf("%s: Found dounmount\n", __FUNCTION__);
    stream[0] = nop;
    found_mac_unmount = true;
    pf_disable_patch(patch);
    return true;
}

bool patch_vm_map_protect(uint32_t *stream) {
    if(found_vm_map_protect) return false;

    uint32_t *tbz = pf_find_next(stream, 8, 0x36480000, 0xfef80010); // tb[n]z w{0-15}, 0x...
    if(!tbz) {
        printf("%s: failed to find tb[n]z\n", __FUNCTION__);
        return false;
    }

    uint32_t op = *tbz;
    if(op & 0x1000000) { // tbnz
        *tbz = nop;
    } else { // tbz
        *tbz = 0x14000000 | (uint32_t) pf_signextend_32(op >> 5, 14);
    }

    found_vm_map_protect = true;
    printf("%s: Found vm_map_protect\n", __FUNCTION__);
    return true;
}

bool patch_vm_prot_branch(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t *bne = pf_find_next(stream, 3, 0x54000001, 0xff00001f);
    if (!bne) {
        return false;
    }
    int32_t off = pf_signextend_32(*bne >> 5, 19);
    *bne = 0x14000000 | (uint32_t) off;

    return patch_vm_map_protect(bne + off); // uint32 takes care of << 2
}

bool patch_vm_prot_inline(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t idx = 2;
    uint32_t op = stream[idx];
    if (
        pf_maskmatch32(op, 0x12090000, 0xfffffe10) ||  // and w{0-15}, w{0-15}, 0x800000
        pf_maskmatch32(op, 0xf269001f, 0xfffffe1f)     // tst x{0-15}, 0x800000
    ) {
        ++idx;
    }

    if (
        pf_maskmatch32(stream[idx + 0], 0x2a000000, 0xfff0fe10) && // orr w{0-15}, w{0-15}, w{0-15}
        pf_maskmatch32(stream[idx + 1], 0x121d7a00, 0xfffffe10) && // and w{0-15}, w{16-31}, 0xfffffffb
        pf_maskmatch32(stream[idx + 2], 0x7100001f, 0xfffffe1f)    // cmp w{0-15}, 0
    ) {
        idx += 3;
    } else if (
        pf_maskmatch32(stream[idx + 0], 0x7a400800, 0xfffffe1f) && // ccmp w{0-15}, 0, 0, eq
        pf_maskmatch32(stream[idx + 1], 0x121d7a00, 0xfffffe10)    // and w{0-15}, w{16-31}, 0xfffffffb
    ) {
        idx += 2;
    } else {
        return false;
    }

    op = stream[idx];
    uint32_t shift = 0;
    if (pf_maskmatch32(op, 0x1a900010, 0xfff0fe10)) { // csel w{16-31}, w{0-15}, w{16-31}, eq
        shift = 16;
    } else if (pf_maskmatch32(op, 0x1a801210, 0xfff0fe10)) { // csel w{16-31}, w{16-31}, w{0-15}, ne
        shift = 5;
    } else {
        return false;
    }

    // Make sure csel regs match
    if((op & 0x1f) != ((op >> shift) & 0x1f)) {
        printf("%s: mismatching csel regs\n", __FUNCTION__);
        return false;
    }
    stream[idx] = nop;

    return patch_vm_map_protect(stream + idx + 1);
}

bool patch_vm_fault_enter(struct pf_patch_t *patch, uint32_t *stream) {
    if (found_vm_fault_enter) return false;

    // Should be followed by a tb(n)z wX, 2 shortly
    if (!pf_find_next(stream, 0x18, 0x36100000, 0xfef80000)) {
        // Wrong place...
        return false;
    }

    uint32_t *b_loc = 0;
    if (!(b_loc = pf_find_prev(stream, 0x80, 0x14000000, 0xff000000))) {
        return false;
    }

    uint32_t *wanted_addr = b_loc + 1;
    for (int i = 2; i < 20; i++) {
        uint32_t *try_loc = wanted_addr - i;
        // TBZ or CBZ
        if (pf_maskmatch32(*try_loc | (i << 5), 0x34000000 | i << 5, 0xFD07FFE0)) {
            // Found it!
            *try_loc = nop;

            printf("%s: Found vm_fault_enter\n", __FUNCTION__);
            found_vm_fault_enter = true;
            pf_disable_patch(patch);
            return true;
        }
    }

    return false;
}

bool patch_vm_fault_enter14(struct pf_patch_t *patch, uint32_t *stream) {
    if (found_vm_fault_enter) return false;

    // Make sure this was preceded by a "tbz w[16-31], 2, ..." that jumps to the code we're currently looking at
    uint32_t *tbz = pf_find_prev(stream, 0x18, 0x36100010, 0xfff80010);
    if (!tbz) {
        // This isn't our TBZ
        return false;
    }
    tbz += pf_signextend_32(*tbz >> 5, 14); // uint32 takes care of << 2
    // A few instructions close is good enough
    if (tbz > stream || stream - tbz > 2) {
        // Apparently still not our TBZ
        return false;
    }

    stream[0] = nop;
    printf("%s: Found vm_fault_enter\n", __FUNCTION__);
    found_vm_fault_enter = true;
    pf_disable_patch(patch);
    return true;
}

bool patch_vnode_getaddr(struct pf_patch_t *patch, uint32_t *stream) {
    if (vnode_gaddr) return false;

    printf("%s: Found vnode_getattr\n", __FUNCTION__);
    vnode_gaddr = pf_find_prev(stream, 0x80, 0xd10000ff, 0xff0000ff);
    
    pf_disable_patch(patch);
    return !!vnode_gaddr;
}

bool patch_vnode_getpath(struct pf_patch_t *patch, uint32_t *stream) {
    if(repatch_ldr_x19_vnode_pathoff) return false;

    printf("%s: Found vnode_getpath\n", __FUNCTION__);
    repatch_ldr_x19_vnode_pathoff = stream[-2];
    pf_disable_patch(patch);
    return true;
}

bool patch_ret0_gadget(struct pf_patch_t *patch, uint32_t *stream) {
    if (ret0_gadget) return false;

    printf("%s: Found ret0 gadget\n", __FUNCTION__);
    uint64_t gadget_addr = text_sect_addr + (uint64_t) ((void *) stream - text_sect_buf);
    ret0_gadget = gadget_addr;
    pf_disable_patch(patch);
    return true;
}

bool patch_fsctl_dev_by_role(struct pf_patch_t *patch, uint32_t *stream) {
    if(found_fsctl_internal || !text_has_rootvp) return false;
    found_fsctl_internal = true;

    uint32_t *stackframe = pf_find_prev(stream - 1, 0x20, 0xa9007bfd, 0xffc07fff); // stp x29, x30, [sp, ...]
    if(!stackframe)
    {
        printf("%s: Failed to find stack frame\n", __FUNCTION__);
        return false;
    }

    uint32_t *start = pf_find_prev(stackframe - 1, 8, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
    if(!start)
    {
        printf("%s: Failed to find start of function\n", __FUNCTION__);
        return false;
    }


    printf("%s: Found fsctl_dev_by_role\n", __FUNCTION__);
    fsctl_patchpoint = start;
    return true;
}

bool patch_vnode_open_close(struct pf_patch_t *patch, uint32_t *stream) {
    if(found_vnode_open_close || !text_has_rootvp) return false;
    found_vnode_open_close = true;

    uint32_t *vnode_open = pf_find_next(stream + 2, 3, 0x94000000, 0xfc000000);
    if(!vnode_open)
    {
        printf("%s: Failed to find vnode_open\n", __FUNCTION__);
        return false;
    }

    uint32_t *vnode_close = pf_find_next(vnode_open + 1, 0x30, 0xaa1003e2, 0xfff0ffff); // mov x2, x{x16-31}
    if(
        !vnode_close ||
        !pf_maskmatch32(vnode_close[1], 0x94000000, 0xfc000000)  || // bl
         vnode_close[-1]               != 0x52800001             || // mov w1, 0
        !pf_maskmatch32(vnode_close[-2], 0xaa1003e0, 0xfff0ffff) ||
        !pf_maskmatch32(vnode_close[-3], 0x91000210, 0xffc00210) || // add x{16-31}, x{16-31}, ...
        !pf_maskmatch32(vnode_close[-4], 0x90000010, 0x9f000010)    // adrp x{16-31}, ...
    )
    {
        printf("%s: Failed to find vnode_close\n", __FUNCTION__);
        return false;
    }
    vnode_close++;

    uint64_t open_addr = text_sect_addr + (uint64_t) ((void *) vnode_open - text_sect_buf);
    uint64_t close_addr = text_sect_addr + (uint64_t) ((void *) vnode_close - text_sect_buf);
    vnode_open_addr  = open_addr + (pf_signextend_32(*vnode_open,  26) << 2);
    vnode_close_addr = close_addr + (pf_signextend_32(*vnode_close, 26) << 2);

    printf("%s: Found vnode_open/vnode_close\n", __FUNCTION__);
    return true;
}

bool patch_vnop_rootvp_auth(struct pf_patch_t *patch, uint32_t *stream) {
    if (!text_has_rootvp) return false;

    // cmp xN, xM - wrong match
    if(pf_maskmatch32(stream[2], 0xeb000300, 0xffe0ffe0)) {
        return false;
    }
    // Old sequence like:
    // 0xfffffff00759d9f8      61068d52       mov w1, 0x6833
    // 0xfffffff00759d9fc      8100b072       movk w1, 0x8004, lsl 16
    // 0xfffffff00759da00      020080d2       mov x2, 0
    // 0xfffffff00759da04      03008052       mov w3, 0
    // 0xfffffff00759da08      4ca3f797       bl sym._VNOP_IOCTL
    if (
        stream[0] == 0x528d0661 && // mov w1, 0x6833
        stream[1] == 0x72b00081 && // movk w1, 0x8004, lsl 16
        stream[2] == 0xd2800002 && // mov x2, 0
        stream[3] == 0x52800003 && // mov w3, 0
        pf_maskmatch32(stream[4], 0x94000000, 0xfc000000) // bl sym._VNOP_IOCTL
    ) {
        printf("%s: Found vnop_rootvp_auth\n", __FUNCTION__);
        // Replace the call with mov x0, 0
        stream[4] = 0xd2800000;
        return true;
    } else if (
        (
            pf_maskmatch32(stream[2], 0xa90003e0, 0xffc003e0) && // stp xN, xM, [sp, ...]
            ((stream[2] & 0x1f) == (stream[1] & 0x1f) || ((stream[2] >> 10) & 0x1f) == (stream[1] & 0x1f)) // match reg
        ) ||
        (
            pf_maskmatch32(stream[2], 0xf90003e0, 0xffc003e0) && // str xN, [sp, ...]
            (stream[2] & 0x1f) == (stream[1] & 0x1f) // match reg
        )
    ) {
        // add x0, sp, 0x...
        uint32_t *sp = pf_find_next(stream + 3, 0x10, 0x910003e0, 0xffc003ff);
        if(sp && (sp[1] & 0xfffffc1f) == 0xd63f0000) // blr
        {
            printf("%s: Found vnop_rootvp_auth\n", __FUNCTION__);
            // Replace the call with mov x0, 0
            sp[1] = 0xd2800000;
            return true;
        }
    }
    return false;
}

bool patch_shared_region_root_dir(struct pf_patch_t *patch, uint32_t *stream) {
    if (!text_has_rootvp || text_has_cryptex) return false;

    // Make sure regs match
    if(stream[0] != stream[3] || (stream[2] & 0x1f) != (stream[5] & 0x1f)) return false;

    uint32_t reg = stream[5] & 0x1f;
    // There's a cmp+b.cond afterwards, but there can be a load from stack in between,
    // so we find that dynamically.
    uint32_t *cmp = pf_find_next(stream + 6, 2, 0xeb00001f, 0xffe0fc1f);
    if (!cmp || (((cmp[0] >> 5) & 0x1f) != reg && ((cmp[0] >> 16) & 0x1f) != reg) ||
        !pf_maskmatch32(cmp[1], 0x54000000, 0xff00001e) // Mask out lowest bit to catch both b.eq and b.ne
    ) {
        return false;
    }
    // Now that we're sure this is a match, check that we haven't matched already
    if(found_shared_region_root_dir) return false;

    // The thing we found isn't what we actually want to patch though.
    // The check right here is fine, but there's one further down that's
    // much harder to identify, so we use this as a landmark.
    uint32_t *ldr1 = pf_find_next(cmp + 2, 120, 0xf9406c00, 0xfffffc00); // ldr xN, [xM, 0xd8]
    if (!ldr1 || ((*ldr1 >> 5) & 0x1f) == 0x1f) { // no stack loads
        printf("%s: Failed to find ldr1\n", __FUNCTION__);
        return false;
    }
    uint32_t *ldr2 = pf_find_next(ldr1 + 1, 2, 0xf9406c00, 0xfffffc00); // ldr xN, [xM, 0xd8]
    if (!ldr2 || ((*ldr2 >> 5) & 0x1f) == 0x1f) { // no stack loads
        printf("%s: Failed to find ldr2\n", __FUNCTION__);
        return false;
    }
    size_t idx = 2;
    uint32_t reg1 = (*ldr1 & 0x1f),
             reg2 = (*ldr2 & 0x1f),
             cmp2 = ldr2[1],
             bcnd = ldr2[idx];
    if (cmp2 != (0xeb00001f | (reg1 << 16) | (reg2 << 5)) && cmp2 != (0xeb00001f | (reg1 << 5) | (reg2 << 16))) {
        printf("%s: Bad cmp\n", __FUNCTION__);
        return false;
    }
    if (pf_maskmatch32(bcnd, 0xb94003f0, 0xbfc003f0)) { // ldr x{16-31}, [sp, ...]
        bcnd = ldr2[++idx];
    }
    if (!pf_maskmatch32(bcnd, 0x54000000, 0xff00001e)) { // Mask out lowest bit to catch both b.eq and b.ne
        printf("%s: Failed to find b.cond\n", __FUNCTION__);
        return false;
    }
    ldr2[1] = 0xeb00001f; // cmp x0, x0
    found_shared_region_root_dir = true;
    return true;
}

bool patch_shellcode_area(struct pf_patch_t *patch, uint32_t *stream) {
    // For anything else we wouldn't want to disable the patch to make sure that
    // we only match what we want to, but this is literally just empty space.
    pf_disable_patch(patch);

    shellcode_area = stream;
    printf("%s: Found shellcode area\n", __FUNCTION__);
    return true;
}

bool patch_dyld(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t adrp = stream[5],
             add  = stream[6];
    // Sanity check: make sure instrs use the same reg
    if((adrp & 0x1f) != (add & 0x1f) || (add & 0x1f) != ((add >> 5) & 0x1f))
    {
        return false;
    }
    // Actual match check
    const char *str = pf_follow_xref(text_rbuf, stream + 5);
    if (!str) return false;
    if(strcmp(str, "/usr/lib/dyld") != 0)
    {
        return false;
    }

    if (found_dyld) return false;
    found_dyld = true;

    // We replace this bit of code:
    //
    // if (0 != strcmp(name, DEFAULT_DYLD_PATH)) {
    //     return (LOAD_BADMACHO);
    // }
    //
    // With this:
    //
    // name = dyld_hook();
    //
    // So instead of checking the path, we just always override it either
    // with our custom dyld path if it exists, and with /usr/lib/dyld otherwise.

    // Check whether strcmp is inlined or not
    uint32_t *target = NULL;
    if (
        pf_maskmatch32(stream[7], 0xaa1003e0, 0xfff0ffff) && // mov x0, x{16-31}
        pf_maskmatch32(stream[8], 0x94000000, 0xfc000000) && // bl sym._strcmp
        pf_maskmatch32(stream[9], 0x34000000, 0xff00001f)    // cbz w0, ...
    ) {
        target = stream + 9 + pf_signextend_32(stream[9] >> 5, 19); // uint32 takes care of << 2
    } else if (
        pf_maskmatch32(stream[ 7], 0xaa1003e0, 0xfff0fff0) && // mov x{0-15}, x{16-31}
        pf_maskmatch32(stream[ 8], 0x39400000, 0xfffffe10) && // ldrb w{0-15}, [x{0-15}]
        pf_maskmatch32(stream[ 9], 0x39400000, 0xfffffe10) && // ldrb w{0-15}, [x{0-15}]
        pf_maskmatch32(stream[10], 0x6b00001f, 0xfff0fe1f) && // cmp w{0-15}, w{0-15}
        pf_maskmatch32(stream[11], 0x54000001, 0xff00001f) && // b.ne 0x...
        pf_maskmatch32(stream[12], 0x91000400, 0xfffffe10) && // add x{0-15}, x{0-15}, 1
        pf_maskmatch32(stream[13], 0x91000400, 0xfffffe10) && // add x{0-15}, x{0-15}, 1
        pf_maskmatch32(stream[14], 0x35800000, 0xff800010)    // cbnz w{0-15}, {backwards}
    ) {
        target = stream + 15;
    } else {
        printf("%s: Bad instructions after adrp/add\n", __FUNCTION__);
        return false;
    }

    // We have at least 5 instructions we can overwrite.
    uint32_t reg = (stream[0] >> 16) & 0x1f;
    stream[5] = 0x94000000;                           // bl dyld_hook
    stream[6] = 0xaa0003e0 | reg;                     // mov xN, x0
    stream[7] = 0x14000000 | (target - (stream + 7)); // b target

    // dyld_hook hasn't been emitted yet
    dyld_hook_patchpoint = stream + 5;

    printf("%s: Found dyld\n", __FUNCTION__);
    return true;
}

bool patch_nvram(struct pf_patch_t *patch, uint32_t *stream) {
    if (nvram_patchpoint || nvram_inline_patch) return false;

    nvram_patchpoint = pf_find_next(stream, 0x10, ret, 0xffffffff);
    if (nvram_patchpoint) {
        printf("%s: Found NVRAM unlock\n", __FUNCTION__);
        return true;
    }

    return false;
}

bool patch_nvram_inline(struct pf_patch_t *patch, uint32_t *stream) {
    if (nvram_patchpoint || nvram_inline_patch) return false;

    // Most reliable marker of a stack frame seems to be "add x29, sp, 0x...".
    // And this function is HUGE, hence up to 2k insn.
    uint32_t *frame = pf_find_prev(stream, 2000, 0x910003fd, 0xff8003ff);
    if(!frame) return false;

    // Now find the insn that decrements sp. This can be either
    // "stp ..., ..., [sp, -0x...]!" or "sub sp, sp, 0x...".
    // Match top bit of imm on purpose, since we only want negative offsets.
    uint32_t  *start = pf_find_prev(frame, 10, 0xa9a003e0, 0xffe003e0);
    if(!start) start = pf_find_prev(frame, 10, 0xd10003ff, 0xff8003ff);
    if(!start) return false;

    nvram_inline_patch = true;

    start[0] = 0x52800020; // mov w0, 1
    start[1] = ret;

    printf("%s: Found NVRAM unlock\n", __FUNCTION__);
    return true;
}

bool patch_nvram_table(struct pf_patch_t *patch, uint32_t *stream) {
    if (nvram_patchpoint || nvram_inline_patch) return false;

    // Sanity checks
    uint32_t reg = stream[0] & 0x1f; // adrp
    if (
        ( stream[1]       & 0x3ff) != (reg | (reg << 5)) || // add src and dst
        ((stream[7] >> 5) &  0x1f) !=  reg               || // ldr src
        ((stream[9] >> 5) &  0x1f) !=  reg                  // ldr src
    ) {
        return false;
    }
    const char *str = pf_follow_xref(text_rbuf, stream + 2);
    if (!str) return false;
    if (strcmp(str, "aapl,pci") != 0) {
        return false;
    }
    nvram_inline_patch = true;

    uint32_t *tbnz = pf_find_next(stream + 10, 10, 0x37100000 | (stream[9] & 0x1f), 0xfff8001f); // tbnz wM, 2, 0xfffffff0077ae070
    if (!tbnz) {
        printf("%s: Failed to find tbnz\n", __FUNCTION__);
        return false;
    }

    *tbnz = nop;

    printf("%s: Found NVRAM unlock\n", __FUNCTION__);
    return true;
}

bool patch_task_conversion_eval_ldr(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t * const orig = stream;
    uint32_t lr1 = stream[0],
             lr2 = stream[2];
    // Step 2
    // Make sure that the registers used in tbz are the ones actually
    // loaded by ldr, and that both ldr's use the same offset.
    if((lr1 & 0x1f) != (stream[1] & 0x1f) || (lr2 & 0x1f) != (stream[3] & 0x1f) || (lr1 & 0x3ffc00) != (lr2 & 0x3ffc00))
    {
        printf("%s: opcode check failed\n", __FUNCTION__);
        return false;
    }
    if(found_task_conversion_eval_bl || found_task_conversion_eval_imm) {
        printf("%s: found both bl/imm and ldr\n", __FUNCTION__);
        return false;
    }
    found_task_conversion_eval_ldr = true;

    // Step 3
    // Search backwards for the check "caller == victim".
    // If this is the case, then XNU always allows conversion, so we patch that to always be true.
    // Since this function can be inlined in a lot of different places, our search needs to be quite resilient.
    // Therefore, we start by noting which registers our ldr's above load, and keep track of which registers
    // are moved to which other registers while going backwards, since the check will almost certainly use
    // different registers. We also search for this instruction pattern:
    //
    // cmp xN, xM
    // ccmp xR, xT, {0|4}, ne   -- (optional)
    // ubfm ...                 -- (optional)
    // adrp ...                 -- (optional)
    // b.{eq|ne} ...
    //
    // Where either the cmp or ccmp registers must correspond to ours.
    // We simply patch the first check to always succeed.
    uint32_t regs = (1 << ((lr1 >> 5) & 0x1f)) | (1 << ((lr2 >> 5) & 0x1f));
    for (size_t i = 0; i < 128; ++i) { // arbitrary limit
        uint32_t op = *--stream;
        if (pf_maskmatch32(op, 0xeb00001f, 0xffe0fc1f)) { // cmp xN, xM
            uint32_t n1 = stream[1],
                     n2 = stream[2];
            size_t idx = 2;
            if (pf_maskmatch32(n2, 0x53000000, 0x7f800000)) { // ubfm
                n2 = stream[++idx];
            }
            if (pf_maskmatch32(n2, 0x90000000, 0x9f000000)) { // adrp
                n2 = stream[++idx];
            }
            if (
                // Simple case: just cmp + b.{eq|ne}
                (pf_maskmatch32(n1, 0x54000000, 0xff00001e) && ((regs & (1 << ((op >> 5) & 0x1f))) != 0 && (regs & (1 << ((op >> 16) & 0x1f))) != 0)) ||
                // Complex case: cmp + ccmp + b.{eq|ne}
                (
                    pf_maskmatch32(n1, 0xfa401000, 0xffe0fc1b) && pf_maskmatch32(n2, 0x54000000, 0xff00001e) &&
                    (
                        ((regs & (1 << ((op >> 5) & 0x1f))) != 0 && (regs & (1 << ((op >> 16) & 0x1f))) != 0) ||
                        ((regs & (1 << ((n1 >> 5) & 0x1f))) != 0 && (regs & (1 << ((n1 >> 16) & 0x1f))) != 0)
                    )
                )
            ) {
                *stream = 0xeb1f03ff; // cmp xzr, xzr
                printf("%s: Found task_conversion_eval\n", __FUNCTION__);
                return true;
            }
        }
        else if (pf_maskmatch32(op, 0xaa0003e0, 0xffe0ffe0)) // mov xN, xM
        {
            uint32_t src = (op >> 16) & 0x1f,
                     dst = op & 0x1f;
            regs |= ((regs >> dst) & 1) << src;
        }
    }
    printf("%s: failed to find cmp\n", __FUNCTION__);
    return false;
}

bool patch_task_conversion_eval(uint32_t *stream, bool can_double_match) {
    if (found_task_conversion_eval_ldr) {
        printf("%s: found both ldr and bl/imm\n", __FUNCTION__);
        return false;
    }

    static uint32_t *last_match = NULL;
    for (size_t i = 0; i < 0x48; ++i) {
        uint32_t *ldr = stream - i;
        // Already matched and patched
        if (can_double_match && ldr == last_match) {
            return false;
        }

        // Find ldr/cmp pattern
        if (!(
            (
                (ldr[0] == nop && pf_maskmatch32(ldr[1], 0x58000000, 0xff000000)) // nop + ldr
                ||
                (pf_maskmatch32(ldr[0], 0x90000000, 0x9f000000) && pf_maskmatch32(ldr[1], 0xf9400000 | ((ldr[0] & 0x1f) << 5), 0xffc003e0)) // adrp + ldr
            )
            && pf_maskmatch32(ldr[2], 0xeb00001f | ((ldr[1] & 0x1f) << 5), 0xffe0ffff) // cmp
        )) {
            continue;
        }

        size_t idx = 3;
        if (pf_maskmatch32(ldr[idx], 0xfa401000, 0xffe0fc1b)) { // ccmp {eq|ne}
            ++idx;
        }
        if(!pf_maskmatch32(ldr[idx], 0x54000000, 0xff00001e)) { // b.{eq|ne}
            printf("%s: no b.{eq|ne} after cmp/ccmp?\n", __FUNCTION__);
            return false;
        }

        // Subsequent matches would fail to patch
        if (can_double_match) {
            last_match = stream;
        }

        ldr[2] = 0xeb1f03ff; // cmp xzr, xzr

        printf("%s: Found task_conversion_eval\n", __FUNCTION__);
        return true;
    }
    printf("%s: failed to find ldr of kernel_task\n", __FUNCTION__);
    return false;
}

bool patch_task_conversion_eval_bl(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t bl1 = stream[1],
             bl2 = stream[4];
    // Only match if funcs are the same
    uint32_t *f1 = stream + 1 + pf_signextend_32(bl1, 26), // uint32 takes care of << 2
             *f2 = stream + 4 + pf_signextend_32(bl2, 26); // uint32 takes care of << 2
    if (f1 != f2) {
        return false;
    }
    // Search for bitfield marker in target function. We can be quite restrictive here
    // because if this doesn't match, then nothing will and we'll get a KPF panic.
    // Also make sure we don't seek past the end of any function here.
    for (size_t i = 0; i < 48; ++i) {
        uint32_t op = f1[i];
        if (op == ret) {
            return false;
        } else if (op == 0x530a2900) { // ubfx w0, w8, 0xa, 1
            found_task_conversion_eval_bl = true;

            return patch_task_conversion_eval(stream, false);
        }
    }
    return false;
}

bool patch_task_conversion_eval_imm(struct pf_patch_t *patch, uint32_t *stream) {
    found_task_conversion_eval_imm = true;

    return patch_task_conversion_eval(stream, true);
}

static bool patch_convert_port_to_map(struct pf_patch_t *patch, uint32_t *stream) {
    if (found_convert_port_to_map || !text_has_kmap) return false;
    found_convert_port_to_map = true;

    uint32_t *patchpoint = stream + 7;
    uint32_t op = *patchpoint;
    if (op & 1) { // is b.ne
        // Follow branch (convert to b.al)
        *patchpoint = op | 0xf;
        patchpoint += pf_signextend_32(op >> 5, 19); // uint32 takes care of << 2
    } else {
        // Don't follow branch
        *patchpoint = nop;
        // Continue at next instr
        ++patchpoint;
    }

    // New in iOS 15: zone_require just to annoy us
    bool have_zone_require = pf_maskmatch32(patchpoint[0], 0x52800000, 0xfffffe1f) &&  // movz w0, {0-15}
                             pf_maskmatch32(patchpoint[1], 0x52800001, 0xffffe0ff) &&  // movz w1, {0x0-0x100 with granularity 8}
                             pf_maskmatch32(patchpoint[2], 0x94000000, 0xfc000000);    // bl zone_require
    if (have_zone_require) {
        patchpoint[2] = nop;
    }

    printf("%s: Found convert_port_to_map\n", __FUNCTION__);
    return true;
}

static bool patch_rootdev(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t adrp = stream[0],
             add  = stream[1];
    const char *str = pf_follow_xref(text_rbuf, stream);
    if (!str) return false;
    if(strcmp(str, "rootdev") != 0)
    {
        return false;
    }

    // Make sure this is the correct match
    uint32_t *bl = pf_find_next(stream + 2, 6, 0x94000000, 0xfc000000);
    if(!bl || (bl[1] & 0xff00001f) != 0x35000000 || (bl[2] & 0xfffffe1f) != 0x3900021f) // cbnz w0, ...; strb wzr, [x{16-31}]
    {
        return false;
    }

    if(rootdev_patchpoint)
    {
        printf("%s: Found twice\n", __FUNCTION__);
        return false;
    }
    rootdev_patchpoint = stream;

    printf("%s: Found rootdev\n", __FUNCTION__);
    return true;
}

static bool patch_developer_mode(struct pf_patch_t *patch, uint32_t *stream) {
    if (!text_has_devmode) return false;
    if (found_devmode) {
        printf("%s: Found twice!\n", __FUNCTION__);
        return false;
    }
    found_devmode = true;
    stream[5] = 0x14000000 | ((&stream[0] - &stream[5]) & 0x03ffffff); // uint32 takes care of >> 2

    printf("%s: Found developer mode\n", __FUNCTION__);
    return true;
}

void text_exec_patches(void *real_buf, void *text_buf, size_t text_len, uint64_t text_addr, bool has_rootvp, bool has_cryptex, bool has_kmap, bool has_devmode){
    text_rbuf = real_buf;
    text_sect_buf = text_buf;
    text_sect_addr = text_addr;
    text_has_rootvp = has_rootvp;
    text_has_cryptex = has_cryptex;
    text_has_kmap = has_kmap;
    text_has_devmode = has_devmode;

    uint32_t mount_matches[] = {
        0x321f2fe9 // orr w9, wzr, 0x1ffe
    };

    uint32_t mount_masks[] = {
        0xffffffff
    };

    struct pf_patch_t mac_mount_patch = pf_construct_patch(mount_matches, mount_masks, sizeof(mount_matches) / sizeof(uint32_t), (void *) patch_mac_mount);

    uint32_t mount_matches_alt[] = {
        0x1283ffc9 // // movz w/x9, 0x1ffe/-0x1fff
    };

    uint32_t mount_masks_alt[] = {
        0x3fffffff
    };

    struct pf_patch_t mac_mount_patch_alt = pf_construct_patch(mount_matches_alt, mount_masks_alt, sizeof(mount_matches_alt) / sizeof(uint32_t), (void *) patch_mac_mount);

    uint32_t unmount_matches[] = {
        0x52800001, // mov w1, 0
        0x52800002, // mov w2, 0
        0x52800003  // mov w3, 0
    };
    uint32_t unmount_masks[] = {
        0xffffffff,
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t mac_unmount = pf_construct_patch(unmount_matches, unmount_masks, sizeof(unmount_matches) / sizeof(uint32_t), (void *) patch_mac_unmount);

    // r2: /x 00061f121f180071010000540000a837:10feffff1ffeffff1f0000ff1000f8ff
    uint32_t vm_prot_matches_old[] = {
        0x121f0600, // and w{0-15}, w{16-31}, 6
        0x7100181f, // cmp w{0-15}, 6
        0x54000001, // b.ne 0x...
        0x37a80000  // tbnz w{0-15}, 0x15, 0x...
    };
    uint32_t vm_prot_masks_old[] = {
        0xfffffe10,
        0xfffffe1f,
        0xff00001f,
        0xfff80010
    };

    struct pf_patch_t vm_prot_old = pf_construct_patch(vm_prot_matches_old, vm_prot_masks_old, sizeof(vm_prot_matches_old) / sizeof(uint32_t), (void *) patch_vm_prot_branch);

    // r2: /x e003302a1f041f72010000540000a837:f0fff0ff1ffeffff1f0000ff1000e8ff
    uint32_t vm_prot_matches_new[] = {
        0x2a3003e0, // mvn w{0-15}, w{16-31}
        0x721f041f, // tst w{0-15}, 6
        0x54000001, // b.ne 0x...
        0x37a80000  // tbnz w{0-15}, {0x15 | 0x17}, 0x...
    };
    uint32_t vm_prot_masks_new[] = {
        0xfff0fff0,
        0xfffffe1f,
        0xff00001f,
        0xffe80010
    };

    struct pf_patch_t vm_prot_new = pf_construct_patch(vm_prot_matches_new, vm_prot_masks_new, sizeof(vm_prot_matches_new) / sizeof(uint32_t), (void *) patch_vm_prot_branch);

    uint32_t vm_prot_matches17[] = {
        0x6a30001f, // bics wzr, w{0-15}, w{16-31}
        0x54000001, // b.ne 0x...
        0x37a80000  // tbnz w{0-15}, {0x15 | 0x17}, 0x...
    };
    uint32_t vm_prot_masks17[] = {
        0xfff00e1f, // bics wzr, w{0-15}, w{16-31}
        0xff00001f, // b.ne 0x...
        0xffe80010  // tbnz w{0-15}, {0x15 | 0x17}, 0x...
    };

    struct pf_patch_t vm_prot17 = pf_construct_patch(vm_prot_matches17, vm_prot_masks17, sizeof(vm_prot_matches17) / sizeof(uint32_t), (void *) patch_vm_prot_branch);

    // r2: /x e003302a1f041f720100005400000035:f0fff0ff1ffeffff1f0000ff100000ff
    uint32_t vm_prot_matches_new_alt[] = {
        0x2a3003e0, // mvn w{0-15}, w{16-31}
        0x721f041f, // tst w{0-15}, 6
        0x54000001, // b.ne 0x...
        0x35000000  // cbnz w{0-15}, 0x...
    };
    uint32_t vm_prot_masks_new_alt[] = {
        0xfff0fff0,
        0xfffffe1f,
        0xff00001f,
        0xff000010
    };

    struct pf_patch_t vm_prot_new_alt = pf_construct_patch(vm_prot_matches_new_alt, vm_prot_masks_new_alt, sizeof(vm_prot_matches_new_alt) / sizeof(uint32_t), (void *) patch_vm_prot_branch);

    // r2: /x e003302a00041f12:f0fff0ff10feffff
    uint32_t vm_prot_matches_inline[] = {
        0x2a3003e0, // mvn w{0-15}, w{16-31}
        0x121f0400  // and w{0-15}, w{0-15}, 6
    };
    uint32_t vm_prot_masks_inline[] = {
        0xfff0fff0,
        0xfffffe10
    };

    struct pf_patch_t vm_prot_inline = pf_construct_patch(vm_prot_matches_inline, vm_prot_masks_inline, sizeof(vm_prot_matches_inline) / sizeof(uint32_t), (void *) patch_vm_prot_inline);

    uint32_t vmf_enter_matches[] = {
        0x37980000,  // tbnz wN, 0x13
        0x37900000   // tbnz wN, 0x12
    };
    uint32_t vmf_enter_masks[] = {
        0xfff80000,
        0xfff80000
    };

    struct pf_patch_t vmf_enter = pf_construct_patch(vmf_enter_matches, vmf_enter_masks, sizeof(vmf_enter_matches) / sizeof(uint32_t), (void *) patch_vm_fault_enter);

    uint32_t vmf_enter_matches_alt[] = {
        0x37980000,  // tbnz wN, 0x13
        0x37900000   // tbnz wN, 0x12
    };
    uint32_t vmf_enter_masks_alt[] = {
        0xfff80000,
        0xfff80000
    };

    struct pf_patch_t vmf_enter_alt = pf_construct_patch(vmf_enter_matches_alt, vmf_enter_masks_alt, sizeof(vmf_enter_matches_alt) / sizeof(uint32_t), (void *) patch_vm_fault_enter);

    uint32_t vmf_enter_matches14[] = {
        0x36180000, // tbz w*, 3
        0x52800000  // mov w*, 0
    };
    uint32_t vmf_enter_masks14[] = {
        0xfff80000,
        0xffffffe0
    };

    struct pf_patch_t vmf_enter14 = pf_construct_patch(vmf_enter_matches14, vmf_enter_masks14, sizeof(vmf_enter_matches14) / sizeof(uint32_t), (void *) patch_vm_fault_enter14);

    uint32_t vmf_enter_matches14_alt[] = {
        0x36180000, // tbz w*, 3
        0xaa170210, // mov x{16-31}, x{16-31}
        0x52800000  // mov w*, 0
    };
    uint32_t vmf_enter_masks14_alt[] = {
        0xfff80000,
        0xfffffe10,
        0xffffffe0
    };

    struct pf_patch_t vmf_enter14_alt = pf_construct_patch(vmf_enter_matches14_alt, vmf_enter_masks14_alt, sizeof(vmf_enter_matches14_alt) / sizeof(uint32_t), (void *) patch_vm_fault_enter14);

    // r2: /x 00008192007fbef2:00ffffff00ffffff
    uint32_t getaddr_matches[] = {
        0x92810000, // movn x*, 0x800
        0xf2be7f00  // movk x*, 0xf3f8, lsl 16
    };
    uint32_t getaddr_masks[] = {
        0xffffff00,
        0xffffff00
    };

    struct pf_patch_t vnode_getaddr = pf_construct_patch(getaddr_matches, getaddr_masks, sizeof(getaddr_matches) / sizeof(uint32_t), (void *) patch_vnode_getaddr);

    uint32_t getpath_matches[] = {
        0xaa1303e0, // mov x0, x19
        0,
        0xaa0003e1, // mov x1, x0
        0x52800002, // movz w2, 0
        0x52800003, // movz w3, 0
        0xaa1303e0  // mov x0, x19
    };
    uint32_t getpath_masks[] = {
        0xffffffff,
        0,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t vnode_getpath = pf_construct_patch(getpath_matches, getpath_masks, sizeof(getpath_matches) / sizeof(uint32_t), (void *) patch_vnode_getpath);

    uint32_t getpath_matches_alt[] = {
        0xaa1303e0, // mov x0, x19
        0,
        0xaa0003e1, // mov x1, x0
        0xaa1303e0, // mov x0, x19
        0x52800002, // movz w2, 0
        0x52800003  // movz w3, 0
    };
    uint32_t getpath_masks_alt[] = {
        0xffffffff,
        0,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t vnode_getpath_alt = pf_construct_patch(getpath_matches_alt, getpath_masks_alt, sizeof(getpath_matches_alt) / sizeof(uint32_t), (void *) patch_vnode_getpath);

    uint32_t ret0_matches[] = {
        0xd2800000, // mov x0, 0
        ret
    };

    uint32_t ret0_masks[] = {
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t ret0 = pf_construct_patch(ret0_matches, ret0_masks, sizeof(ret0_matches) / sizeof(uint32_t), (void *) patch_ret0_gadget);

    // r2: /x 002088520000b072:e0ffffffe0ffffff
    uint32_t fsctl_matches[] = {
        0x52882000, // mov wN, 0x4100
        0x72b00000  // movk wN, 0x8000, lsl 16
    };
    uint32_t fsctl_masks[] = {
        0xffffffe0,
        0xffffffe0
    };

    struct pf_patch_t fsctl = pf_construct_patch(fsctl_matches, fsctl_masks, sizeof(fsctl_matches) / sizeof(uint32_t), (void *) patch_fsctl_dev_by_role);

    uint32_t vnode_oc_matches[] = {
        0x5280c061, // mov w1, 0x603
        0x52803002  // mov w2, 0x180
    };
    uint32_t vnode_oc_masks[] = {
        0xffffffff,
        0xffffffff
    };

    struct pf_patch_t vnode_oc = pf_construct_patch(vnode_oc_matches, vnode_oc_masks, sizeof(vnode_oc_matches) / sizeof(uint32_t), (void *) patch_vnode_open_close);

    // r2: /x 60068d528000b072:f0fffffff0ffffff
    uint32_t rootvp_matches[] = {
        0x528d0660, // movz w{0-15}, 0x6833
        0x72b00080  // movk w{0-15}, 0x8004, lsl 16
    };
    uint32_t rootvp_masks[] = {
        0xfffffff0,
        0xfffffff0
    };

    struct pf_patch_t rootvp = pf_construct_patch(rootvp_matches, rootvp_masks, sizeof(rootvp_matches) / sizeof(uint32_t), (void *) patch_vnop_rootvp_auth);

    uint32_t srrr_matches[] = {
        0xaa1003e0, // mov x0, x{16-31}
        0x94000000, // bl IOLockLock
        0xf9400210, // ldr x{16-31}, [x{16-31}, .*]
        0xaa1003e0, // mov x0, x{16-31}
        0x94000000, // bl IOLockUnlock
        0xb4000010  // cbz x{16-31}, ...
    };
    uint32_t srrr_masks[] = {
        0xfff0ffff,
        0xfc000000,
        0xffc00210,
        0xfff0ffff,
        0xfc000000,
        0xff000010
    };

    struct pf_patch_t srrr = pf_construct_patch(srrr_matches, srrr_masks, sizeof(srrr_matches) / sizeof(uint32_t), (void *) patch_shared_region_root_dir);

    uint32_t count = (_dyld_shc_end - _dyld_shc);
    // get rid of this
    {
        count += (_sandbox_shellcode_end - _sandbox_shellcode);
        count += 2; /* new rootdev string */
        //+ (kdi_shc_end - kdi_shc) + (fsctl_shc_end - fsctl_shc);
    }
    uint32_t shc_matches[count];
    uint32_t shc_masks[count];
    for(size_t i = 0; i < count; ++i)
    {
        shc_matches[i] = 0;
        shc_masks[i] = 0xffffffff;
    }
    struct pf_patch_t shc = pf_construct_patch(shc_matches, shc_masks, sizeof(shc_matches) / sizeof(uint32_t), (void *) patch_shellcode_area);

    uint32_t dyld_matches[] = {
        0xaa1003e0, // mov x0, x{16-31}
        0xaa1003e1, // mov x1, x{16-31}
        0x94000000, // bl sym._strnlen
        0xeb10001f, // cmp x0, x{16-31}
        0x54000002, // b.hs 0x...
        0x90000000, // adrp xN, "/usr/lib/dyld"@PAGE
        0x91000000  // add xN, xN, "/usr/lib/dyld"@PAGEOFF
    };
    uint32_t dyld_masks[] =
    {
        0xfff0ffff,
        0xfff0ffff,
        0xfc000000,
        0xfff0ffff,
        0xff00001f,
        0x9f000000,
        0xffc00000
    };

    struct pf_patch_t dyld = pf_construct_patch(dyld_matches, dyld_masks, sizeof(dyld_matches) / sizeof(uint32_t), (void *) patch_dyld);

    uint32_t nvram_matches[] = {
        0xf8418c00, // ldr x*, [x*, 0x18]!
        0xb5000000, // cbnz x*, 0x...
        0xb9400c00  // ldr w0, [x*, 0xc]
    };
    uint32_t nvram_masks[] = {
        0xfffffc00,
        0xff000000,
        0xfffffc1f
    };

    struct pf_patch_t nvram = pf_construct_patch(nvram_matches, nvram_masks, sizeof(nvram_matches) / sizeof(uint32_t), (void *) patch_nvram);

    uint32_t nvram140_matches[] = {
        0xf8418c00, // ldr x*, [x*, 0x18]!
        0xb5000000, // cbnz x*, 0x...
        0xaa090000, // mov x*, x*
        0xb9400c00  // ldr w0, [x*, 0xc]
    };
    uint32_t nvram140_masks[] = {
        0xfffffc00,
        0xff000000,
        0xfffffc00,
        0xfffffc1f
    };

    struct pf_patch_t nvram140 = pf_construct_patch(nvram140_matches, nvram140_masks, sizeof(nvram140_matches) / sizeof(uint32_t), (void *) patch_nvram);

    uint32_t nvram142_matches[] = {
        0x39404400, 0x7101881f, 0x54000001, // b
        0x39404800, 0x7101bc1f, 0x54000001, // o
        0x39404c00, 0x7101bc1f, 0x54000001, // o
        0x39405000, 0x7101d01f, 0x54000001, // t
        0x39405400, 0x7100b41f, 0x54000001, // -
        0x39405800, 0x7101b81f, 0x54000001, // n
        0x39405c00, 0x7101bc1f, 0x54000001, // o
        0x39406000, 0x7101b81f, 0x54000001, // n
        0x39406400, 0x71018c1f, 0x54000001, // c
        0x39406800, 0x7101941f, 0x54000001  // e
    };
    uint32_t nvram142_masks[] = {
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f,
        0xfffffc00, 0xfffffc1f, 0xff00001f
    };

    struct pf_patch_t nvram142 = pf_construct_patch(nvram142_matches, nvram142_masks, sizeof(nvram142_matches) / sizeof(uint32_t), (void *) patch_nvram_inline);

    uint32_t nvram164_matches[] = {
        0x90000010, // adrp xN, 0x...
        0x91000210, // add xN, xN, 0x...
        0x90000000, // adrp x0, 0x...
        0x91000000, // add x0, x0, 0x...
        0xaa1003e1, // mov x1, x{16-31}
        0x94000000, // bl sym._strcmp
        0x34000060, // cbz w0, .+12
        0xf8400c00, // ldr x0, [xN, ...]!
        0xb5ffff80, // cbnz x0, .-16
        0xf9400610, // ldr x{16-31}, [xN, 8]
    };
    uint32_t nvram164_masks[] = {
        0x9f000010,
        0xffc00210,
        0x9f00001f,
        0xffc003ff,
        0xfff0ffff,
        0xfc000000,
        0xffffffff,
        0xffe00c1f,
        0xffffffff,
        0xfffffe10,
    };

    struct pf_patch_t nvram164 = pf_construct_patch(nvram164_matches, nvram164_masks, sizeof(nvram164_matches) / sizeof(uint32_t), (void *) patch_nvram_table);

    // r2: /x 000040b900005036000040b900005036:0000c0ff0000f8ff0000c0ff0000f8fe
    uint32_t tce_matches[] = {
        0xb9400000, // ldr x*, [x*]
        0x36500000, // tbz w*, 0xa, *
        0xb9400000, // ldr x*, [x*]
        0x36500000  // tbz w*, 0xa, *
    };
    uint32_t tce_masks[] = {
        0xffc00000,
        0xfff80000,
        0xffc00000,
        0xfef80000  // match both tbz or tbnz
    };

    struct pf_patch_t tce = pf_construct_patch(tce_matches, tce_masks, sizeof(tce_matches) / sizeof(uint32_t), (void *) patch_task_conversion_eval_ldr);

    uint32_t tce_matches_bl[] = {
        0xaa0003e0, // mov x0, xN
        0x94000000, // bl 0x{same}
        0x34000000, // cbz w0, 0x...
        0xaa1003e0, // mov x0, x{16-31}
        0x94000000, // bl 0x{same}
        0x34000000  // cb(n)z w0, 0x...
    };
    uint32_t tce_masks_bl[] = {
        0xffe0ffff,
        0xfc000000,
        0xff00001f,
        0xfff0ffff,
        0xfc000000,
        0xfe00001f
    };

    struct pf_patch_t tce_bl = pf_construct_patch(tce_matches_bl, tce_masks_bl, sizeof(tce_matches_bl) / sizeof(uint32_t), (void *) patch_task_conversion_eval_bl);

    uint32_t tce_matches_imm[] = {
        0x12002400, // and w*, w*, 0x3ff
        0x7100141f, // cmp w*, 5
        0x54000001, // b.ne 0x...
        0xf9400400, // ldr x*, [x*, 0x...]
        0xeb00001f, // cmp x*, x*
        0x54000001, // b.ne 0x...
        0x39400400, // ldrb w*, [x*, 0x... & 0x1]
        0x36100000  // tbz w*, 2, 0x...
    };
    uint32_t tce_masks_imm[] = {
        0xfffffc00,
        0xfffffc1f,
        0xff00001f,
        0xfffffc00,
        0xffe0fc1f,
        0xff00001f,
        0xffc00400,
        0xfef80000
    };

    struct pf_patch_t tce_imm = pf_construct_patch(tce_matches_imm, tce_masks_imm, sizeof(tce_matches_imm) / sizeof(uint32_t), (void *) patch_task_conversion_eval_imm);

    uint32_t kmap_matches[] = {
        0x39400000, // ldr(b) wN, [xM, ...]
        0x34000000, // cbz
        0xf9400000, // ldr xN, [xM, {0x0-0x78}]
        0xf9402000, // ldr xN, [xM, {0x40|0x48}]
        0x90000000, // adrp
        0xf9400000, // ldr xN, [xM, ...]
        0xeb00001f, // cmp
        0x54000000  // b.ne / b.eq
    };
    uint32_t kmap_masks[] = {
        0x7fc00000,
        0xff000000,
        0xffffc000,
        0xfffff800,
        0x9f000000,
        0xffc00000,
        0xffe0fc1f,
        0xff00001e
    };

    struct pf_patch_t kmap = pf_construct_patch(kmap_matches, kmap_masks, sizeof(kmap_matches) / sizeof(uint32_t), (void *) patch_convert_port_to_map);

    uint32_t kmap_matches_alt[] = {
        0x39400000, // ldr(b) wN, [xM, ...]
        0x34000000, // cbz
        0xf9400000, // ldr xN, [xM, {0x0-0x78}]
        0xf9402000, // ldr xN, [xM, {0x40|0x48}]
        nop,
        0x58000000, // ldr
        0xeb00001f, // cmp
        0x54000000  // b.ne / b.eq
    };
    uint32_t kmap_masks_alt[] = {
        0x7fc00000,
        0xff000000,
        0xffffc000,
        0xfffff800,
        0xffffffff,
        0xff000000,
        0xffe0fc1f,
        0xff00001e
    };

    struct pf_patch_t kmap_alt = pf_construct_patch(kmap_matches_alt, kmap_masks_alt, sizeof(kmap_matches_alt) / sizeof(uint32_t), (void *) patch_convert_port_to_map);

    uint32_t kmap_matches155[] = {
        0x39400000, // ldrb wN, [xM, ...]
        0x34000000, // cbz
        0xf9400000, // ldr xN, [xM, {0x0-0x78}]
        0xf9402000, // ldr xN, [xM, {0x40|0x48}]
        0x90000000, // adrp
        0x91000000, // add
        0xeb00001f, // cmp
        0x54000000  // b.ne / b.eq
    };
    uint32_t kmap_masks155[] = {
        0xffc00000,
        0xff000000,
        0xffffc000,
        0xfffff800,
        0x9f000000,
        0xffc00000,
        0xffe0fc1f,
        0xff00001e
    };

    struct pf_patch_t kmap155 = pf_construct_patch(kmap_matches155, kmap_masks155, sizeof(kmap_matches155) / sizeof(uint32_t), (void *) patch_convert_port_to_map);

    // A ton of kexts check for "rd=md*" and "rootdev=md*" in order to determine whether we're restoring.
    // We previously tried to patch all of those, but that is really tedious to do, and it's basically
    // impossible to determine whether you found all instances.
    // What we do now is just change the place that actually boots off the ramdisk from "rootdev" to "spartan",
    // and then patch the boot-args string to reflect that.
    //
    // Because codegen orders function args differently across versions and may or may not inline stuff,
    // we just match adrp+add to either x0 or x1, and check the string and the rest in the callback.
    //
    // /x 0000009000000091:1e00009fde03c0ff
    uint32_t rootdev_matches[] =
    {
        0x90000000, // adrp x{0|1}, 0x...
        0x91000000, // add x{0|1}, x{0|1}, 0x...
    };
    uint32_t rootdev_masks[] =
    {
        0x9f00001e,
        0xffc003de,
    };
    struct pf_patch_t rootdev = pf_construct_patch(rootdev_matches, rootdev_masks, sizeof(rootdev_matches)/sizeof(uint32_t), (void*)patch_rootdev);

    // Find enable_developer_mode and disable_developer_mode in AMFI,
    // then we patch the latter to branch to the former
    //
    // Example from iPad 6th gen iOS 16.0 beta 3:
    // ;-- _enable_developer_mode:
    // 0xfffffff007633f74      681300f0       adrp x8, 0xfffffff0078a2000
    // 0xfffffff007633f78      08810291       add x8, x8, 0xa0
    // 0xfffffff007633f7c      29008052       movz w9, 0x1
    // 0xfffffff007633f80      09fd9f08       stlrb w9, [x8]
    // 0xfffffff007633f84      c0035fd6       ret
    // ;-- _disable_developer_mode:
    // 0xfffffff007633f88      681300f0       adrp x8, 0xfffffff0078a2000
    // 0xfffffff007633f8c      08810291       add x8, x8, 0xa0
    // 0xfffffff007633f90      1ffd9f08       stlrb wzr, [x8]
    // 0xfffffff007633f94      c0035fd6       ret
    // /x 08000090080100912900805209010008c0035fd6080000900801009109010008c0035fd6:1f00009fff038097ffffffffff0360ceffffffff1f00009fff038097e90360ceffffffff

    uint32_t devmode_matches[] = {
        0x90000008, // adrp x8, ...
        0x91000108, // {ldr,add} x8, [x8, ...]
        0x52800029, // mov w9, #0x1
        0x08000109, // str{l,}b w9, [x8]
        ret, // ret
        0x90000008, // adrp x8, ...
        0x91000108, // {ldr,add} x8, [x8, ...]
        0x08000109, // str{l,}b wzr, [x8]
        ret, // ret
    };
    uint32_t devmode_masks[] = {
        0x9f00001f,
        0x978003ff,
        0xffffffff,
        0xce6003ff,
        0xffffffff,
        0x9f00001f,
        0x978003ff,
        0xce6003e9,
        0xffffffff,
    };
    struct pf_patch_t developer_mode = pf_construct_patch(devmode_matches, devmode_masks, sizeof(devmode_matches) / sizeof(uint32_t), (void *) patch_developer_mode);

    struct pf_patch_t patches[] = {
        mac_mount_patch,
        mac_mount_patch_alt,
        mac_unmount,
        vm_prot_old,
        vm_prot_new,
        vm_prot_new_alt,
        vm_prot_inline,
        vm_prot17,
        vmf_enter,
        vmf_enter_alt,
        vmf_enter14,
        vmf_enter14_alt,
        vnode_getaddr,
        vnode_getpath,
        vnode_getpath_alt,
        ret0,
        fsctl,
        vnode_oc,
        rootvp,
        srrr,
        shc,
        dyld,
        nvram,
        nvram140,
        nvram142,
        nvram164,
        tce,
        tce_bl,
        tce_imm,
        kmap,
        kmap_alt,
        kmap155,
        rootdev,
        developer_mode
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(text_buf, text_len, patchset);
}
