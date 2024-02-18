#ifdef __gnu_linux__
#define _GNU_SOURCE 
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "formats/macho.h"
#include "plooshfinder.h"
#include "patches/apfs.h"
#include "patches/amfi.h"
#include "patches/sandbox.h"
#include "patches/kext.h"
#include "patches/traps.h"
#include "patches/sbops.h"
#include "patches/shellcode.h"
#include "patches/text.h"
#include "mac.h"

void *kernel_buf;
size_t kernel_len;
int platform = 0;

#define addr_to_ptr(addr) macho_va_to_ptr(kernel_buf, macho_xnu_untag_va(addr))
#define patch(function, addr, size, ...) function(kernel_buf, addr_to_ptr(addr), size, ##__VA_ARGS__);
#define find_str_in_region(str, addr, size) memmem(addr, size, str, sizeof(str));
#define find_partial_str_in_region(str, addr, size) memmem(addr, size, str, sizeof(str) - 1);
#define patch_sbop(ops, op, val)       \
    if (ops->op) {                     \
        ops->op &= 0xFFFFFFFF00000000; \
        ops->op |= val;                \
    }

int patch_kernel(void) {
    printf("Starting KPlooshFinder\n");

    struct section_64 *data_const = macho_find_section(kernel_buf, "__DATA_CONST", "__const");
    if (!data_const) {
        printf("Unable to find data const!\n");
        return 1;
    }

    struct section_64 *cstring = macho_find_section(kernel_buf, "__TEXT", "__cstring");
    if (!cstring) {
        printf("Unable to find cstring!\n");
        return 1;
    }

    struct section_64 *text = macho_find_section(kernel_buf, "__TEXT_EXEC", "__text");
    if (!text) {
        printf("Unable to find text!\n");
        return 1;
    }


    const char rootvp_string[] = "rootvp not authenticated after mounting";
    const char *rootvp_string_match = find_partial_str_in_region(rootvp_string, kernel_buf + cstring->offset, cstring->size);
    const char constraints_string[] = "mac_proc_check_launch_constraints";
    const char *constraints_string_match = find_str_in_region(constraints_string, kernel_buf + cstring->offset, cstring->size);
    const char cryptex_string[] = "/private/preboot/Cryptexes";
    const char *cryptex_string_match = find_str_in_region(cryptex_string, kernel_buf + cstring->offset, cstring->size);
    const char kmap_port_string[] = "userspace has control access to a"; // iOS 14 had broken panic strings
    const char *kmap_port_string_match = find_partial_str_in_region(kmap_port_string, kernel_buf + cstring->offset, cstring->size);

    struct mach_header_64 *apfs_kext = macho_find_kext(kernel_buf, "com.apple.filesystems.apfs");
    if (!apfs_kext) {
        printf("Unable to find APFS kext!\n");
        return 1;
    }

    struct section_64 *apfs_text = macho_find_section(apfs_kext, "__TEXT_EXEC", "__text");
    if (!apfs_text) {
        printf("Unable to find APFS text!\n");
        return 1;
    }
    
    patch(patch_apfs_kext, apfs_text->addr, apfs_text->size, rootvp_string_match == NULL);

    struct mach_header_64 *amfi_kext = macho_find_kext(kernel_buf, "com.apple.driver.AppleMobileFileIntegrity");
    if (!amfi_kext) {
        printf("Unable to find AMFI kext!\n");
        return 1;
    }

    struct section_64 *amfi_text = macho_find_section(amfi_kext, "__TEXT_EXEC", "__text");
    if (!amfi_text) {
        printf("Unable to find AMFI text!\n");
        return 1;
    }

    struct section_64 *amfi_cstring = macho_find_section(amfi_kext, "__TEXT", "__cstring");

    struct section_64 *devmode_cstring = amfi_cstring ? amfi_cstring : cstring;
    void *devmode_straddr = amfi_cstring ? addr_to_ptr(amfi_cstring->addr) : kernel_buf + cstring->offset;

    const char dev_mode_string[] = "AMFI: developer mode is force enabled\n";
    const char *dev_mode_string_match = find_str_in_region(dev_mode_string, devmode_straddr, devmode_cstring->size);

    struct mach_header_64 *sandbox_kext = macho_find_kext(kernel_buf, "com.apple.security.sandbox");
    if (!sandbox_kext) {
        printf("Unable to find sandbox kext!\n");
        return 1;
    }

    struct section_64 *sandbox_text = macho_find_section(sandbox_kext, "__TEXT_EXEC", "__text");
    if (!sandbox_text) {
        printf("Unable to find sandbox text!\n");
        return 1;
    }

    //macho_run_each_kext(kernel_buf, (void *) patch_all_kexts);

    patch(patch_mach_traps, data_const->addr, data_const->size);

    // sbops useful shit
    /*
    fffffff006f33d98  data_fffffff006f33d98:
fffffff006f33d98                          ad b9 63 05 f0 ff ff ff          ..c.....
fffffff006f33da0  14 9f 63 05 f0 ff ff ff f0 3d f3 06 f0 ff ff ff  ..c......=......
fffffff006f33db0  01 00 00 00 00 00 00 00 f8 3d f3 06 f0 ff ff ff  .........=......
fffffff006f33dc0  00 00 00 00 00 00 00 00 94 3d f3 06 f0 ff ff ff  .........=......
fffffff006f33dd0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
fffffff006f33de0  00 00 00 00 00 00 00 00                          ........
fffffff006f33de8  data_fffffff006f33de8:
fffffff006f33de8                          00 00 00 00 00 00 00 00          ........
fffffff006f33df0  2c 9f 63 05 f0 ff ff ff 00 00 00 00 00 00 00 00  ,.c.............
fffffff006f33e00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
fffffff006f33e10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
fffffff006f33e20  00 00 00 00 00 00 00 00 a8 b7 68 06 f0 ff ff ff  ..........h.....
fffffff006f33e30  9c 1f 67 06 f0 ff ff ff 00 00 00 00 00 00 00 00  ..g.............

*/

    struct section_64 *sandbox_cstring = macho_find_section(sandbox_kext, "__TEXT", "__cstring");
    struct section_64 *sbops_cstring = sandbox_cstring ? sandbox_cstring : cstring;
    void *sbops_cstring_addr = sandbox_cstring ? addr_to_ptr(sandbox_cstring->addr) : kernel_buf + cstring->offset;

    const char sbops_string[] = "Seatbelt sandbox policy";
    const char *sbops_string_match = find_str_in_region(sbops_string, sbops_cstring_addr, sbops_cstring->size);

    if (!sbops_string_match) {
        printf("Unable to find sbops string!\n");
        return 1;
    }

    const char protobox_string[] = "\"failed to initialize protobox collection: %d\" @%s:%d";
    const char *protobox_string_match = find_str_in_region(protobox_string, sbops_cstring_addr, sbops_cstring->size);

    struct section_64 *sandbox_data_const = macho_find_section(sandbox_kext, "__DATA_CONST", "__const");
    struct section_64 *sbops_data_const = sandbox_cstring ? sandbox_data_const : data_const;
    
    uint64_t sbops_string_addr = sbops_cstring->addr + (uint64_t) ((void *) sbops_string_match - sbops_cstring_addr);

    patch(patch_sandbox_kext, sandbox_text->addr, sandbox_text->size, protobox_string_match != NULL);

    patch(sbops_patch, sbops_data_const->addr, sbops_data_const->size, sbops_string_addr);

    patch(patch_amfi_kext, amfi_text->addr, amfi_text->size, constraints_string_match != NULL);

    patch(text_exec_patches, text->addr, text->size, text->addr, rootvp_string_match != NULL, cryptex_string_match != NULL, kmap_port_string_match != NULL, dev_mode_string != NULL);

    if (!found_amfi_mac_syscall) {
        printf("%s: no amfi_mac_syscall\n", __FUNCTION__);
        return 1;
    } else if (!found_mac_unmount) {
        printf("%s: no dounmount\n", __FUNCTION__);
        return 1;
    } else if (!repatch_ldr_x19_vnode_pathoff) {
        printf("%s: no repatch_ldr_x19_vnode_pathoff\n", __FUNCTION__);
        return 1;
    } else if (!found_sbops) {
        printf("%s: no sbops?\n", __FUNCTION__);
        return 1;
    } else if (!amfi_ret) {
        printf("%s: no amfi_ret?\n", __FUNCTION__);
        return 1;
    } else if (!vnode_lookup) {
        printf("%s: no vnode_lookup\n", __FUNCTION__);
        return 1;
    } else if (!vnode_put) {
        printf("%s: no vnode_put\n", __FUNCTION__);
        return 1;
    } else if (offsetof_p_flags == UINT32_MAX) {
        printf("%s: no p_flags?\n", __FUNCTION__);
        return 1;
    } else if (!found_vm_fault_enter) {
        printf("%s: no vm_fault_enter\n", __FUNCTION__);
        return 1;
    } else if (!found_vm_map_protect) {
        printf("%s: no vm_map_protect\n", __FUNCTION__);
        return 1;
    } else if (!vfs_context_current) {
        printf("%s: no vfs_context_current\n", __FUNCTION__);
        return 1;
    } else if (!rootvp_string_match && !found_mac_mount) {
        printf("%s: no mac_mount\n", __FUNCTION__);
        return 1;
    } else if (!dyld_hook_patchpoint) {
        printf("%s: no dyld hook?\n", __FUNCTION__);
        return 1;
    } else if (!rootdev_patchpoint) {
        printf("%s: no rootdev\n", __FUNCTION__);
        return 1;
    }

    if (protobox_string_match && !found_protobox) {
        printf("%s: no protobox\n", __FUNCTION__);
        return 1;
    } else if (dev_mode_string_match && !found_devmode) {
        printf("%s: no developer mode\n", __FUNCTION__);
        return 1;
    } else if (constraints_string_match && !found_launch_constraints) {
        printf("%s: no launch constraints\n", __FUNCTION__);
        return 1;
    }

    uint64_t shc_va = macho_ptr_to_va(kernel_buf, &shellcode_area[1]);
    uint64_t ret_va = macho_ptr_to_va(kernel_buf, amfi_ret);

    uint32_t delta = (shc_va - ret_va) / 4;

    delta &= 0x03ffffff;
    delta |= 0x14000000;
    
    *amfi_ret = delta;

    uint64_t shc_addr = macho_ptr_to_va(kernel_buf, shellcode_area);

    struct mac_policy_ops *sbops_struct = (struct mac_policy_ops *) sbops;

    uint64_t ret0 = ret0_gadget & 0xffffffff;
    uint64_t open_shc = shc_addr & 0xffffffff; 

    patch_sbop(sbops_struct, mpo_mount_check_mount, ret0);
    patch_sbop(sbops_struct, mpo_mount_check_remount, ret0);
    patch_sbop(sbops_struct, mpo_mount_check_umount, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_write, ret0);
    patch_sbop(sbops_struct, mpo_file_check_mmap, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_rename, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_access, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_chroot, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_create, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_deleteextattr, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_exchangedata, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_exec, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_getattrlist, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_getextattr, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_ioctl, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_link, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_listextattr, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_open, open_shc);
    patch_sbop(sbops_struct, mpo_vnode_check_readlink, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_setattrlist, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_setextattr, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_setflags, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_setmode, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_setowner, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_setutimes, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_stat, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_truncate, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_unlink, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_fsgetpath, ret0);
    patch_sbop(sbops_struct, mpo_vnode_check_getattr, ret0);
    patch_sbop(sbops_struct, mpo_mount_check_stat, ret0);
    patch_sbop(sbops_struct, mpo_proc_check_get_cs_info, ret0);
    patch_sbop(sbops_struct, mpo_proc_check_set_cs_info, ret0);
    uint64_t update_execve = sbops_struct->mpo_cred_label_update_execve;
    patch_sbop(sbops_struct, mpo_cred_label_update_execve, open_shc + 8);

    uint32_t *shellcode_from = _sandbox_shellcode;
    uint32_t *shellcode_end = _sandbox_shellcode_end;
    uint32_t *shellcode_to = shellcode_area;
    // Identify where the LDR/STR insns that will need to be patched will be
    uint32_t *repatch_sandbox_shellcode_setuid_patch = (void *) _sandbox_shellcode_setuid_patch - (void *) shellcode_from + (void *) shellcode_to;
    uint64_t *repatch_sandbox_shellcode_ptrs = (uint64_t *)((void *) _sandbox_shellcode_ptrs - (void *) shellcode_from + (void *) shellcode_to);

    while(shellcode_from < shellcode_end) {
        *shellcode_to++ = *shellcode_from++;
    }

    if (repatch_sandbox_shellcode_ptrs[0] != 0x4141413341414132) {
        printf("%s: Sandbox shellcode corruption\n", __FUNCTION__);
        return 1;
    }
    // Patch offset into LDR and STR p->p_flags
    repatch_sandbox_shellcode_setuid_patch[0] |= ((offsetof_p_flags >> 2) & 0x1ff) << 10;
    repatch_sandbox_shellcode_setuid_patch[2] |= ((offsetof_p_flags >> 2) & 0x1ff) << 10;

    uint64_t vnode_gaddr_p = macho_ptr_to_va(kernel_buf, vnode_gaddr);
    uint64_t vfs_context_current_p = macho_ptr_to_va(kernel_buf, vfs_context_current);
    uint64_t vnode_lookup_p = macho_ptr_to_va(kernel_buf, vnode_lookup);
    uint64_t vnode_put_p = macho_ptr_to_va(kernel_buf, vnode_put);
    // Patch shellcode pointers
    repatch_sandbox_shellcode_ptrs[0] = update_execve;
    repatch_sandbox_shellcode_ptrs[1] = vnode_gaddr_p;
    repatch_sandbox_shellcode_ptrs[2] = vfs_context_current_p;
    repatch_sandbox_shellcode_ptrs[3] = vnode_lookup_p;
    repatch_sandbox_shellcode_ptrs[4] = vnode_put_p;

    uint32_t *repatch_vnode_shellcode = &shellcode_area[5];
    *repatch_vnode_shellcode = repatch_ldr_x19_vnode_pathoff;
    if (rootvp_string_match) {
        uint32_t *shellcode_block = shellcode_to;
        uint64_t shellcode_addr = macho_ptr_to_va(kernel_buf, shellcode_block);
        uint64_t patchpoint_addr = macho_ptr_to_va(kernel_buf, fsctl_patchpoint);
        uint64_t orig_func = patchpoint_addr + 4;

        size_t slow_idx  = _fsctl_shc_stolen_slowpath - _fsctl_shc;
        size_t fast_idx  = _fsctl_shc_stolen_fastpath - _fsctl_shc;
        size_t open_idx  = _fsctl_shc_vnode_open      - _fsctl_shc;
        size_t close_idx = _fsctl_shc_vnode_close     - _fsctl_shc;
        size_t bl_idx    = _fsctl_shc_orig_bl         - _fsctl_shc;
        size_t b_idx     = _fsctl_shc_orig_b          - _fsctl_shc;

        int64_t open_off  = vnode_open_addr  - (shellcode_addr + (open_idx  << 2));
        int64_t close_off = vnode_close_addr - (shellcode_addr + (close_idx << 2));
        int64_t bl_off    = orig_func - (shellcode_addr + (bl_idx << 2));
        int64_t b_off     = orig_func - (shellcode_addr + (b_idx  << 2));
        int64_t patch_off = shellcode_addr - patchpoint_addr;
        if (
            open_off  > 0x7fffffcLL || open_off  < -0x8000000LL ||
            close_off > 0x7fffffcLL || close_off < -0x8000000LL ||
            bl_off    > 0x7fffffcLL || bl_off    < -0x8000000LL ||
            b_off     > 0x7fffffcLL || b_off     < -0x8000000LL ||
            patch_off > 0x7fffffcLL || patch_off < -0x8000000LL
        ) {
            printf("fsctl_shc jump too far: 0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "\n", open_off, close_off, bl_off, b_off, patch_off);
            return 1;
        }

        shellcode_from = _fsctl_shc;
        shellcode_end = _fsctl_shc_end;
        while(shellcode_from < shellcode_end)
        {
            *shellcode_to++ = *shellcode_from++;
        }

        uint32_t stolen = *fsctl_patchpoint;
        shellcode_block[slow_idx]   = stolen;
        shellcode_block[fast_idx]   = stolen;
        shellcode_block[open_idx]  |= (open_off  >> 2) & 0x03ffffff;
        shellcode_block[close_idx] |= (close_off >> 2) & 0x03ffffff;
        shellcode_block[bl_idx]    |= (bl_off    >> 2) & 0x03ffffff;
        shellcode_block[b_idx]     |= (b_off     >> 2) & 0x03ffffff;

        *fsctl_patchpoint = 0x14000000 | ((patch_off >> 2) & 0x03ffffff);
    }

    uint64_t patchpoint_addr = macho_ptr_to_va(kernel_buf, dyld_hook_patchpoint);
    uint64_t dyld_block = macho_ptr_to_va(kernel_buf, shellcode_to);

    size_t ctx_idx    = _dyld_shc_ctx    - _dyld_shc;
    size_t lookup_idx = _dyld_shc_lookup - _dyld_shc;
    size_t put_idx    = _dyld_shc_put    - _dyld_shc;

    int64_t ctx_off    = vfs_context_current_p - (dyld_block + (ctx_idx    << 2));
    int64_t lookup_off = vnode_lookup_p        - (dyld_block + (lookup_idx << 2));
    int64_t put_off    = vnode_put_p           - (dyld_block + (put_idx    << 2));
    int64_t patch_off  = dyld_block - patchpoint_addr;
    if(ctx_off > 0x7fffffcLL || ctx_off < -0x8000000LL || lookup_off > 0x7fffffcLL || lookup_off < -0x8000000LL || put_off > 0x7fffffcLL || put_off < -0x8000000LL || patch_off > 0x7fffffcLL || patch_off < -0x8000000LL) {
        printf("dyld_shc: jump too far: 0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64 "\n", ctx_off, lookup_off, put_off, patch_off);
        return 1;
    }

    memcpy(shellcode_to, _dyld_shc, (uint64_t) _dyld_shc_end - (uint64_t) _dyld_shc);

    shellcode_to[ctx_idx]    |= (ctx_off    >> 2) & 0x03ffffff;
    shellcode_to[lookup_idx] |= (lookup_off >> 2) & 0x03ffffff;
    shellcode_to[put_idx]    |= (put_off    >> 2) & 0x03ffffff;
    *dyld_hook_patchpoint    |= (patch_off  >> 2) & 0x03ffffff;

    if (nvram_patchpoint) {
        uint64_t nvram_patch_from = macho_ptr_to_va(kernel_buf, nvram_patchpoint);
        uint64_t nvram_patch_to = macho_ptr_to_va(kernel_buf, shellcode_to);
        int64_t nvram_off = nvram_patch_to - nvram_patch_from;
        if(nvram_off > 0x7fffffcLL || nvram_off < -0x8000000LL) {
            printf("nvram_shc: jump too far: 0x%" PRIx64 "\n", nvram_off);
            return 1;
        }

        shellcode_from = _nvram_shc;
        shellcode_end = _nvram_shc_end;
        while(shellcode_from < shellcode_end) {
            *shellcode_to++ = *shellcode_from++;
        }

        *nvram_patchpoint = 0x14000000 | (((uint64_t)nvram_off >> 2) & 0x3ffffff);
    }

    uint64_t rootdev_patchpoint_addr = macho_ptr_to_va(kernel_buf, rootdev_patchpoint);
    uint64_t rootdev_shellcode_addr = macho_ptr_to_va(kernel_buf, shellcode_to);
   
    uint64_t rootdev_shellcode_page  = rootdev_shellcode_addr  & ~0xfffULL;
    uint64_t rootdev_patchpoint_page = rootdev_patchpoint_addr & ~0xfffULL;

    int64_t rootdev_shellcode_pagediff = (rootdev_shellcode_page - rootdev_patchpoint_page) >> 12;

    rootdev_patchpoint[0] = (rootdev_patchpoint[0] & 0x9f00001f) | ((rootdev_shellcode_pagediff & 0x3) << 29) | (((rootdev_shellcode_pagediff >> 2) & 0x7ffff) << 5);
    rootdev_patchpoint[1] = (rootdev_patchpoint[1] & 0xffc003ff) | ((rootdev_shellcode_addr & 0xfff) << 10);

    memcpy(shellcode_to, "spartan", 8);

    shellcode_to += 2; /* 8 bytes */

    if (!rootvp_string_match) {
        const char *snapshot = "com.apple.os.update-";
        struct section_64 *apfs_cstring = macho_find_section(apfs_kext, "__TEXT", "__cstring");
        struct section_64 *snapshot_cstring = apfs_cstring ? apfs_cstring : cstring;
        void *snapshot_cstring_addr = apfs_cstring ? addr_to_ptr(apfs_cstring->addr) : kernel_buf + cstring->offset;

        char *snapshotStr = find_str_in_region(snapshot, snapshot_cstring_addr, snapshot_cstring->size);

        if (snapshotStr) {
            *snapshotStr = 'x';
            printf("%s: Disabled snapshot temporarily\n", __FUNCTION__);
        }
    }

    printf("Patching completed successfully.\n");
    return 0;
}

int main(int argc, char **argv) {
    FILE *fp = NULL;

    if (argc < 3) {
        printf("Usage: %s <input kernel> <patched kernel>\n", argv[0]);
        return 0;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Failed to open kernel!\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kernel_buf = (void *) malloc(kernel_len);
    if (!kernel_buf) {
        printf("Out of memory while allocating region for kernel!\n");
        fclose(fp);
        return -1;
    }

    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);

    uint32_t magic = macho_get_magic(kernel_buf);

    if (!magic) {
        free(kernel_buf);
        return 1;
    }

    void *orig_kernel_buf = kernel_buf;
    if (magic == 0xbebafeca) {
        kernel_buf = macho_find_arch(kernel_buf, CPU_TYPE_ARM64);
        if (!kernel_buf) {
            free(orig_kernel_buf);
            return 1;
        }
    }

    platform = macho_get_platform(kernel_buf);
    if (platform == 0) {
        free(orig_kernel_buf);
        return 1;
    }

    int retval = patch_kernel();

    fp = fopen(argv[2], "wb");
    if(!fp) {
        printf("Failed to open output file!\n");
        free(orig_kernel_buf);
        return -1;
    }
    
    fwrite(orig_kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);

    free(orig_kernel_buf);

    return retval;
}
