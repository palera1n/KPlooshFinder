#ifndef _PATCHES_SHELLCODE_H
#define _PATCHES_SHELLCODE_H
#include <stdint.h>

extern uint32_t _sandbox_shellcode[4];
extern uint32_t _sandbox_shellcode_setuid_patch[4];
extern uint64_t orig[1];

#define _sandbox_shellcode_ptrs orig

extern uint32_t _dyld_shc[4];
#define _sandbox_shellcode_end _dyld_shc
extern uint32_t _dyld_shc_ctx[8];
extern uint32_t _dyld_shc_lookup[4];
extern uint32_t _dyld_shc_put[4];

extern uint32_t _nvram_shc[4];
#define _dyld_shc_end _nvram_shc
#define _nvram_shc_end _fsctl_shc

extern uint32_t _fsctl_shc[28];
extern uint32_t _fsctl_shc_vnode_open[9];
extern uint32_t _fsctl_shc_stolen_slowpath[3];
extern uint32_t _fsctl_shc_orig_bl[8];
extern uint32_t _fsctl_shc_vnode_close[4];
extern uint32_t _fsctl_shc_stolen_fastpath[1];
extern uint32_t _fsctl_shc_orig_b[1];
extern char L_fsctl_shc_mnt[9];
#define _fsctl_shc_end (void *) L_fsctl_shc_mnt + 9

#endif
