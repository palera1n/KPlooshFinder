#ifndef _PATCHES_TEXT_H
#define _PATCHES_TEXT_H
#include <stdint.h>
#include <stdlib.h>

extern bool found_mac_mount;
extern bool found_mac_unmount;
extern bool found_vm_map_protect;
extern bool found_vm_fault_enter;
extern bool found_fsctl_internal;
extern bool found_vnode_open_close;
extern bool found_shared_region_root_dir;
extern bool found_task_conversion_eval_ldr;
extern bool found_task_conversion_eval_bl;
extern bool found_task_conversion_eval_imm;
extern bool found_convert_port_to_map;

extern uint32_t *vnode_gaddr;
extern uint32_t repatch_ldr_x19_vnode_pathoff;
extern uint64_t ret0_gadget;
extern uint32_t *fsctl_patchpoint;
extern uint64_t vnode_open_addr;
extern uint64_t vnode_close_addr;
extern uint32_t *shellcode_area;
extern uint32_t *dyld_hook_patchpoint;
extern uint32_t *nvram_patchpoint;
extern uint32_t* rootdev_patchpoint;

void text_exec_patches(void *real_buf, void *text_buf, size_t text_len, uint64_t text_addr, bool has_rootvp, bool has_cryptex, bool has_kmap);

#endif
