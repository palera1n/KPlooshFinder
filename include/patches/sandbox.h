#ifndef _PATCHES_SANDBOX_H
#define _PATCHES_SANDBOX_H
#include <stdint.h>
#include <stdlib.h>

extern uint32_t *vnode_lookup;
extern uint32_t *vnode_put;
extern uint32_t *vfs_context_current;

void patch_sandbox_kext(void *real_buf, void *sandbox_buf, size_t sandbox_len, bool has_protobox);

#endif
