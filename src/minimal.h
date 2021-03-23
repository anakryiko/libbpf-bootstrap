/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Facebook */
#ifndef __MINIMAL_H
#define __MINIMAL_H

#define MAX_FUNC_CNT (16 * 1024)
#define MAX_FUNC_MASK (MAX_FUNC_CNT - 1)
/* MAX_CPU_CNT needs to be power-of-2 */
#define MAX_CPU_CNT 64
#define MAX_CPU_MASK (MAX_CPU_CNT - 1)
#define MAX_STACK_DEPTH 64

struct call_stack {
	__u32 func_ids[MAX_STACK_DEPTH];
	long func_res[MAX_STACK_DEPTH];
	__u32 depth;
	__u32 max_depth;
	bool is_err;

	__u32 saved_ids[MAX_STACK_DEPTH];
	long saved_res[MAX_STACK_DEPTH];
	__u32 saved_depth;
	__u32 saved_max_depth;

	long kstack[127];
	long kstack_sz;
};

#define FUNC_IS_ENTRY 0x1
#define FUNC_CANT_FAIL 0x2
#define FUNC_NEEDS_SIGN_EXT 0x4
#define FUNC_RET_PTR 0x8

#endif /* __MINIMAL_H */
