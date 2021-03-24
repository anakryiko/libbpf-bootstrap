// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "minimal.h"

#undef bpf_printk
#define bpf_printk(fmt, ...)						\
({									\
	static const char ___fmt[] = fmt;				\
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);	\
})

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, unsigned);
} ip_to_id SEC(".maps");

bool ready = false;
int running[MAX_CPU_CNT] = {};

static __always_inline bool recur_enter(u32 cpu)
{
	if (running[cpu & MAX_CPU_MASK])
		return false;

	running[cpu & MAX_CPU_MASK] += 1;

	return true;
}

static __always_inline void recur_exit(u32 cpu)
{
	running[cpu & MAX_CPU_MASK] -= 1;
}

static __always_inline u64 get_ftrace_caller_ip(void *ctx, int arg_cnt)
{
	u64 off = 1 /* skip orig rbp */ + 1 /* skip reserved space for ret value */;
	u64 ip;

	if (arg_cnt <= 6)
		off += arg_cnt;
	else
		off += 6;
	off = (u64)ctx + off * 8;

	if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off))
		return 0;

	ip -= 5; /* compensate for 5-byte fentry stub */
	return ip;
}

static int handle_func_entry(void *ctx, u32 cpu, u32 func_id, u64 func_ip);
static int handle_func_exit(void *ctx, u32 cpu, u32 func_id, u64 func_ip, u64 ret);

/* we need arg_cnt * sizeof(__u64) to be a constant, so need to inline */
static __always_inline int handle(void *ctx, int arg_cnt, bool entry)
{
	u32 *id_ptr, cpu = bpf_get_smp_processor_id();
	const char *name;
	long ip;

	if (!ready)
		return 0;
	if (!recur_enter(cpu))
		return 0;

	ip = get_ftrace_caller_ip(ctx, arg_cnt);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("UNRECOGNIZED IP %lx ARG_CNT %d ENTRY %d", ip, arg_cnt, entry);
		goto out;
	}

	if (entry) {
		handle_func_entry(ctx, cpu, *id_ptr, ip);
	} else {
		u64 res = *(u64 *)(ctx + sizeof(u64) * arg_cnt);

		handle_func_exit(ctx, cpu, *id_ptr, ip, res);
	}
out:
	recur_exit(cpu);
	return 0;
}

#define DEF_PROGS(arg_cnt) \
SEC("fentry/__x64_sys_read") \
int fentry ## arg_cnt(void *ctx) \
{ \
	return handle(ctx, arg_cnt, true); \
} \
SEC("fexit/__x64_sys_read") \
int fexit ## arg_cnt(void *ctx) \
{ \
	return handle(ctx, arg_cnt, false); \
}

DEF_PROGS(0)
DEF_PROGS(1)
DEF_PROGS(2)
DEF_PROGS(3)
DEF_PROGS(4)
DEF_PROGS(5)
DEF_PROGS(6)
DEF_PROGS(7)
DEF_PROGS(8)
DEF_PROGS(9)
DEF_PROGS(10)
DEF_PROGS(11)

/* =========== END OF MASS ATTACHER INFRA ================== */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 1024 * 1024);
} rb SEC(".maps");

const volatile bool verbose = false;;

char func_names[MAX_FUNC_CNT][64] = {};
long func_ips[MAX_FUNC_CNT] = {};
int func_flags[MAX_FUNC_CNT] = {};

struct call_stack stacks[MAX_CPU_CNT] = {};
long scratch[MAX_CPU_CNT] = {};

static void save_stitch_stack(struct call_stack *stack)
{
	if (verbose) {
		bpf_printk("CURRENT DEPTH %d..%d", stack->depth, stack->max_depth);
		bpf_printk("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);
	}

	if (!stack->saved_depth || stack->max_depth + 1 != stack->saved_depth) {
		bpf_probe_read(stack->saved_ids, sizeof(stack->saved_ids), stack->func_ids);
		bpf_probe_read(stack->saved_res, sizeof(stack->saved_res), stack->func_res);
		bpf_probe_read(stack->saved_lat, sizeof(stack->saved_lat), stack->func_lat);
		stack->saved_depth = stack->depth + 1;
		stack->saved_max_depth = stack->max_depth;
		if (verbose)
			bpf_printk("RESETTING SAVED ERR STACK\n");
	} else {
		bpf_probe_read(stack->saved_ids, sizeof(stack->saved_ids), stack->func_ids);
		bpf_probe_read(stack->saved_res, sizeof(stack->saved_res), stack->func_res);
		bpf_probe_read(stack->saved_lat, sizeof(stack->saved_lat), stack->func_lat);
		stack->saved_depth = stack->depth + 1;
		stack->saved_max_depth = stack->max_depth;
		if (verbose)
			bpf_printk("NEED TO APPEND BUT RESETTING SAVED ERR STACK\n");
	}
	/* we are partially overriding previous stack, so emit error
	 * stack, if present
	 */
	//bpf_printk("CPU %d EMITTING ERROR STACK (DEPTH %d MAX DEPTH %d)!!!", cpu, stack->depth, stack->max_depth);
	//bpf_ringbuf_output(&rb, stack, sizeof(*stack), 0);
}

static bool push_call_stack(u32 cpu, u32 id, u64 ip)
{
	struct call_stack *stack = &stacks[cpu & MAX_CPU_MASK];
	u32 d = stack->depth;

	if (d == 0 && !(func_flags[id & MAX_FUNC_MASK] & FUNC_IS_ENTRY))
		return false;

	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (stack->depth != stack->max_depth && stack->is_err)
		save_stitch_stack(stack);

	/*
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;
	*/

	stack->func_ids[d] = id;
	stack->is_err = false;
	stack->depth = d + 1;
	stack->max_depth = d + 1;
	stack->func_lat[d] = bpf_ktime_get_ns();

	if (verbose) {
		bpf_printk("PUSH(1) cpu %d depth %d name %s", cpu, d + 1, func_names[id & MAX_FUNC_MASK]);
		bpf_printk("PUSH(2) id %d addr %lx name %s", id, ip, func_names[id & MAX_FUNC_MASK]);
	}

	return true;
}


static __always_inline bool pop_call_stack(void *ctx, u32 cpu, u32 id, u64 ip, long res, bool is_err)
{
	struct call_stack *stack = &stacks[cpu & MAX_CPU_MASK];
	u64 d = stack->depth;
	u32 actual_id;
	u64 actual_ip;

	if (d == 0)
		return false;
 
	d -= 1;

	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (verbose) {
		bpf_printk("POP(0) CPU %d DEPTH %d MAX DEPTH %d", cpu, stack->depth, stack->max_depth);
		bpf_printk("POP(1) GOT ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
		if (is_err)
			bpf_printk("POP(2) GOT ERROR RESULT %ld", res);
		else
			bpf_printk("POP(2) GOT SUCCESS RESULT %ld", res);
	}

	actual_id = stack->func_ids[d];
	if (actual_id != id) {
		if (actual_id < MAX_FUNC_CNT)
			actual_ip = func_ips[actual_id];
		else
			actual_ip = 0;

		if (verbose) {
			bpf_printk("POP(0) UNEXPECTED CPU %d DEPTH %d MAX DEPTH %d", cpu, stack->depth, stack->max_depth);
			bpf_printk("POP(1) UNEXPECTEC GOT ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
			bpf_printk("POP(2) UNEXPECTED. WANTED ID %u ADDR %lx NAME %s",
				   actual_id, actual_ip, func_names[actual_id & MAX_FUNC_MASK]);
		}

		stack->depth = 0;
		stack->max_depth = 0;
		stack->is_err = false;
		stack->kstack_sz = 0;
		return false;
	}

	stack->func_res[d] = res;
	stack->func_lat[d] = bpf_ktime_get_ns() - stack->func_lat[d];

	if (is_err && !stack->is_err) {
		stack->is_err = true;
		stack->max_depth = d + 1;

		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
	}
	stack->depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		if (stack->is_err) {
			if (verbose)
				bpf_printk("CPU %d EMITTING DEPTH 0 ERROR STACK MAX DEPTH %d\n", cpu, stack->max_depth);
			bpf_ringbuf_output(&rb, stack, sizeof(*stack), 0);
		} else {
			if (verbose)
				bpf_printk("CPU %d EMITTING DEPTH 0 SUCCESS STACK MAX DEPTH %d\n", cpu, stack->max_depth);
			bpf_ringbuf_output(&rb, stack, sizeof(*stack), 0);
		}
		stack->is_err = false;
		stack->saved_depth = 0;
		stack->saved_max_depth = 0;
		stack->depth = 0;
		stack->max_depth = 0;
		stack->kstack_sz = 0;
	}

	return true;
}

int handle_func_entry(void *ctx, u32 cpu, u32 func_id, u64 func_ip)
{
	push_call_stack(cpu, func_id, func_ip);
	return 0;
}

#define MAX_ERRNO 4095

static __always_inline bool IS_ERR_VALUE(long x)
{
	return (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO;
}

static __always_inline bool IS_ERR_VALUE32(u64 x)
{
	/* Due to BPF verifier limitations, it's really hard to do int to long
	 * sign extension generically, because some return types might be
	 * pointers and BPF verifier really hates us for treating pointer as
	 * integer and doing arbitrary (bit shifts) arithmetics on it.  So
	 * instead we just assume we have a 32-bit signed integer and check
	 * manually that it's value unsigned value lies in [-4095, 1] range.
	 * -1 is 0xffffffff, -4095 is 0xfffff001. Easy.
	 */
	if (x < 0xfffff001)
		return false;
	/* prevent clever Clang optimizaations involving math */
	barrier_var(x);
	if ( x > 0xffffffff)
		return false;
	return true;
}

int handle_func_exit(void *ctx, u32 cpu, u32 func_id, u64 func_ip, u64 ret)
{
	int flags;
	bool failed = false;

	flags = func_flags[func_id & MAX_FUNC_MASK];
	if (flags & FUNC_CANT_FAIL)
		goto pop;

	if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32(ret);
	else
		failed = IS_ERR_VALUE(ret);

	/* consider NULL pointer an error */
	if ((flags & FUNC_RET_PTR) && ret == 0)
		failed = true;

pop:
	pop_call_stack(ctx, cpu, func_id, func_ip, ret, failed);
	return 0;
}
