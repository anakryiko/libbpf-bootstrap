// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "minimal.h"

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, unsigned);
} ip_to_idx SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 1024 * 1024);
} rb SEC(".maps");

int running[MAX_CPU_CNT] = {};
long scratch[MAX_CPU_CNT] = {};
int my_pid = 0;
bool ready = false;

long calls_traced = 0;
char func_names[MAX_FUNC_CNT][64] = {};
long func_ips[MAX_FUNC_CNT] = {};
int func_flags[MAX_FUNC_CNT] = {};
long func_call_cnts[MAX_FUNC_CNT] = {};

struct call_stack stacks[MAX_CPU_CNT] = {};

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

static __always_inline void dump_stack(const long *bp, int before, int after)
{
	int i = 0;
	long val;

	for (i = after; i >= before; i--) {
		bpf_probe_read_kernel(&val, sizeof(val), bp + i);
		bpf_printk("0x%lx %d: %lx", (long)bp, i * 8, val);
	}
}

static __always_inline void dump_kprobe(struct pt_regs *regs)
{
	long tmp;

	bpf_printk("hrtimer_start_range_ns() ADDR: %lx", 0xffffffff81133ac0);
	bpf_printk("IP: %lx, FP: %lx, SP: %lx", PT_REGS_IP(regs), PT_REGS_FP(regs), PT_REGS_SP(regs));
	bpf_printk("STACK AT RBP");
	dump_stack((void *)PT_REGS_FP(regs), 0, 16);
	bpf_printk("STACK AT RSP");
	dump_stack((void *)PT_REGS_SP(regs), 0, 16);

	/*
	bpf_probe_read(&tmp, 8, (void *)PT_REGS_FP(regs));
	dump_stack((void *)tmp, 0, 16);
	*/
}

static __always_inline void dump_ftrace(void *ctx)
{
	bpf_printk("hrtimer_start_range_ns() ADDR: %lx", 0xffffffff81133ac0);
	bpf_printk("__x64_sys_write() ADDR: %lx", 0xffffffff812b01e0);
	bpf_printk("CTX: %lx", (long)ctx);
	dump_stack(ctx, 0, 16);
}

static __always_inline long get_ftrace_caller_ip(void *ctx, int arg_cnt)
{
	long ip;
	long off = 1 /* skip orig rbp */ + 1 /* skip reserved space for ret value */;

	if (arg_cnt <= 6)
		off += arg_cnt;
	else
		off += 6;
	off = (long)ctx + off * 8;

	if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off)) {
		bpf_printk("FAILED TO GET CALLER IP AT %lx", off);
		return 0;
	}

	ip -= 5; /* compensate for 5-byte fentry stub */
	return ip;
}

/*
SEC("kprobe/hrtimer_start_range_ns")
int kprobe(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("\n======================\n");
	bpf_printk("KPROBE");
	dump_kprobe(ctx);

	return 0;
}

SEC("kretprobe/hrtimer_start_range_ns")
int kretprobe(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("KRETPROBE");
	dump_kprobe(ctx);

	return 0;
}
*/

static bool push_call_stack(u32 cpu, u32 id, u64 ip)
{
	struct call_stack *stack = &stacks[cpu & MAX_CPU_MASK];
	u32 d = stack->depth;

	if (d == 0 && !(func_flags[id & MAX_FUNC_MASK] & FUNC_IS_ENTRY))
		return false;

	if (d >= MAX_STACK_DEPTH)
		return false;

	if (stack->depth != stack->max_depth && stack->is_err) {
		bpf_printk("CURRENT DEPTH %d..%d", stack->depth, stack->max_depth);
		bpf_printk("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);

		if (!stack->saved_depth || stack->max_depth + 1 != stack->saved_depth) {
			bpf_probe_read(stack->saved_ids, sizeof(stack->saved_ids), stack->func_ids);
			bpf_probe_read(stack->saved_res, sizeof(stack->saved_res), stack->func_res);
			stack->saved_depth = stack->depth + 1;
			stack->saved_max_depth = stack->max_depth;
			bpf_printk("RESETTING SAVED ERR STACK\n");
		} else {
			bpf_probe_read(stack->saved_ids, sizeof(stack->saved_ids), stack->func_ids);
			bpf_probe_read(stack->saved_res, sizeof(stack->saved_res), stack->func_res);
			stack->saved_depth = stack->depth + 1;
			stack->saved_max_depth = stack->max_depth;
			bpf_printk("NEED TO APPEND BUT RESETTING SAVED ERR STACK\n");
		}
		/* we are partially overriding previous stack, so emit error
		 * stack, if present
		 */
		//bpf_printk("CPU %d EMITTING ERROR STACK (DEPTH %d MAX DEPTH %d)!!!", cpu, stack->depth, stack->max_depth);
		//bpf_ringbuf_output(&rb, stack, sizeof(*stack), 0);
	}

	stack->func_ids[d] = id;
	stack->is_err = false;
	stack->depth = d + 1;
	stack->max_depth = d + 1;

	bpf_printk("PUSH(1) cpu %d depth %d name %s", cpu, d + 1, func_names[id & MAX_FUNC_MASK]);
	//bpf_printk("PUSH(2) id %d addr %lx name %s", id, ip, func_names[id & MAX_FUNC_MASK]);

	return true;
}

#define MAX_ERRNO 4095
static __always_inline bool IS_ERR_VALUE(long x)
{
	return (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO;
}

static bool pop_call_stack(u32 cpu, u32 id, u64 ip, long res, bool is_err)
{
	struct call_stack *stack = &stacks[cpu & MAX_CPU_MASK];
	u64 d = stack->depth;
	u32 actual_id;
	u64 actual_ip;

	if (d == 0)
		return false;
 
	d -= 1;
	if (d >= MAX_STACK_DEPTH)
		return false;

	bpf_printk("POP(0) CPU %d DEPTH %d MAX DEPTH %d", cpu, stack->depth, stack->max_depth);
	bpf_printk("POP(1) GOT ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
	if (is_err)
		bpf_printk("POP(2) GOT ERROR RESULT %ld", res);
	else
		bpf_printk("POP(2) GOT SUCCESS RESULT %ld", res);

	actual_id = stack->func_ids[d];
	if (actual_id != id) {
		if (actual_id < MAX_FUNC_CNT)
			actual_ip = func_ips[actual_id];
		else
			actual_ip = 0;

		bpf_printk("POP(0) UNEXPECTED CPU %d DEPTH %d MAX DEPTH %d", cpu, stack->depth, stack->max_depth);
		bpf_printk("POP(1) UNEXPECTEC GOT ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
		bpf_printk("POP(2) UNEXPECTED. WANTED ID %u ADDR %lx NAME %s",
			   actual_id, actual_ip, func_names[actual_id & MAX_FUNC_MASK]);

		stack->depth = 0;
		stack->max_depth = 0;
		stack->is_err = false;
		return false;
	}

	stack->func_res[d] = res;

	if (is_err && !stack->is_err) {
		stack->is_err = true;
		stack->max_depth = d + 1;
	}
	stack->depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		if (stack->is_err) {
			bpf_printk("CPU %d EMITTING DEPTH 0 ERROR STACK MAX DEPTH %d\n", cpu, stack->max_depth);
			bpf_ringbuf_output(&rb, stack, sizeof(*stack), 0);
		} else {
			bpf_printk("CPU %d EMITTING DEPTH 0 SUCCESS STACK MAX DEPTH %d\n", cpu, stack->max_depth);
			bpf_ringbuf_output(&rb, stack, sizeof(*stack), 0);
		}
		stack->is_err = false;
		stack->saved_depth = 0;
		stack->saved_max_depth = 0;
		stack->depth = 0;
		stack->max_depth = 0;
	}

	return true;
}

/* we need arg_cnt * sizeof(__u64) to be a constant, so need to inline */
static __always_inline int handle(void *ctx, int arg_cnt, bool entry)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	unsigned cpu = bpf_get_smp_processor_id();
	const char *name;
	unsigned id, *idx;
	long ip;

	if (!ready)
		return 0;
	if (my_pid && pid != my_pid)
		return 0;
	if (!recur_enter(cpu))
		return 0;

	__sync_fetch_and_add(&calls_traced, 1);

	ip = get_ftrace_caller_ip(ctx, arg_cnt);
	idx = bpf_map_lookup_elem(&ip_to_idx, &ip);
	if (!idx) {
		bpf_printk("UNRECOGNIZED IP %lx", ip);
		goto out;
	}

	id = *idx;
	if (id >= MAX_FUNC_CNT) {
		bpf_printk("INVALID IDX %d FOR IP %lx", id, ip);
		goto out;
	}

	if (entry)
		__sync_fetch_and_add(&func_call_cnts[id], 1);

	/*
	if (entry)
		bpf_printk("FENTRY CALLER %lx -> %s", ip, name);
	else
		bpf_printk("FEXIT CALLER %lx -> %s", ip, name);
	dump_ftrace(ctx);
	*/
	

	if (entry) {
		push_call_stack(cpu, id, ip);
	} else {
		u64 res = *(u64 *)(ctx + sizeof(u64) * arg_cnt);
		int flags = func_flags[id & MAX_FUNC_MASK];
		bool is_err = false;

		barrier_var(res);

		if (flags & FUNC_CANT_FAIL) {
			is_err = false;
		} else {
			if (flags & FUNC_NEEDS_SIGN_EXT) {
				barrier_var(res);
				scratch[cpu & MAX_CPU_MASK] = res;
				barrier_var(res);
				res = (u64)(s64)(s32)scratch[cpu & MAX_CPU_MASK];
				barrier_var(res);
			}
			is_err = (flags & FUNC_RET_PTR)
			       ? (res == 0 || IS_ERR_VALUE(res))
			       : IS_ERR_VALUE(res);
		}

		pop_call_stack(cpu, id, ip, res, is_err);
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

/*
SEC("fentry/__x64_sys_clone")
int BPF_PROG(handle_clone)
{
	__sync_fetch_and_add(&calls_traced, 1);
	bpf_printk("CLONE CALLED!!!\n");
	return 0;
}

SEC("fentry/__x64_sys_execve")
int BPF_PROG(handle_execve)
{
	__sync_fetch_and_add(&calls_traced, 1);
	bpf_printk("EXECVE CALLED!!!\n");
	return 0;
}
*/
