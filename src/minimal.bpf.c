// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_FUNC_CNT 50000

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, unsigned);
} ip_to_idx SEC(".maps");

int running[256] = {};
int my_pid = 0;

long calls_traced = 0;

char func_names[MAX_FUNC_CNT][64] = {};
long func_call_cnts[MAX_FUNC_CNT] = {};

static __always_inline bool recur_enter(void)
{
	int cpu = bpf_get_smp_processor_id();

	if (running[cpu & 0xff])
		return false;

	running[cpu & 0xff] += 1;

	return true;
}

static __always_inline void recur_exit(void)
{
	running[bpf_get_smp_processor_id() & 0xff] -= 1;
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

static __noinline int handle(void *ctx, int arg_cnt, bool entry)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	const char *name;
	unsigned id, *idx;
	long ip;

	if (my_pid && pid != my_pid)
		return 0;
	if (!recur_enter())
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
	*/
	//dump_ftrace(ctx);

out:
	recur_exit();
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
