// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__uint(value_size, 4);
	__uint(max_entries, 1024);
} my_map SEC(".maps");
*/

/*
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 3000);
} my_rb SEC(".maps");
*/

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name/*, int bla*/)
{
	const char *filename = name->name;
	pid_t pid;

	pid = bpf_get_current_pid_tgid();

	bpf_printk("fentry: pid = %d, filename = %s\n", pid, filename);

	/*
	bpf_printk("bla is %d", bla);
	*/
	
	/*
	bpf_ringbuf_output(&my_rb, &pid, 4, 0);
	*/

	/*
	bpf_map_update_elem(&my_map, &pid, &pid, 0);
	*/

	return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid();

	bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
	return 0;
}

