// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include ".output/bpftool/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static struct __sk_buff *(*bpf_skb_clone)(struct __sk_buff *skb) = (void *) 208;
static void (*bpf_skb_free)(struct __sk_buff *skb) = (void *) 209;

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 128);
} sockmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct sk_buff *);
	__uint(max_entries, 128);
} offloads SEC(".maps");

struct my_msg {
	int total_len;
	int payload_len;
	int offload_len;
	int offload_id;
	int offload_start_off;
	int offload_end_off;
};

static int parser_drop_len = 0;
static int verdict_drop_len = 0;
static int verdict_good_len = 0;

static __u64 next_off_id = 1;

static int cur_off_id;

SEC("sk_skb/stream_parser")
int skb_parser(struct __sk_buff *skb)
{
	struct my_msg msg;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	int err, good_len;
	struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
	int strp_off, accum_len;

	if (parser_drop_len) {
		bpf_printk("PARSER DROP len %d (skb_len %d)", parser_drop_len, skb->len);
		verdict_drop_len = parser_drop_len;
		parser_drop_len = 0;
		return verdict_drop_len;
	}

	bpf_printk("PARSER STRP STATE full_len %d offset %d accum_len %d",
		   BPF_CORE_READ(skb_cb, strp.strp.full_len),
		   BPF_CORE_READ(skb_cb, strp.strp.offset),
		   BPF_CORE_READ(skb_cb, strp.accum_len));

	strp_off = BPF_CORE_READ(skb_cb, strp.strp.offset);
	accum_len = BPF_CORE_READ(skb_cb, strp.accum_len);

	err = bpf_skb_load_bytes(skb, strp_off, &msg, sizeof(msg));
	if (err) {
		bpf_printk("PARSER LOAD BYTES ERR %d", err);
		return err;
	}

	bpf_printk("PARSER NEW MSG total %d pay_len %d off_len %d",
		   msg.total_len, msg.payload_len, msg.offload_len);

	parser_drop_len = msg.offload_len;
	good_len = msg.total_len - msg.offload_len;
	verdict_good_len = good_len;

	cur_off_id = msg.offload_id = __sync_fetch_and_add(&next_off_id, 1);
	msg.offload_start_off = strp_off + good_len;
	msg.offload_end_off = strp_off + good_len + msg.offload_len;
	bpf_printk("NEW OFFLOAD id %d [%d, %d)",
		   msg.offload_id, msg.offload_start_off, msg.offload_end_off);

	err = bpf_skb_store_bytes(skb,
				  strp_off + offsetof(struct my_msg, offload_id),
				  &msg.offload_id,
				  3 * sizeof(int), 0);
	if (err) {
		bpf_printk("PARSER STORE BYTES ERR %d", err);
		return err;
	}

	bpf_printk("PARSER PASS len %d (skb_len %d)", good_len, skb->len);
	return good_len;
}

SEC("sk_skb/stream_verdict")
int skb_verdict(struct __sk_buff *skb)
{
	struct my_msg msg;
	struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
	int strp_off, err;

	bpf_printk("VERDICT STRP STATE full_len %d offset %d accum_len %d",
		   BPF_CORE_READ(skb_cb, strp.strp.full_len),
		   BPF_CORE_READ(skb_cb, strp.strp.offset),
		   BPF_CORE_READ(skb_cb, strp.accum_len));

	if (verdict_drop_len) {
		struct sk_buff *offload_skb;

		offload_skb = (void *)bpf_skb_clone(skb);
		if (!offload_skb) {
			bpf_printk("VERDICT ERROR CLONING SKB! \n");
		} else {
			struct sk_skb_cb *off_skb_cb = (void *)&offload_skb->cb;

			bpf_printk("VERDICT CLONED SKB %lx", offload_skb);

			bpf_printk("VERDICT OFFLOAD STRP STATE full_len %d offset %d accum_len %d",
				   BPF_CORE_READ(off_skb_cb, strp.strp.full_len),
				   BPF_CORE_READ(off_skb_cb, strp.strp.offset),
				   BPF_CORE_READ(off_skb_cb, strp.accum_len));
		}

		err = bpf_map_update_elem(&offloads, &cur_off_id, &offload_skb, BPF_NOEXIST);
		if (err) {
			bpf_printk("PARSER STORE OFFLOAD ERR %d", err);
			return err;
		}

		bpf_printk("VERDICT DROP len %d (skb_len %d)", verdict_drop_len, skb->len);
		verdict_drop_len = 0;
		return SK_DROP;
	}

	strp_off = BPF_CORE_READ(skb_cb, strp.strp.offset),
	err = bpf_skb_load_bytes(skb, strp_off, &msg, sizeof(msg));
	if (err) {
		bpf_printk("PARSER LOAD BYTES ERR %d", err);
		return err;
	}

	bpf_printk("VERDICT OFFLOAD id %d [%d, %d)",
		   msg.offload_id, msg.offload_start_off, msg.offload_end_off);

	bpf_printk("VERDICT PASS len %d (skb_len %d)", verdict_good_len, skb->len);
	return SK_PASS;
}

int off_req_id, off_req_start_off, off_req_end_off;
int off_res_len;
char off_res_data[256];

SEC("raw_tp")
int skb_get_offload(void *ctx)
{
	struct sk_buff *skb, **skb_p;
	int err;
	u64 len = off_req_end_off - off_req_start_off;

	skb_p = bpf_map_lookup_elem(&offloads, &off_req_id);
	if (!skb_p) {
		bpf_printk("GETOFFLOAD LOOKUP ERR id %d", off_req_id);
		return 0;
	}
	skb = *skb_p;

	if (len > sizeof(off_res_data))
		len = sizeof(off_res_data);
	off_res_len = len;

	bpf_printk("GETOFFLOAD id %d start_off %d end_off %d len %d skb %lx",
		   off_req_id, off_req_start_off, off_req_end_off, len, skb);

	err = bpf_skb_load_bytes(skb, off_req_start_off, off_res_data, len);
	if (err)
		bpf_printk("GETOFFLOAD SKB LOAD BYTES ERR %d", err);

	bpf_skb_free((void *)skb);
	bpf_printk("GETOFFLOAD FREED SKB %lx", skb);

	bpf_map_delete_elem(&offloads, &off_req_id);

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

/*

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
*/
