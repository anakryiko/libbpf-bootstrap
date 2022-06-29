// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bootstrap.h"

extern int bpf_dynptr_from_skb(struct sk_buff *skb, __u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym __weak;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
                                   void *buffer, uint32_t buffer__sz) __ksym __weak;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 4096);
} sockmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, __u64);
	__type(value, int);
	__uint(max_entries, 4096);
} sockhash SEC(".maps");

struct pos {
	__u64 next_pos;
	__u64 cnt;
	__u64 total;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct pos);
	__uint(max_entries, 4096);
} posmap SEC(".maps");

int port;
bool verbose;
bool transparent;
int coalesce_len;
int conn_cnt;

SEC("sk_skb/stream_parser")
int skb_parser(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	struct pos *p = bpf_map_lookup_elem(&posmap, &cookie);
	struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
	union {
		struct {
			char zero;
			char len[3];
		};
		__u32 frlen;
	} frame_buf = {};
	int cnt, len, off, err;
	__u8 *data, *data_end;
	struct bpf_dynptr skbp __attribute__((aligned(8)));

	if (!p) {
		bpf_printk("PARSER FAIL cookie=%d remote_port=%d",
			cookie, bpf_ntohl(skb->remote_port));
		return 0;
	}

	if (verbose && p->cnt < 10) {
		bpf_printk("PARSER STRP STATE full_len %d offset %d accum_len %d",
			   BPF_CORE_READ(skb_cb, strp.strp.full_len),
			   BPF_CORE_READ(skb_cb, strp.strp.offset),
			   BPF_CORE_READ(skb_cb, strp.accum_len));
	}

	/*
	err = bpf_dynptr_from_skb((void*)skb, 0, &skbp);
	if (err) {
		bpf_printk("FAILED TO CREATE DYNPTR: %d", err);
		return SK_DROP;
	}

	off = BPF_CORE_READ(skb_cb, strp.strp.offset);
	data = bpf_dynptr_slice(&skbp, off, &frame_buf.len, 3);
	if (!data) {
		bpf_printk("SLICE FAIL %d+3", off);
		return 0;
	}

	len = ((__u32)data[0] << 16) + ((__u32)data[1] << 8) + data[2];
	if (verbose && p->cnt < 10) {
		bpf_printk("DYNPTR FRAME LEN %d(+3 = %d) (off %d)",
			len, len+3, off);
	}
	len += 3;
	*/

	off = BPF_CORE_READ(skb_cb, strp.strp.offset);
	if (bpf_skb_load_bytes(skb, off, &frame_buf.len, 3)) {
		if (p->cnt < 10) {
			bpf_printk("FAILED TO LOAD BYTES AT %d+3 skb_len %d",
				off, skb->len);
		}
		return 0;
	}

	len = bpf_ntohl(frame_buf.frlen);
	if (verbose && p->cnt < 10) {
		bpf_printk("FRAME LEN %d(+3 = %d) (off %d)",
			len, len+3, off);
	}
	len += 3;

	if (verbose && p->cnt < 10) {
		bpf_printk("PARSER PASS total=%lu skb_len=%d off=%d len=%d",
			   p->total, skb->len, off, len);
	}
	p->cnt += 1;
	return len;
}

SEC("sk_skb/stream_verdict")
int skb_verdict(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	struct pos *p = bpf_map_lookup_elem(&posmap, &cookie);
	struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
	int full_len;
	
	if (!p) {
		bpf_printk("VERDICT FAIL cookie=%d remote_port=%d",
			cookie, bpf_ntohl(skb->remote_port));
		return 0;
	}

	full_len = BPF_CORE_READ(skb_cb, strp.strp.full_len),
	p->total += full_len;

	if (verbose && p->cnt < 10) {

		bpf_printk("VERDICT STRP STATE full_len %d offset %d accum_len %d",
			   BPF_CORE_READ(skb_cb, strp.strp.full_len),
			   BPF_CORE_READ(skb_cb, strp.strp.offset),
			   BPF_CORE_READ(skb_cb, strp.accum_len));
	}

	if (verbose && p->cnt < 10) {
		bpf_printk("VERDICT PASS sock_cookie=%d local_port=%d remote_port=%d skb_len=%d total=%lu",
			   cookie, skb->local_port, bpf_ntohl(skb->remote_port), skb->len,
			   p->total);
	}
	return SK_PASS;
}


SEC("sockops")
int sock_ops(struct bpf_sock_ops *ctx)
{
	int cur_pid = 0; //bpf_get_current_pid_tgid() >> 32;
	int op = (int)ctx->op;
	int local_port = ctx->local_port;
	int remote_port = bpf_ntohl(ctx->remote_port);

	if (local_port != port && remote_port != port)
		return 0;

	switch (op) {
	default:
	case BPF_SOCK_OPS_TIMEOUT_INIT:
	case BPF_SOCK_OPS_RWND_INIT:
	case BPF_SOCK_OPS_NEEDS_ECN:
	case BPF_SOCK_OPS_BASE_RTT:
	case BPF_SOCK_OPS_RTO_CB:
	case BPF_SOCK_OPS_RETRANS_CB:
		break;

	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		bpf_printk("SOCKOP pid=%d TCP_LISTEN local %d remote %d",
			cur_pid, local_port, remote_port);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_printk("SOCKOP pid=%d PASSIVE_ESTABLISHED local %d remote %d",
			cur_pid, local_port, remote_port);
		break;
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		bpf_printk("SOCKOP pid=%d TCP_CONNECT local %d remote %d",
			cur_pid, local_port, remote_port);
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_printk("SOCKOP pid=%d ACTIVE_ESTABLISHED local %d remote %d",
			cur_pid, local_port, remote_port);
		break;
	}

	if (local_port == port && op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		__u64 sock_cookie = bpf_get_socket_cookie(ctx);
		struct pos p = { .next_pos = 0 };
		int err;

		err = bpf_map_update_elem(&posmap, &sock_cookie, &p, BPF_NOEXIST);
		if (err) {
			bpf_printk("POS ADD failed remote_port=%d err=%d conn_cnt=%d", remote_port, err, conn_cnt);
			return 0;
		}

		err = bpf_sock_hash_update(ctx, &sockhash, &sock_cookie, BPF_NOEXIST);
		if (err) {
			bpf_printk("SOCK ADD failed remote_port=%d err=%d conn_cnt=%d", remote_port, err);
			return 0;
		}

		int cnt = __sync_add_and_fetch(&conn_cnt, 1);
		bpf_printk("SOCK ADDED sock_cookie=%lu remote_port=%d conn_cnt=%d", sock_cookie, remote_port, cnt);
	}

	return 1;
}
