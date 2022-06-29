// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bootstrap.h"

#define VLOG_MAX_CNT 1000000

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

int pid;
static __u64 seq;

#define EV_MSK (((1 << 14) - 1))

enum evtype
{
	EV_INVAL,
	EV_EPOLL_WAIT_RET,
	EV_RECVFROM_RET,
	EV_PARSE,
	EV_VERDICT,
};

struct ev {
	__u64 seq;
	enum evtype t;
	//__u64 ts;
	
	int retval;

	int fr_num;
	int skb_len;
	int fr_len;
	int strp_full_len;
	int strp_off;
	int strp_accum_len;
	int sk_rcvbuf;
	int sk_rmem_alloc;
	int sk_backlog_len;
};

static struct ev evs[EV_MSK + 1];

static struct ev *getev(void)
{
	__u64 sq = __sync_fetch_and_add(&seq, 1);
	struct ev *ev = &evs[sq & EV_MSK];

	ev->t = EV_INVAL;
	ev->seq = sq;
	//ev->ts = bpf_ktime_get_ns();

	return ev;
}

static void dump_state(__u64 seq)
{
	__u64 i;

	for (i = 0; i < 10; i++) {
		__u64 s = (seq - i) & EV_MSK;
		struct ev *ev = &evs[s];

		switch (ev->t) {
		default:
		case EV_INVAL:
			bpf_printk("[%lu] ???", ev->seq);
			break;
		case EV_EPOLL_WAIT_RET:
			bpf_printk("[%lu] EPWAIT_RET retval=%d", ev->seq, ev->retval);
			break;
		case EV_RECVFROM_RET:
			bpf_printk("[%lu] RECVFROM_RET retval=%d", ev->seq, ev->retval);
			break;
		case EV_PARSE:
			bpf_printk("[%lu] PARSE fr#%d fr_len %d skb_len %d sk_rcvbuf %d sk_rmem_alloc %d sk_backlog_len %d strp (full %d, off %d, accum %d)",
				ev->seq, ev->fr_num, ev->fr_len, ev->skb_len,
				ev->sk_rcvbuf, ev->sk_rmem_alloc, ev->sk_backlog_len,
				ev->strp_full_len, ev->strp_off, ev->strp_accum_len);
			break;
		case EV_VERDICT:
			bpf_printk("[%lu] VERDICT fr#%d fr_len %d skb_len %d sk_rcvbuf %d sk_rmem_alloc %d sk_backlog_len %d strp (full %d, off %d, accum %d)",
				ev->seq, ev->fr_num, ev->fr_len, ev->skb_len,
				ev->sk_rcvbuf, ev->sk_rmem_alloc, ev->sk_backlog_len,
				ev->strp_full_len, ev->strp_off, ev->strp_accum_len);
			break;
		}
	}
}

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

	if (transparent)
		return skb->len;

	if (verbose && p->cnt < VLOG_MAX_CNT) {
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
		if (p->cnt < VLOG_MAX_CNT) {
			bpf_printk("FAILED TO LOAD BYTES AT %d+3 skb_len %d",
				off, skb->len);
		}
		return 0;
	}

	len = bpf_ntohl(frame_buf.frlen) + 3;

	if (verbose && p->cnt < VLOG_MAX_CNT) {
		bpf_printk("FRAME skb_len=%d off=%d len=%d more=%d",
			skb->len, off, len, (off + len < skb->len) ? 1 : 0);
	}
	p->cnt += 1;

	struct ev *ev = getev();

	ev->t = EV_PARSE;
	ev->fr_num = p->cnt - 1;
	ev->skb_len = skb->len;
	ev->fr_len = len;
	ev->strp_full_len = BPF_CORE_READ(skb_cb, strp.strp.full_len);
	ev->strp_off = off;
	ev->strp_accum_len = BPF_CORE_READ(skb_cb, strp.accum_len);
	ev->sk_rcvbuf = BPF_CORE_READ((struct sk_buff *)skb, sk, sk_rcvbuf);
	ev->sk_rmem_alloc = BPF_CORE_READ((struct sk_buff *)skb, sk, sk_backlog.rmem_alloc.counter);
	ev->sk_backlog_len = BPF_CORE_READ((struct sk_buff *)skb, sk, sk_backlog.len);

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

	if (verbose && p->cnt < VLOG_MAX_CNT) {

		bpf_printk("VERDICT STRP STATE full_len %d offset %d accum_len %d",
			   BPF_CORE_READ(skb_cb, strp.strp.full_len),
			   BPF_CORE_READ(skb_cb, strp.strp.offset),
			   BPF_CORE_READ(skb_cb, strp.accum_len));
	}

	if (verbose && p->cnt < VLOG_MAX_CNT) {
		bpf_printk("VERDICT PASS sock_cookie=%d local_port=%d remote_port=%d skb_len=%d total=%lu",
			   cookie, skb->local_port, bpf_ntohl(skb->remote_port), skb->len,
			   p->total);
	}

	struct ev *ev = getev();

	ev->t = EV_VERDICT;
	ev->fr_num = p->cnt - 1;
	ev->skb_len = skb->len;
	ev->fr_len = 0;
	ev->strp_full_len = BPF_CORE_READ(skb_cb, strp.strp.full_len);
	ev->strp_off = BPF_CORE_READ(skb_cb, strp.strp.offset);
	ev->strp_accum_len = BPF_CORE_READ(skb_cb, strp.accum_len);
	ev->sk_rcvbuf = BPF_CORE_READ((struct sk_buff *)skb, sk, sk_rcvbuf);
	ev->sk_rmem_alloc = BPF_CORE_READ((struct sk_buff *)skb, sk, sk_backlog.rmem_alloc.counter);
	ev->sk_backlog_len = BPF_CORE_READ((struct sk_buff *)skb, sk, sk_backlog.len);

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
		int sk_rcvbuf = BPF_CORE_READ((struct sk_buff *)ctx, sk, sk_rcvbuf);
		bpf_printk("SOCK ADDED sock_cookie=%lu remote_port=%d sk_rcvbuf=%d conn_cnt=%d",
			sock_cookie, remote_port, sk_rcvbuf, cnt);
	}

	return 1;
}

SEC("fexit/__x64_sys_epoll_wait")
int BPF_PROG(epoll_wait_exit, struct pt_regs *regs, int retval)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct ev *ev;

	if (pid == 0 || pid != cur_pid)
		return 0;

	if (retval <= 0)
		return 0;

	ev = getev();

	ev->t = EV_EPOLL_WAIT_RET;
	ev->retval = retval;

	return 0;
}

SEC("fexit/__x64_sys_recvfrom")
int BPF_PROG(recvfrom_exit, struct pt_regs *regs, int retval)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct ev *ev;

	if (pid == 0 || pid != cur_pid)
		return 0;

	if (retval >= 0)
		return 0;

	ev = getev();

	ev->t = EV_RECVFROM_RET;
	ev->retval = retval;

	dump_state(ev->seq);

	return 0;
}

/*
#define SOL_SOCKET 1
#define SO_RCVLOWAT 18

SEC("cgroup/skb")
int handle_skb(struct __sk_buff *skb)
{
	int err, val;

	if (skb->local_port != port)
		return SK_PASS;

	val = 16 * 1024;
	err = bpf_setsockopt(skb, SOL_SOCKET, SO_RCVLOWAT, &val, sizeof(val));
	if (err)
		bpf_printk("SETSOCKOPT FAILED: %d", err);
	return SK_PASS;
}
*/
