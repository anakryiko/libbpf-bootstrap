/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __WPROF_H_
#define __WPROF_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef WORKER_DESC_LEN
#define WORKER_DESC_LEN 32
#endif

#define TASK_COMM_FULL_LEN (2 * TASK_COMM_LEN + 4)

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

#ifndef PF_WQ_WORKER
#define PF_WQ_WORKER 0x00000020
#endif
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

struct wprof_stats {
	__u64 rb_drops;
	__u64 task_state_drops;
};

enum task_status {
	STATUS_UNKNOWN,
	STATUS_ON_CPU,
	STATUS_OFF_CPU,
	STATUS_IRQ,
};

enum event_kind {
	EV_ON_CPU,
	EV_OFF_CPU,
	EV_TIMER,
	EV_SWITCH,
	EV_WAKEUP_NEW,
	EV_WAKEUP,
	EV_WAKING,
	EV_EXIT,
	EV_HARDIRQ_ENTER,
	EV_HARDIRQ_EXIT,
	EV_SOFTIRQ_ENTER,
	EV_SOFTIRQ_EXIT,
	EV_WQ_START,
	EV_WQ_END,
};

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct wprof_task {
	__u32 tid;
	__u32 pid;
	__u32 flags;
	char comm[TASK_COMM_FULL_LEN];
	char pcomm[TASK_COMM_LEN];
};

struct wprof_event {
	enum event_kind kind;
	__u32 cpu_id;
	__u64 ts;
	__u64 dur_ns;
	struct wprof_task task;

	union {
		struct wprof_switch {
			struct wprof_task prev;
			__u64 waking_ts;
			__u32 waking_cpu;
		} swtch;
		struct wprof_timer {
		} timer;
		struct wprof_hardirq {
			int irq;
			char name[WORKER_DESC_LEN - 4];
		} hardirq;
		struct wprof_softirq {
			int vec_nr;
		} softirq;
		struct wprof_wq_info {
			char desc[WORKER_DESC_LEN];
		} wq;
	};

	/*
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
	*/
};

#endif /* __WPROF_H_ */
