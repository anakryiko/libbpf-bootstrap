// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wprof.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
struct task_state {
	__u64 ts;
	__u64 waking_ts;
	__u32 waking_cpu;
	enum task_status status;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); /* task_id, see task_id() */
	__type(value, struct task_state);
} task_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct wprof_stats);
	__uint(max_entries, 1);
} stats SEC(".maps");

#define inc_stat(stat) ({							\
	struct wprof_stats *s = bpf_map_lookup_elem(&stats, (void *)&zero);	\
	if (s) s->stat++;							\
})

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

const volatile int pid_filter_cnt;
int pids[1] SEC(".data.pids");

const volatile int comm_filter_cnt;
char comms[16][1] SEC(".data.comms");

const volatile bool cpu_filter;
__u64 cpus[512] SEC(".data.cpus"); /* CPU bitmask, up to 4096 CPUs are supported */

__u64 session_start_ts;

const volatile int zero = 0;

static struct task_state empty_task_state;

static __always_inline int task_id(int pid)
{
	/* use CPU ID for identifying idle tasks */
	return pid ?: -(bpf_get_smp_processor_id() + 1);
}

static struct task_state *task_state(int pid)
{
	struct task_state *s;
	int id = task_id(pid);

	s = bpf_map_lookup_elem(&task_states, &id);
	if (!s) {
		bpf_map_update_elem(&task_states, &id, &empty_task_state, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&task_states, &id);
	}
	if (!s)
		inc_stat(task_state_drops);
	return s;
}

/* don't create an entry if it's not there already */
static struct task_state *task_state_peek(int pid)
{
	int id = task_id(pid);

	return bpf_map_lookup_elem(&task_states, &id);
}

static void task_state_delete(int pid)
{
	int id = task_id(pid);

	bpf_map_delete_elem(&task_states, &id);
}

static bool should_trace(struct task_struct *task1, struct task_struct *task2)
{
	if (!session_start_ts) /* we are still starting */
		return false;

	if (cpu_filter) {
		int cpu = bpf_get_smp_processor_id();
		__u64 mask = cpus[(cpu >> 6) & (ARRAY_SIZE(cpus) - 1)];

		if (!(mask & (1ULL << (cpu & 63))))
			return false;
	}

	return true;
}

static void fill_task_name(struct task_struct *t, char *comm, int max_len)
{
	if (t->flags & PF_WQ_WORKER) {
		//struct kthread *k = bpf_core_cast(t->worker_private, struct kthread);
		//struct worker *worker = bpf_core_cast(k->data, struct worker);

		/* TODO: prepend "kworker/..." parts */
		//bpf_probe_read_kernel_str(comm, WORKER_DESC_LEN, worker->desc);
		__builtin_memcpy(comm, t->comm, TASK_COMM_LEN);
	} else if (t->flags & PF_KTHREAD) {
		struct kthread *k = bpf_core_cast(t->worker_private, struct kthread);
		int err = -1;

		if (bpf_core_field_exists(struct kthread, full_name) && k->full_name)
			err = bpf_probe_read_kernel_str(comm, max_len, k->full_name);
		if (err)
			__builtin_memcpy(comm, t->comm, TASK_COMM_LEN);
	} else {
		__builtin_memcpy(comm, t->comm, TASK_COMM_LEN);
	}
}

static void fill_task_info(struct task_struct *t, struct wprof_task *info)
{
	info->tid = t->pid;
	if (info->tid == 0) /* idle thread */
		info->tid = -bpf_get_smp_processor_id();
	info->pid = t->tgid;
	info->flags = t->flags;
	fill_task_name(t, info->comm, sizeof(info->comm));
	__builtin_memcpy(info->pcomm, t->group_leader->comm, sizeof(info->pcomm));
}

static struct wprof_event *prep_task_event(enum event_kind kind, u64 now_ts, struct task_struct *p)
{
	struct wprof_event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		inc_stat(rb_drops);
		return NULL;
	}

	e->kind = kind;
	e->ts = now_ts;
	e->cpu_id = bpf_get_smp_processor_id();
	fill_task_info(p, &e->task);

	/*
	e->kstack_sz = 0;
	e->ustack_sz = 0;

	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz =
		bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
	*/

	return e;
}

static void submit_event(struct wprof_event *e)
{
	bpf_ringbuf_submit(e, 0);
}

SEC("perf_event")
int wprof_timer_tick(void *ctx)
{
	struct task_state *scur;
	struct task_struct *cur = bpf_get_current_task_btf();
	struct wprof_event *e;
	u64 now_ts, dur_ns;

	if (!should_trace(cur, NULL))
		return false;

	scur = task_state(cur->pid);
	if (!scur)
		return 0; /* shouldn't happen, unless we ran out of space */

	now_ts = bpf_ktime_get_ns();

	/* cur task was on-cpu since last checkpoint */
	dur_ns = now_ts - (scur->ts ?: session_start_ts);

	scur->ts = now_ts;
	if (scur->status == STATUS_UNKNOWN)
		/* we don't know if we are in IRQ or not, but presume not */
		scur->status = STATUS_ON_CPU;

	if ((e = prep_task_event(EV_TIMER, now_ts, cur))) {
		e->dur_ns = dur_ns;
		submit_event(e);
	}

out:
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(wprof_task_switch,
	     bool preempt,
	     struct task_struct *prev,
	     struct task_struct *next,
	     unsigned prev_state)
{
	struct task_state *sprev, *snext;
	struct wprof_event *e;
	u64 now_ts, prev_dur_ns, next_dur_ns, waking_ts;
	u32 waking_cpu;

	if (!should_trace(prev, next))
		return 0;

	sprev = task_state(prev->pid);
	snext = task_state(next->pid);
	if (!sprev || !snext)
		return 0;

	now_ts = bpf_ktime_get_ns();

	waking_ts = snext->waking_ts;

	/* prev task was on-cpu since last checkpoint */
	prev_dur_ns = now_ts - (sprev->ts ?: session_start_ts);
	sprev->ts = now_ts;
	sprev->waking_ts = 0;

	/* next task was off-cpu since last checkpoint */
	next_dur_ns = now_ts - (snext->ts ?: session_start_ts);
	snext->ts = now_ts;
	snext->waking_ts = 0;

	if ((e = prep_task_event(EV_ON_CPU, now_ts, prev))) {
		e->dur_ns = prev_dur_ns;
		submit_event(e);
	}

	if ((e = prep_task_event(EV_OFF_CPU, now_ts, next))) {
		e->dur_ns = next_dur_ns;
		submit_event(e);
	}

	if ((e = prep_task_event(EV_SWITCH, now_ts, next))) {
		fill_task_info(prev, &e->swtch.prev);
		e->swtch.waking_ts = waking_ts;
		e->swtch.waking_cpu = snext->waking_cpu;
		submit_event(e);
	}

	return 0;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(wprof_task_waking, struct task_struct *p)
{
	struct wprof_event *e;
	struct task_state *s;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	s = task_state(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	s->waking_ts = now_ts;
	s->waking_cpu = bpf_get_smp_processor_id();

	if ((e = prep_task_event(EV_WAKING, now_ts, p))) {
		submit_event(e);
	}

	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(wprof_task_wakeup_new, struct task_struct *p)
{
	struct task_state *s;
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	s = task_state(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	s->ts = now_ts;
	if (s->waking_ts == 0) {
		s->waking_ts = now_ts;
		s->waking_cpu = bpf_get_smp_processor_id();
	}
	s->status = STATUS_OFF_CPU;

	if ((e = prep_task_event(EV_WAKEUP_NEW, now_ts, p))) {
		submit_event(e);
	}

	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(wprof_task_wakeup, struct task_struct *p)
{
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	now_ts = bpf_ktime_get_ns();
	if ((e = prep_task_event(EV_WAKEUP, now_ts, p))) {
		submit_event(e);
	}

	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(wprof_task_exit, struct task_struct *p)
{
	struct task_state *s;
	struct wprof_event *e;
	enum event_kind kind;
	u64 now_ts;
	int id;

	if (!should_trace(p, NULL))
		return 0;

	s = task_state_peek(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	kind = s->status == STATUS_ON_CPU ? EV_ON_CPU : EV_OFF_CPU;
	
	task_state_delete(p->pid);

	if ((e = prep_task_event(kind, now_ts, p))) {
		e->dur_ns = now_ts - s->ts;
		submit_event(e);
	}

	if ((e = prep_task_event(EV_EXIT, now_ts, p))) {
		submit_event(e);
	}

	return 0;
}

static int handle_hardirq(struct task_struct *task, struct irqaction *action, int irq, bool start)
{
	struct wprof_event *e;
	u64 now_ts;
	
	now_ts = bpf_ktime_get_ns();
	if ((e = prep_task_event(start ? EV_HARDIRQ_ENTER : EV_HARDIRQ_EXIT, now_ts, task))) {
		bpf_probe_read_kernel_str(&e->hardirq.name, sizeof(e->hardirq.name), action->name);
		submit_event(e);
	}

	return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(wprof_hardirq_entry, int irq, struct irqaction *action)
{
	struct task_struct *task = bpf_get_current_task_btf();
	
	if (!should_trace(task, NULL))
		return 0;

	return handle_hardirq(task, action, irq, true /*start*/);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(wprof_hardirq_exit, int irq, struct irqaction *action, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	
	if (!should_trace(task, NULL))
		return 0;

	return handle_hardirq(task, action, irq, false /*!start*/);
}

static int handle_softirq(struct task_struct *task, int vec_nr, bool start)
{
	struct wprof_event *e;
	u64 now_ts;
	
	now_ts = bpf_ktime_get_ns();
	if ((e = prep_task_event(start ? EV_SOFTIRQ_ENTER : EV_SOFTIRQ_EXIT, now_ts, task))) {
		e->softirq.vec_nr = vec_nr;
		submit_event(e);
	}

	return 0;
}


SEC("tp_btf/softirq_entry")
int BPF_PROG(wprof_softirq_entry, int vec_nr)
{
	struct task_struct *task = bpf_get_current_task_btf();
	
	if (!should_trace(task, NULL))
		return 0;

	return handle_softirq(task, vec_nr, true /*start*/);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(wprof_softirq_exit, int vec_nr)
{
	struct task_struct *task = bpf_get_current_task_btf();
	u64 now_ts;
	
	if (!should_trace(task, NULL))
		return 0;

	return handle_softirq(task, vec_nr, false /*!start*/);
}

static int handle_workqueue(struct task_struct *task, struct work_struct *work, bool start)
{
	struct wprof_event *e;
	u64 now_ts;
	
	now_ts = bpf_ktime_get_ns();
	if ((e = prep_task_event(start ? EV_WQ_START : EV_WQ_END, now_ts, task))) {
		struct kthread *k = bpf_core_cast(task->worker_private, struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		bpf_probe_read_kernel_str(&e->wq.desc, sizeof(e->wq.desc), worker->desc);
		submit_event(e);
	}

	return 0;
}

SEC("tp_btf/workqueue_execute_start")
int BPF_PROG(wprof_wq_exec_start, struct work_struct *work)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct wprof_event *e;
	u64 now_ts;
	
	if (!should_trace(task, NULL))
		return 0;

	return handle_workqueue(task, work, true /*start*/);
}

SEC("tp_btf/workqueue_execute_end")
int BPF_PROG(wprof_wq_exec_end, struct work_struct *work /* , work_func_t function */)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct wprof_event *e;
	u64 now_ts;
	
	if (!should_trace(task, NULL))
		return 0;

	return handle_workqueue(task, work, false /*!start*/);
}
