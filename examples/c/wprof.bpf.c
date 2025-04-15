// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wprof.h"

#define E2BIG		7
#define ENODATA		61

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define __cleanup(callback) __attribute__((cleanup(callback)))

#define TASK_RUNNING 0

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
struct task_state {
	__u64 ts;
	__u64 waking_ts;
	__u32 waking_cpu;
	__u32 waking_flags;
	struct wprof_task waking_task;
	enum task_status status;
	__u64 softirq_ts;
	__u64 hardirq_ts;
	__u64 wq_ts;
	char wq_name[WORKER_DESC_LEN];
	struct perf_counters hardirq_ctrs;
	struct perf_counters softirq_ctrs;
	struct perf_counters wq_ctrs;
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct stack_trace);
	__uint(max_entries, 1);
} stack_trace_scratch SEC(".maps");

#define inc_stat(stat) ({							\
	__u64 __s = 0;								\
	struct wprof_stats *s = bpf_map_lookup_elem(&stats, (void *)&zero);	\
	if (s) { s->stat++; __s = s->stat; }					\
	__s;									\
})

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} perf_cntrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_RINGBUF);
		 /* max_entries doesn't matter, just to successfully create inner map proto */
		__uint(max_entries, 64 * 1024);
	});
} rbs SEC(".maps");

const volatile int pid_filter_cnt;
int pids[1] SEC(".data.pids");

const volatile int comm_filter_cnt;
char comms[16][1] SEC(".data.comms");

const volatile bool cpu_filter;
__u64 cpus[512] SEC(".data.cpus"); /* CPU bitmask, up to 4096 CPUs are supported */

const volatile __u32 perf_ctr_cnt = 1; /* for veristat, reset in user space */

const volatile __u64 rb_cnt_bits;


const volatile bool capture_stack_traces = true;

static int zero = 0;
static struct task_state empty_task_state;

__u64 session_start_ts;

/* XXX: pass CPU explicitly to avoid unnecessary surprises */
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
		(void)inc_stat(task_state_drops);
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
	if (t->flags & PF_KTHREAD) {
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
		info->tid = -(bpf_get_smp_processor_id() + 1);
	info->pid = t->tgid;
	info->flags = t->flags;
	fill_task_name(t, info->comm, sizeof(info->comm));
	__builtin_memcpy(info->pcomm, t->group_leader->comm, sizeof(info->pcomm));
}

static inline __u64 hash_bits(__u64 h, int bits)
{
	if (bits == 0)
		return 0;
	return (h * 11400714819323198485llu) >> (64 - bits);
}

static __always_inline __u32 calc_rb_slot(int pid, int cpu)
{
	return hash_bits(pid ?: cpu, rb_cnt_bits);
}

struct rb_ctx {
	void *rb;
	void *ev;
	struct bpf_dynptr dptr;
	u64 has_dptr;
};

static __always_inline struct rb_ctx __rb_event_reserve(struct task_struct *p, __u64 fix_sz, __u64 dyn_sz,
							void **ev_out, struct bpf_dynptr **dptr)
{
	struct rb_ctx rb_ctx = {};
	struct wprof_event *e;
	void *rb;
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 rb_slot = calc_rb_slot(p->pid, cpu);

	rb = bpf_map_lookup_elem(&rbs, &rb_slot);
	if (!rb) {
		(void)inc_stat(rb_misses);
		return rb_ctx;
	}
	rb_ctx.rb = rb;
	rb_ctx.has_dptr = true;

	if (bpf_ringbuf_reserve_dynptr(rb, fix_sz + dyn_sz, 0, &rb_ctx.dptr))
		(void)inc_stat(rb_drops);

	*ev_out = rb_ctx.ev = bpf_dynptr_data(&rb_ctx.dptr, 0, fix_sz);
	if (dptr)
		*dptr = &rb_ctx.dptr;

	return rb_ctx;
}

static void __rb_event_submit(void *arg)
{
	struct rb_ctx *ctx = arg;

	if (!ctx->has_dptr)
		return;

	long queued_sz = bpf_ringbuf_query(ctx->rb, BPF_RB_AVAIL_DATA);
	long flags = queued_sz >= 256 * 1024 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;

	/* no-op, if ctx->rb is NULL */
	bpf_ringbuf_submit_dynptr(&ctx->dptr, flags);
}

static void capture_perf_counters(struct perf_counters *c, int cpu)
{
	struct bpf_perf_event_value perf_val;

	for (__u64 i = 0; i < perf_ctr_cnt; i++) {
		int idx = cpu * perf_ctr_cnt + i, err;

		err = bpf_perf_event_read_value(&perf_cntrs, idx, &perf_val, sizeof(perf_val));
		if (err) {
			bpf_printk("Failed to read perf counter #%d for #%d: %d", err, i, cpu);
			c->val[i] = 0;
		} else {
			c->val[i] = perf_val.counter;
		}
	}
}

static void __capture_stack_trace(void *ctx, struct stack_trace *st)
{
	__u64 off = zero;

	st->kstack_sz = bpf_get_stack(ctx, st->addrs, sizeof(st->addrs) / 2, 0);
	if (st->kstack_sz > 0)
		off += st->kstack_sz;

	if (off > sizeof(st->addrs) / 2) /* impossible */
		off = sizeof(st->addrs) / 2;

	st->ustack_sz = bpf_get_stack(ctx, (void *)st->addrs + off, sizeof(st->addrs) / 2, BPF_F_USER_STACK);
}

static struct stack_trace *grab_stack_trace(void *ctx, size_t *sz)
{
	struct stack_trace *st;

	st = bpf_map_lookup_elem(&stack_trace_scratch, &zero);
	if (!st)
		return *sz = 0, NULL; /* shouldn't happen */

	__capture_stack_trace(ctx, st);
	*sz = (st->kstack_sz < 0 ? 0 : st->kstack_sz) +
	      (st->ustack_sz < 0 ? 0 : st->ustack_sz) +
	      offsetof(struct stack_trace, addrs);
	return st;
}

static int emit_stack_trace(struct stack_trace *t, size_t sz, struct bpf_dynptr *dptr, size_t offset)
{
	if (sz == 0)
		return -ENODATA;
	barrier_var(sz);
	if (sz > sizeof(*t))
		return -E2BIG; /* shouldn't ever happen */
	return bpf_dynptr_write(dptr, offset, t, sz, 0);
}

static __always_inline bool init_wprof_event(struct wprof_event *e, u32 sz, enum event_kind kind, u64 ts, struct task_struct *p)
{
	e->sz = sz;
	e->flags = 0;
	e->kind = kind;
	e->ts = ts;
	e->cpu = bpf_get_smp_processor_id();
	fill_task_info(p, &e->task);
	return true; /* makes emit_task_event() macro a bit easier to write */
}

#define emit_task_event(e, fix_sz, dyn_sz, kind, ts, task)					\
	for (struct rb_ctx __cleanup(__rb_event_submit) __ctx =					\
			__rb_event_reserve(task, fix_sz, dyn_sz, (void **)&(e), NULL);		\
	     e && __ctx.ev && init_wprof_event(e, fix_sz, kind, ts, task);			\
	     __ctx.ev = NULL)

#define emit_task_event_dyn(e, dptr, fix_sz, dyn_sz, kind, ts, task)				\
	for (struct rb_ctx __cleanup(__rb_event_submit) __ctx =					\
			__rb_event_reserve(task, fix_sz, dyn_sz, (void **)&(e), &(dptr));	\
	     e && __ctx.ev && init_wprof_event(e, fix_sz, kind, ts, task);			\
	     __ctx.ev = NULL)


SEC("perf_event")
int wprof_timer_tick(void *ctx)
{
	struct task_state *scur;
	struct task_struct *cur = bpf_get_current_task_btf();
	u64 now_ts;

	if (!should_trace(cur, NULL))
		return false;

	scur = task_state(cur->pid);
	if (!scur)
		return 0; /* shouldn't happen, unless we ran out of space */

	now_ts = bpf_ktime_get_ns();

	scur->ts = now_ts;
	if (scur->status == STATUS_UNKNOWN)
		/* we don't know if we are in IRQ or not, but presume not */
		scur->status = STATUS_ON_CPU;

	struct wprof_event *e;
	struct bpf_dynptr *dptr;
	struct stack_trace *strace = NULL;
	size_t dyn_sz = 0;
	size_t fix_sz = EV_SZ(timer);

	if (capture_stack_traces)
		strace = grab_stack_trace(ctx, &dyn_sz);

	emit_task_event_dyn(e, dptr, fix_sz, dyn_sz, EV_TIMER, now_ts, cur) {
		emit_stack_trace(strace, dyn_sz, dptr, fix_sz);
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
	int cpu = bpf_get_smp_processor_id();
	struct perf_counters counters;

	if (!should_trace(prev, next))
		return 0;

	sprev = task_state(prev->pid);
	snext = task_state(next->pid);
	if (!sprev || !snext)
		return 0;

	now_ts = bpf_ktime_get_ns();

	waking_ts = snext->waking_ts;

	if (perf_ctr_cnt)
		capture_perf_counters(&counters, cpu);

	/* prev task was on-cpu since last checkpoint */
	prev_dur_ns = now_ts - (sprev->ts ?: session_start_ts);
	sprev->ts = now_ts;
	sprev->waking_ts = 0;

	/* if process was involuntarily preempted, mark this as a start of
	 * scheduling delay
	 */
	if (prev->__state == TASK_RUNNING && prev->pid) {
		sprev->waking_ts = now_ts;
		sprev->waking_cpu = cpu;
		sprev->waking_flags = WF_PREEMPTED;
		fill_task_info(next, &sprev->waking_task);
	}

	/* next task was off-cpu since last checkpoint */
	next_dur_ns = now_ts - (snext->ts ?: session_start_ts);
	snext->ts = now_ts;
	snext->waking_ts = 0;


	emit_task_event(e, EV_SZ(swtch_from), 0, EV_SWITCH_FROM, now_ts, prev) {
		e->swtch_from.ctrs = counters;
		fill_task_info(next, &e->swtch_from.next);
	}

	emit_task_event(e, EV_SZ(swtch_to), 0, EV_SWITCH_TO, now_ts, next) {
		e->swtch_to.ctrs = counters;
		fill_task_info(prev, &e->swtch_to.prev);
		e->swtch_to.waking_ts = waking_ts;
		if (waking_ts) {
			e->swtch_to.waking_cpu = snext->waking_cpu;
			e->swtch_to.waking_flags = snext->waking_flags;
			bpf_probe_read_kernel(&e->swtch_to.waking, sizeof(snext->waking_task),
					      &snext->waking_task);
		}
	}

	return 0;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(wprof_task_waking, struct task_struct *p)
{
	struct wprof_event *e;
	struct task_state *s;
	struct task_struct *task;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	s = task_state(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	s->waking_ts = now_ts;
	s->waking_cpu = bpf_get_smp_processor_id();
	s->waking_flags = WF_AWOKEN;
	task = bpf_get_current_task_btf();
	fill_task_info(task, &s->waking_task);

	/*
	emit_task_event(e, EV_SZ(task), 0, EV_WAKING, now_ts, p);
	*/

	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(wprof_task_wakeup_new, struct task_struct *p)
{
	struct task_struct *task;
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
		s->waking_flags = WF_AWOKEN_NEW;
		task = bpf_get_current_task_btf();
		fill_task_info(task, &s->waking_task);
	}
	s->status = STATUS_OFF_CPU;

	/*
	emit_task_event(e, EV_SZ(task), 0, EV_WAKEUP_NEW, now_ts, p);
	*/

	return 0;
}

SEC("?tp_btf/sched_wakeup")
int BPF_PROG(wprof_task_wakeup, struct task_struct *p)
{
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	now_ts = bpf_ktime_get_ns();
	emit_task_event(e, EV_SZ(task), 0, EV_WAKEUP, now_ts, p);

	return 0;
}

SEC("tp_btf/task_rename")
int BPF_PROG(wprof_task_rename, struct task_struct *task, const char *comm)
{
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(task, NULL))
		return 0;

	if (task->flags & (PF_KTHREAD | PF_WQ_WORKER))
		return 0;

	now_ts = bpf_ktime_get_ns();

	emit_task_event(e, EV_SZ(rename), 0, EV_TASK_RENAME, now_ts, task) {
		bpf_probe_read_kernel_str(e->rename.new_comm, sizeof(e->rename.new_comm), comm);
	}

	return 0;
}


SEC("tp_btf/sched_process_fork")
int BPF_PROG(wprof_task_fork, struct task_struct *parent, struct task_struct *child)
{
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(parent, child))
		return 0;

	now_ts = bpf_ktime_get_ns();
	emit_task_event(e, EV_SZ(fork), 0, EV_FORK, now_ts, parent) {
		fill_task_info(child, &e->fork.child);
	}

	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(wprof_task_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	now_ts = bpf_ktime_get_ns();
	emit_task_event(e, EV_SZ(exec), 0, EV_EXEC, now_ts, p) {
		e->exec.old_tid = old_pid;
		bpf_probe_read_kernel_str(e->exec.filename, sizeof(e->exec.filename), bprm->filename);
	}

	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(wprof_task_exit, struct task_struct *p)
{
	struct task_state *s;
	struct wprof_event *e;
	u64 now_ts;
	int id;

	if (!should_trace(p, NULL))
		return 0;

	s = task_state_peek(p->pid);
	if (!s)
		return 0;

	now_ts = bpf_ktime_get_ns();
	
	emit_task_event(e, EV_SZ(task), 0, EV_TASK_EXIT, now_ts, p);

	task_state_delete(p->pid);

	return 0;
}

SEC("tp_btf/sched_process_free")
int BPF_PROG(wprof_task_free, struct task_struct *p)
{
	struct wprof_event *e;
	u64 now_ts;

	if (!should_trace(p, NULL))
		return 0;

	now_ts = bpf_ktime_get_ns();
	emit_task_event(e, EV_SZ(task), 0, EV_TASK_FREE, now_ts, p);

	return 0;
}

static int handle_hardirq(struct task_struct *task, struct irqaction *action, int irq, bool start)
{
	struct task_state *s;
	struct wprof_event *e;
	u64 now_ts;
	int cpu;
	
	s = task_state(task->pid);
	if (!s)
		return 0;

	cpu = bpf_get_smp_processor_id();
	now_ts = bpf_ktime_get_ns();
	if (start) {
		s->hardirq_ts = now_ts;
		if (perf_ctr_cnt)
			capture_perf_counters(&s->hardirq_ctrs, cpu);
		return 0;
	}

	if (s->hardirq_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	now_ts = bpf_ktime_get_ns();
	emit_task_event(e, EV_SZ(hardirq), 0, EV_HARDIRQ_EXIT, now_ts, task) {
		e->hardirq.hardirq_ts = s->hardirq_ts;
		e->hardirq.irq = irq;
		bpf_probe_read_kernel_str(&e->hardirq.name, sizeof(e->hardirq.name), action->name);

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (__u64 i = 0; i < perf_ctr_cnt; i++)
				e->hardirq.ctrs.val[i] = ctrs.val[i] - s->hardirq_ctrs.val[i];
		}
	}

	s->hardirq_ts = 0;

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
	struct task_state *s;
	struct wprof_event *e;
	u64 now_ts;
	int cpu;
	
	s = task_state(task->pid);
	if (!s)
		return 0;

	cpu = bpf_get_smp_processor_id();
	now_ts = bpf_ktime_get_ns();
	if (start) {
		s->softirq_ts = now_ts;
		if (perf_ctr_cnt)
			capture_perf_counters(&s->softirq_ctrs, cpu);
		return 0;
	}

	if (s->softirq_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_task_event(e, EV_SZ(softirq), 0, EV_SOFTIRQ_EXIT, now_ts, task) {
		e->softirq.softirq_ts = s->softirq_ts;
		e->softirq.vec_nr = vec_nr;

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (__u64 i = 0; i < perf_ctr_cnt; i++)
				e->softirq.ctrs.val[i] = ctrs.val[i] - s->softirq_ctrs.val[i];
		}
	}

	s->softirq_ts = 0;

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

static __always_inline bool is_valid_wq_char(char c)
{
	switch (c) {
	case '_': case '-': case '[': case ']': case '\\': case '/': case '=':
	case '.': case ',': case ';': case ':':
	case '0' ... '9':
	case 'a' ... 'z':
	case 'A' ... 'Z':
		return true;
	default:
		return false;
	}
}

static int handle_workqueue(struct task_struct *task, struct work_struct *work, bool start)
{
	struct task_state *s;
	struct wprof_event *e;
	u64 now_ts;
	int cpu, err;

	s = task_state(task->pid);
	if (!s)
		return 0;

	cpu = bpf_get_smp_processor_id();
	now_ts = bpf_ktime_get_ns();
	if (start) {
		struct kthread *k = bpf_core_cast(task->worker_private, struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		s->wq_ts = now_ts;

		err = bpf_probe_read_kernel_str(s->wq_name, sizeof(s->wq_name), worker->desc);
		if (err < 0 || !is_valid_wq_char(s->wq_name[0])) {
			s->wq_name[0] = '?';
			s->wq_name[1] = '?';
			s->wq_name[2] = '?';
			s->wq_name[3] = '\0';
		}

		if (perf_ctr_cnt)
			capture_perf_counters(&s->wq_ctrs, cpu);
		return 0;
	}

	if (s->wq_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_task_event(e, EV_SZ(wq), 0, EV_WQ_END, now_ts, task) {
		e->wq.wq_ts = s->wq_ts;
		__builtin_memcpy(e->wq.desc, s->wq_name, sizeof(e->wq.desc));

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (__u64 i = 0; i < perf_ctr_cnt; i++)
				e->wq.ctrs.val[i] = ctrs.val[i] - s->wq_ctrs.val[i];
		}
	}

	s->wq_ts = 0;

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
