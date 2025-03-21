// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <argp.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>

#include "wprof.skel.h"
#include "wprof.h"
#include "blazesym.h"
#include "hashmap.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define __unused __attribute__((unused))
#define __cleanup(fn) __attribute__((cleanup(fn)))

#define DEFAULT_RINGBUF_SZ (4 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ 4096
#define DEFAULT_STATS_PERIOD_MS 5000

static struct env {
	bool verbose;
	bool bpf_stats;
	bool libbpf_logs;
	bool print_stats;
	int freq;
	int stats_period_ms; 
	int run_dur_ms;
	int pid;
	int cpu;

	int ringbuf_sz;
	int task_state_sz;

	__u64 sess_start_ts;
	const char *trace_path;
	FILE *trace;
} env = {
	.freq = 100,
	.pid = -1,
	.cpu = -1,
	.ringbuf_sz = DEFAULT_RINGBUF_SZ,
	.task_state_sz = DEFAULT_TASK_STATE_SZ,
	.stats_period_ms = DEFAULT_STATS_PERIOD_MS,
};

const char *argp_program_version = "wprof 0.0";
const char *argp_program_bug_address = "<andrii@kernel.org>";
const char argp_program_doc[] = "BPF-based wallcklock profiler.\n";

enum {
	OPT_RINGBUF_SZ = 1000,
	OPT_TASK_STATE_SZ = 1001,
	OPT_STATS_PERIOD = 1002,
	OPT_BPF_STATS = 1003,
	OPT_LIBBPF_LOGS = 1004,
	OPT_RUN_DUR_MS = 1005,
	OPT_PRINT_STATS = 1006,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "bpf-stats", OPT_BPF_STATS, NULL, 0, "Enable and print BPF runtime stats" },
	{ "libbpf-logs", OPT_LIBBPF_LOGS, NULL, 0, "Emit libbpf verbose logs" },

	{ "trace", 'T', "FILE", 0, "Emit trace to specified file" },

	{ "pid", 'p', "PID", 0, "PID filter (track only specified PIDs)" },
	{ "cpu", 'c', "CPU", 0, "CPU filter (track only specified CPUs)" },

	{ "freq", 'f', "HZ", 0, "On-CPU timer interrupt frequency (default: 100Hz, i.e., every 10ms)" },

	{ "ringbuf-size", OPT_RINGBUF_SZ, "SIZE", 0, "BPF ringbuf size (in KBs)" },
	{ "task-state-size", OPT_TASK_STATE_SZ, "SIZE", 0, "BPF task state map size (in threads)" },

	{ "print-stats", OPT_PRINT_STATS, NULL, 0, "Print stats periodically" },
	{ "stats-period", OPT_STATS_PERIOD, "PERIOD", 0, "Stats printing period (in ms)" },
	{ "run-dur-ms", OPT_RUN_DUR_MS, "DURATION", 0, "Limit running duration to given number of ms" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case OPT_BPF_STATS:
		env.bpf_stats = true;
		break;
	case OPT_LIBBPF_LOGS:
		env.libbpf_logs = true;
		break;
	case 'T':
		if (env.trace_path) {
			fprintf(stderr, "Only one trace file can be specified!\n");
			return -EINVAL;
		}
		env.trace_path = strdup(arg);
		break;
	case 'p':
		if (env.pid >= 0) {
			fprintf(stderr, "Only one PID filter is supported!\n");
			return -EINVAL;
		}
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		if (env.cpu >= 0) {
			fprintf(stderr, "Only one CPU filter is supported!\n");
			return -EINVAL;
		}
		errno = 0;
		env.cpu = strtol(arg, NULL, 0);
		if (errno || env.cpu < 0) {
			fprintf(stderr, "Invalid CPU: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RINGBUF_SZ:
		errno = 0;
		env.ringbuf_sz = strtol(arg, NULL, 0);
		if (errno || env.ringbuf_sz < 0) {
			fprintf(stderr, "Invalid ringbuf size: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_sz *= 1024;
		break;
	case OPT_TASK_STATE_SZ:
		errno = 0;
		env.task_state_sz = strtol(arg, NULL, 0);
		if (errno || env.task_state_sz < 0) {
			fprintf(stderr, "Invalid task state size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_PRINT_STATS:
		env.print_stats = true;
		break;
	case OPT_STATS_PERIOD:
		errno = 0;
		env.stats_period_ms = strtol(arg, NULL, 0);
		if (errno || env.stats_period_ms < 0) {
			fprintf(stderr, "Invalid stats period: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RUN_DUR_MS:
		errno = 0;
		env.run_dur_ms = strtol(arg, NULL, 0);
		if (errno || env.run_dur_ms < 0) {
			fprintf(stderr, "Invalid running duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/* Copy up to sz - 1 bytes from zero-terminated src string and ensure that dst
 * is zero-terminated string no matter what (unless sz == 0, in which case
 * it's a no-op). It's conceptually close to FreeBSD's strlcpy(), but differs
 * in what is returned. Given this is internal helper, it's trivial to extend
 * this, when necessary. Use this instead of strncpy inside libbpf source code.
 */
static inline void strlcpy(char *dst, const char *src, size_t sz)
{
	size_t i;

	if (sz == 0)
		return;

	sz--;
	for (i = 0; i < sz && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

#define FMT_BUF_LEVELS 4
#define FMT_BUF_LEN 1024

static __thread char fmt_bufs[FMT_BUF_LEVELS][FMT_BUF_LEN];
static __thread int fmt_buf_idx = 0;

__unused __attribute__((format(printf, 1, 2)))
static const char *sfmt(const char *fmt, ...)
{
	va_list ap;
	char *fmt_buf = fmt_bufs[fmt_buf_idx % FMT_BUF_LEVELS];

	va_start(ap, fmt);
	(void)vsnprintf(fmt_buf, FMT_BUF_LEN, fmt, ap);
	va_end(ap);

	fmt_buf_idx++;
	return fmt_buf;
}

enum emit_scope {
	EMIT_ARR,
	EMIT_OBJ,
};

struct emit_state {
	int lvl;
	enum emit_scope scope[5];
	int cnt[5]; /* object field or array items counts, per-level */
};

static __thread struct emit_state em = {.lvl = -1};

static void emit_obj_start(void)
{
	em.scope[++em.lvl] = EMIT_OBJ;
	fprintf(env.trace, "{");
}

static void emit_obj_end(void)
{
	em.cnt[em.lvl--] = 0;
	if (em.lvl < 0) /* outermost level, we are done with current record */
		fprintf(env.trace, "},\n");
	else
		fprintf(env.trace, "}");
}

static void emit_key(const char *key)
{
	fprintf(env.trace, "%s\"%s\":", em.cnt[em.lvl] ? "," : "", key);
	em.cnt[em.lvl]++;
}

static void emit_subobj_start(const char *key)
{
	emit_key(key);
	emit_obj_start();
}

__unused
static void emit_kv_str(const char *key, const char *value)
{
	emit_key(key);
	fprintf(env.trace, "\"%s\"", value);
}

__unused
__attribute__((format(printf, 2, 3)))
static void emit_kv_fmt(const char *key, const char *fmt, ...)
{
	emit_key(key);

	fprintf(env.trace, "\"");

	va_list ap;
	va_start(ap, fmt);
	vfprintf(env.trace, fmt, ap);
	va_end(ap);

	fprintf(env.trace, "\"");
}

__unused
static void emit_kv_int(const char *key, long long value)
{
	emit_key(key);
	fprintf(env.trace, "%lld", value);
}

__unused
static void emit_kv_float(const char *key, const char *fmt, double value)
{
	emit_key(key);
	fprintf(env.trace, fmt, value);
	em.cnt[em.lvl]++;
}

__unused
static void emit_arr_start(void)
{
	em.scope[++em.lvl] = EMIT_ARR;
	fprintf(env.trace, "[");
}

__unused
static void emit_arr_end(void)
{
	em.cnt[em.lvl--] = 0;
	fprintf(env.trace, "]");
}

__unused
static void emit_subarr_start(const char *key)
{
	emit_key(key);
	emit_arr_start();
}

static void emit_arr_elem(void)
{
	if (em.cnt[em.lvl])
		fprintf(env.trace, ",");
	em.cnt[em.lvl]++;
}

__unused
static void emit_arr_str(const char *value)
{
	emit_arr_elem();
	fprintf(env.trace, "\"%s\"", value);
}

__unused
__attribute__((format(printf, 1, 2)))
static void emit_arr_fmt(const char *fmt, ...)
{
	emit_arr_elem();

	fprintf(env.trace, "\"");

	va_list ap;
	va_start(ap, fmt);
	vfprintf(env.trace, fmt, ap);
	va_end(ap);

	fprintf(env.trace, "\"");
}

__unused
static void emit_arr_int(long long value)
{
	emit_arr_elem();
	fprintf(env.trace, "%lld", value);
}

__unused
static void emit_arr_float(const char *fmt, double value)
{
	emit_arr_elem();
	fprintf(env.trace, fmt, value);
}

struct emit_rec { bool done; };

static void emit_cleanup(struct emit_rec *r)
{
	while (em.lvl >= 0) {
		if (em.scope[em.lvl] == EMIT_OBJ)
			emit_obj_end();
		else
			emit_arr_end();
	}
}

static struct blaze_symbolizer *symbolizer;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset,
			const blaze_symbolize_code_info* code_info)
{
	/* If we have an input address we have a new symbol. */
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		} else {
			printf("\n");
		}
	} else {
		printf("%16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		} else {
			printf("[inlined]\n");
		}
	}
}

__unused
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *syms;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	if (!syms) {
		printf("  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &syms->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_syms_free(syms);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.libbpf_logs)
		return 0;
	return vfprintf(stderr, format, args);
}

static __u64 ktime_off;

static inline uint64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static void calibrate_ktime(void)
{
	int i;
	struct timespec t1, t2, t3;
	uint64_t best_delta = 0, delta, ts;

	for (i = 0; i < 10; i++) {
		clock_gettime(CLOCK_REALTIME, &t1);
		clock_gettime(CLOCK_MONOTONIC, &t2);
		clock_gettime(CLOCK_REALTIME, &t3);

		delta = timespec_to_ns(&t3) - timespec_to_ns(&t1);
		ts = (timespec_to_ns(&t3) + timespec_to_ns(&t1)) / 2;

		if (i == 0 || delta < best_delta) {
			best_delta = delta;
			ktime_off = ts - timespec_to_ns(&t2);
		}
	}
}

static __u64 ktime_now_ns()
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}

static long task_id(struct wprof_task *t)
{
	return t->tid;
}

struct task_state {
	int tid, pid;
	char comm[TASK_COMM_FULL_LEN];
	/* task renames */
	__u64 rename_ts;
	char old_comm[TASK_COMM_FULL_LEN];
	/* periodic stats */
	uint64_t on_cpu_ns;
	uint64_t off_cpu_ns;
};

static struct hashmap *tasks;

static size_t hash_identity_fn(long key, void *ctx)
{
	return key;
}

static bool hash_equal_fn(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

static volatile bool exiting;

static void sig_timer(int sig)
{
	struct hashmap_entry *cur, *tmp;
	int bkt;
	struct task_state *st;

	if (env.run_dur_ms) {
		exiting = true;
		return;
	}

	printf("===============================\n");
	hashmap__for_each_entry_safe(tasks, cur, tmp, bkt) {
		st = cur->pvalue;

		if (st->on_cpu_ns + st->off_cpu_ns == 0)
			continue;

		if (cur->key < 0) {
			printf("IDLE #%ld: ONCPU = %.3lfms OFFCPU = %.3lfms\n",
			       -cur->key - 1, st->on_cpu_ns / 1000000.0, st->off_cpu_ns / 1000000.0);
		} else {
			printf("%s (%d/%d): ONCPU = %.3lfms OFFCPU = %.3lfms\n",
			       st->comm, st->tid, st->pid,
			       st->on_cpu_ns / 1000000.0, st->off_cpu_ns / 1000000.0);
		}

		st->on_cpu_ns = 0;
		st->off_cpu_ns = 0;
	}
	printf("-------------------------------\n");
}

static void sig_term(int sig)
{
	exiting = true;
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

enum {
	TRACE_PID_IDLE = 0,
	TRACE_PID_WQ = 100000000,
	TRACE_PID_KTHREAD = 200000000,
};

static int trace_tid(const struct wprof_task *t)
{
	return t->pid ? t->tid : (-t->tid - 1);
}

static int trace_pid(const struct wprof_task *t)
{
	if (t->pid == 0)
		return TRACE_PID_IDLE;
	else if (t->flags & PF_WQ_WORKER)
		return TRACE_PID_WQ;
	else if (t->flags & PF_KTHREAD)
		return TRACE_PID_KTHREAD;
	else
		return t->pid;
}

__unused
static int trace_sort_idx(const struct wprof_task *t)
{
	if (t->pid == 0)
		return -1; /* IDLE */
	else if (t->flags & PF_WQ_WORKER)
		return -2;
	else if (t->flags & PF_KTHREAD)
		return -3;
	else
		return 0;
}

static const char *trace_pcomm(const struct wprof_task *t)
{
	if (t->pid == 0)
		return "IDLE";
	else if (t->flags & PF_WQ_WORKER)
		return "KWORKERS";
	else if (t->flags & PF_KTHREAD)
		return "KTHREADS";
	else
		return t->pcomm;
}


/* from include/linux/interrupt.h */
enum irq_vec {
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ,
	RCU_SOFTIRQ,
	NR_SOFTIRQS
};

static const char *softirq_str_map[] = {
	[HI_SOFTIRQ] = "hi",
	[TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net-tx",
	[NET_RX_SOFTIRQ] = "net-rx",
	[BLOCK_SOFTIRQ] = "block",
	[IRQ_POLL_SOFTIRQ] = "irq-poll",
	[TASKLET_SOFTIRQ] = "tasklet",
	[SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer",
	[RCU_SOFTIRQ] = "rcu",
};

static const char *softirq_str(int vec_nr)
{
	if (vec_nr >= 0 && vec_nr < ARRAY_SIZE(softirq_str_map))
		return softirq_str_map[vec_nr];
	return NULL;
}

static const char *event_kind_str_map[] = {
	[EV_ON_CPU] = "ON_CPU",
	[EV_OFF_CPU] = "OFF_CPU",
	[EV_TIMER] = "TIMER",
	[EV_SWITCH] = "SWITCH",
	[EV_WAKEUP_NEW] = "WAKEUP_NEW",
	[EV_WAKEUP] = "WAKEUP",
	[EV_WAKING] = "WAKING",
	[EV_HARDIRQ_ENTER] = "HARDIRQ_ENTER",
	[EV_HARDIRQ_EXIT] = "HARDIRQ_EXIT",
	[EV_SOFTIRQ_ENTER] = "HARDIRQ_ENTER",
	[EV_SOFTIRQ_EXIT] = "SOFTIRQ_EXIT",
	[EV_WQ_START] = "WQ_START",
	[EV_WQ_END] = "WQ_END",
	[EV_FORK] = "FORK",
	[EV_EXEC] = "EXEC",
	[EV_TASK_RENAME] = "TASK_RENAME",
	[EV_TASK_EXIT] = "TASK_EXIT",
	[EV_TASK_FREE] = "TASK_EXIT",
};

static const char *event_kind_str(enum event_kind kind)
{
	if (kind >= 0 && kind < ARRAY_SIZE(event_kind_str_map))
		return event_kind_str_map[kind] ?: "UNKNOWN";
	return "UNKNOWN";
}

static const char *waking_reason_str(enum waking_flags flags)
{
	switch (flags) {
		case WF_UNKNOWN: return "unknown";
		case WF_AWOKEN: return "awoken";
		case WF_AWOKEN_NEW: return "awoken_new";
		case WF_PREEMPTED: return "preempted";
		default: return "???";
	}
}

enum instant_scope {
	SCOPE_THREAD,
	SCOPE_PROCESS,
	SCOPE_GLOBAL,
};

__unused
static const char *scope_str_map[] = {
	[SCOPE_THREAD] = "t",
	[SCOPE_PROCESS] = "p",
	[SCOPE_GLOBAL] = "g",
};

__unused
static const char *scope_str(enum instant_scope scope)
{
	return scope_str_map[scope];
}

__unused
static struct emit_rec emit_instant_pre(__u64 ts, const struct wprof_task *t,
					const char *name, const char *subname)
{
	emit_obj_start();
		emit_kv_str("ph", "i");
		emit_kv_float("ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
		emit_kv_fmt("name", "%s%s%s", name, subname ? ":" : "", subname ?: "");
		/* assume thread-scoped instant event */
		// emit_kv_str("s", "t");
		emit_kv_int("tid", trace_tid(t));
		emit_kv_int("pid", trace_pid(t));
	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_instant(ts, t, name, subname)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, t, name, subname);						\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_slice_point_pre(__u64 ts, const struct wprof_task *t,
					    const char *name, const char *subname,
					    const char *category, bool start)
{
	emit_obj_start();
		emit_kv_str("ph", start ? "B" : "E");
		emit_kv_float("ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
		emit_kv_fmt("name", "%s%s%s", name, subname ? ":" : "", subname ?: "");
		emit_kv_str("cat", category);
		emit_kv_int("tid", trace_tid(t));
		emit_kv_int("pid", trace_pid(t));
	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_slice_point(ts, t, name, subname, category, start)					\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, t, name, subname, category, start);			\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_counter_pre(__u64 ts, const struct wprof_task *t,
					const char *name, const char *subname)
{
	emit_obj_start();
		emit_kv_str("ph", "C");
		emit_kv_float("ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
		/* counters are process-scoped, so include TID into counter name */
		emit_kv_fmt("name", "%s%s%s:%d", name, subname ? ":" : "", subname ?: "", trace_tid(t));
		//emit_kv_int("tid", trace_tid(t));
		emit_kv_int("pid", trace_pid(t));
		emit_subobj_start("args");
	return (struct emit_rec){};
}

#define emit_counter(ts, t, name, subname)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_counter_pre(ts, t, name, subname);						\
	     !___r.done; ___r.done = true)

static int emit_trace_meta(const struct wprof_task *t)
{
	int tid = trace_tid(t);
	int pid = trace_pid(t);
	const char *pcomm = trace_pcomm(t);
	//int sort_idx = trace_sort_idx(t);
	
	emit_obj_start();
		emit_kv_str("ph", "M");
		emit_kv_str("name", "process_name");
		emit_kv_int("pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_str("name", pcomm);
		emit_obj_end();
	emit_obj_end();
	emit_obj_start();
		emit_kv_str("ph", "M");
		emit_kv_str("name", "process_sort_index");
		emit_kv_int("pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_int("sort_index", pid);
		emit_obj_end();
	emit_obj_end();

	emit_obj_start();
		emit_kv_str("ph", "M");
		emit_kv_str("name", "thread_name");
		emit_kv_int("tid", tid);
		emit_kv_int("pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_str("name", t->comm);
		emit_obj_end();
	emit_obj_end();
	emit_obj_start();
		emit_kv_str("ph", "M");
		emit_kv_str("name", "thread_sort_index");
		emit_kv_int("tid", tid);
		emit_kv_int("pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_int("sort_index", tid);
		emit_obj_end();
	emit_obj_end();

	return 0;
}

static struct task_state *task_state(struct wprof_task *t)
{
	unsigned long key = task_id(t);
	struct task_state *st;

	if (!hashmap__find(tasks, key, &st)) {
		st = calloc(1, sizeof(*st));
		st->tid = t->tid;
		st->pid = t->pid;
		strlcpy(st->comm, t->comm, sizeof(st->comm));

		if (env.trace)
			emit_trace_meta(t);

		hashmap__set(tasks, key, st, NULL, NULL);
	}

	return st;
}

static void task_state_delete(struct wprof_task *t)
{
	unsigned long key = task_id(t);
	struct task_state *st;

	hashmap__delete(tasks, key, NULL, &st);

	free(st);
}

/* Receive events from the ring buffer. */
static int handle_event(void *_ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	const char *status;
	struct task_state *st, *pst = NULL;

	st = task_state(&e->task);

	switch (e->kind) {
	case EV_ON_CPU:
		st->on_cpu_ns += e->dur_ns;
		break;
	case EV_OFF_CPU:
		st->off_cpu_ns += e->dur_ns;
		break;
	case EV_TIMER:
		st->on_cpu_ns += e->dur_ns;
		break;
	case EV_SWITCH:
		/* init switched-from task state, if necessary */
		pst = task_state(&e->swtch.prev);
		break;
	case EV_FORK:
		/* init forked child task state */
		(void)task_state(&e->fork.child);
		break;
	case EV_TASK_RENAME:
		if (st->rename_ts == 0) {
			memcpy(st->old_comm, e->task.comm, sizeof(st->old_comm));
			st->rename_ts = e->ts;
		}
		memcpy(st->comm, e->rename.new_comm, sizeof(st->comm));
		break;
	case EV_TASK_EXIT:
		/* we still might be getting task events, too early to delete the state */
		break;
	case EV_TASK_FREE:
		/* now we should be done with the task */
		task_state_delete(&e->task);
		break;
	default:
	}

	status = event_kind_str(e->kind);

	if (env.trace) {
		switch (e->kind) {
		case EV_ON_CPU:
			/* task finished running on CPU */
			//emit_trace_slice_point(e, e.task.comm, NULL, "ON_CPU", false /* !start */);
			break;
		case EV_OFF_CPU:
			/* task starting to run on CPU */
			//emit_trace_slice_point(e, e.task.comm, NULL, "ON_CPU", true /* start */);
			break;
		case EV_TIMER:
			/* task keeps running on CPU */
			emit_instant(e->ts, &e->task, "TIMER", NULL) {
			}
			break;
		case EV_SWITCH: {
			const char *prev_name;

			/* take into account task rename for switched-out task
			 * to maintain consistently named trace slice
			 */
			prev_name = pst->rename_ts ? pst->old_comm : e->swtch.prev.comm;
			emit_slice_point(e->ts, &e->swtch.prev, prev_name, NULL, "ONCPU", false /*!start*/) {
				emit_subobj_start("args");
				emit_kv_fmt("switch_to", "%s(%d/%d)",
					    e->task.comm, trace_tid(&e->task), e->task.pid);
				if (pst->rename_ts)
					emit_kv_str("renamed_to", e->swtch.prev.comm);
			}

			emit_slice_point(e->ts, &e->task, e->task.comm, NULL, "ONCPU", true /*start*/) {
				emit_subobj_start("args");
				if (e->swtch.waking_ts) {
					emit_kv_int("waking_cpu", e->swtch.waking_cpu);
					emit_kv_float("waking_delay_us", "%.3lf", (e->ts - e->swtch.waking_ts) / 1000.0);
					emit_kv_fmt("waking_from", "%s(%d/%d)",
						    e->swtch.waking.comm,
						    trace_tid(&e->swtch.waking), e->swtch.waking.pid);
					emit_kv_str("waking_reason", waking_reason_str(e->swtch.waking_flags));
				}
				emit_kv_fmt("switch_from", "%s(%d/%d)",
					    e->swtch.prev.comm,
					    trace_tid(&e->swtch.prev), e->swtch.prev.pid);
				emit_kv_int("cpu", e->cpu_id);
				emit_obj_end();

				/*
				emit_subarr_start("stack");
				emit_arr_str("blah");
				emit_arr_fmt("WOOT%d", 123);
				emit_arr_end();
				*/
			}

			if (e->swtch.waking_ts) {
				emit_counter(e->ts, &e->task, "waking_delay", NULL) {
					emit_kv_float("us", "%.3lf", (e->ts - e->swtch.waking_ts) / 1000.0);
				}
			}

			/*
			sfmt("%d/%d(%s)->%d/%d(%s)",
			      e->swtch.prev.tid, e->swtch.prev.pid, e->swtch.prev.comm,
			      e->task.tid, e->task.pid, e->task.comm);
			 */
		       /* !!!HACK to nest instant event at *EXACT* end of the slice within that slice,
			* because slice's end is considered to be *EXCLUSIVE*!
			* So, we adjust timestamp by one nanosecond BACKWARDS.
			*/
			//emit_instant(e->ts - 1, &e->swtch.prev, "SWITCH_OUT", buf);
			//emit_instant(e->ts, &e->task, "SWITCH_IN", buf);

			pst->rename_ts = 0;
			break;
		}
		case EV_FORK:
			emit_instant(e->ts, &e->task, "FORKING", NULL) {
				emit_subobj_start("args");
				emit_kv_fmt("forked_into", "%s(%d/%d)",
					    e->fork.child.comm, trace_tid(&e->fork.child), e->fork.child.pid);
			}
			emit_instant(e->ts, &e->fork.child, "FORKED", NULL) {
				emit_subobj_start("args");
				emit_kv_fmt("forked_from", "%s(%d/%d)",
					    e->task.comm, trace_tid(&e->task), e->task.pid);
			}
			break;
		case EV_EXEC:
			emit_instant(e->ts, &e->task, "EXEC", NULL) {
				emit_subobj_start("args");
				emit_kv_str("filename", e->exec.filename);
				if (e->task.tid != e->exec.old_tid)
					emit_kv_int("tid_changed_from", e->exec.old_tid);
			}
			break;
		case EV_TASK_RENAME:
			emit_instant(e->ts, &e->task, "RENAME",
				     sfmt("%s->%s", e->task.comm, e->rename.new_comm));
			break;
		case EV_TASK_EXIT:
			emit_instant(e->ts, &e->task, "EXIT", e->task.comm);
			break;
		case EV_TASK_FREE:
			emit_instant(e->ts, &e->task, "FREE", e->task.comm);
			break;
		case EV_WAKEUP:
			emit_instant(e->ts, &e->task, "WAKEUP", e->task.comm);
			break;
		case EV_WAKEUP_NEW:
			emit_instant(e->ts, &e->task, "WAKEUP_NEW", e->task.comm);
			break;
		case EV_WAKING:
			emit_instant(e->ts, &e->task, "WAKING", e->task.comm);
			break;
		case EV_HARDIRQ_ENTER:
		case EV_HARDIRQ_EXIT:
			emit_slice_point(e->ts, &e->task, "HARDIRQ", e->hardirq.name,
					 "HARDIRQ", e->kind == EV_HARDIRQ_ENTER /* start */);
			break;
		case EV_SOFTIRQ_ENTER:
		case EV_SOFTIRQ_EXIT:
			emit_slice_point(e->ts, &e->task, "SOFTIRQ", softirq_str(e->softirq.vec_nr),
					 "SOFTIRQ",
					 e->kind == EV_SOFTIRQ_ENTER /* start */);
			break;
		case EV_WQ_START:
		case EV_WQ_END:
			emit_slice_point(e->ts, &e->task, "WQ", e->wq.desc,
					 "WQ", e->kind == EV_WQ_START /* start */);
			break;
		default:
			break;
		}
	}

	if (!env.verbose)
		return 0;

	printf("%s (%d/%d) @ CPU %d %s %lldus\n",
	       e->task.comm, e->task.tid, e->task.pid, e->cpu_id,
	       status, e->dur_ns / 1000);

	/*
	if (e->kstack_sz <= 0 && e->ustack_sz <= 0)
		return 1;

	if (e->kstack_sz > 0) {
		printf("Kernel:\n");
		show_stack_trace(e->kstack, e->kstack_sz / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	if (e->ustack_sz > 0) {
		printf("Userspace:\n");
		show_stack_trace(e->ustack, e->ustack_sz / sizeof(__u64), e->pid);
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");
	*/

	return 0;
}

static void print_stats(struct wprof_bpf *skel, int num_cpus)
{
	struct wprof_stats *stats = calloc(num_cpus, sizeof(*stats));
	struct wprof_stats s = {};
	int zero = 0, err, i;
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_prog_info info;
		__u32 info_sz = sizeof(info);

		memset(&info, 0, sizeof(info));
		err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_sz);
		if (err) {
			fprintf(stderr, "%s: failed to fetch prog info: %d\n",
				bpf_program__name(prog), err);
			continue;
		}

		if (info.recursion_misses) {
			fprintf(stderr, "%s: missed %llu execution misses!\n",
				bpf_program__name(prog), info.recursion_misses);
		}

		if (env.bpf_stats) {
			fprintf(stderr, "%s: %llu runs for total of %.3lfms.\n",
				bpf_program__name(prog), info.run_cnt, info.run_time_ns / 1000000.0);
		}
	}

	err = bpf_map__lookup_elem(skel->maps.stats, &zero, sizeof(int),
				   stats, sizeof(*stats) * num_cpus, 0);
	if (err) {
		fprintf(stderr, "Failed to fetch BPF-side stats: %d\n", err);
		return;
	}

	for (i = 0; i < num_cpus; i++) {
		s.rb_drops += stats[i].rb_drops;
		s.task_state_drops += stats[i].task_state_drops;
	}

	if (s.rb_drops)
		fprintf(stderr, "Total ringbuf drops: %llu\n", s.rb_drops);
	if (s.task_state_drops)
		fprintf(stderr, "Total task state drops: %llu\n", s.task_state_drops);
}

static ssize_t file_size(FILE *f)
{
	int fd = fileno(f);
	struct stat st;

	if (fstat(fd, &st))
		return -errno;

	return st.st_size;
}

int main(int argc, char **argv)
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	struct wprof_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int i, err = 0;
	bool *online_mask = NULL;
	struct itimerval timer_ival;
	int stats_fd = -1;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		err = -1;
		goto cleanup;
	}

	if (env.print_stats && env.run_dur_ms) {
		fprintf(stderr, "Can't specify --print-stats and --run-dur-ms at the same time!\n");
		err = -1;
		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	tasks = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	calibrate_ktime();

	skel = wprof_bpf__open();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	bpf_map__set_max_entries(skel->maps.rb, env.ringbuf_sz);
	bpf_map__set_max_entries(skel->maps.task_states, env.task_state_sz);
	if (env.cpu >= 0) {
		skel->rodata->cpu_filter = true;
		skel->data_cpus->cpus[env.cpu / 64] |= (1ULL << ((env.cpu) % 64));
	}

	if (env.bpf_stats) {
		stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (stats_fd < 0)
			fprintf(stderr, "Failed to enable BPF run stats tracking: %d!\n", stats_fd);
	}

	err = wprof_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Fail to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_freq = env.freq;
	attr.freq = 1;

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* Set up performance monitoring on a CPU/Core */
		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.wprof_timer_tick, pefd);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	if (env.trace_path) {
		env.trace = fopen(env.trace_path, "w");
		if (!env.trace) {
			err = -errno;
			fprintf(stderr, "Failed to create trace file at '%s': %d\n", env.trace_path, err);
			goto cleanup;
		}
		if (fprintf(env.trace, "{\"traceEvents\":[\n") < 0) {
			err = -errno;
			fprintf(stderr, "Failed to write trace preamble: %d\n", err);
			goto cleanup;
		}
		/* emit fake instant event to establish strict zero timestamp */
		err = fprintf(env.trace, "{\"ph\":\"i\",\"name\":\"START\",\"s\":\"t\",\"ts\":0.0,\"tid\":0,\"pid\":0},\n");
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "Failed to start trace at '%s' with time origin instan event: %d\n", env.trace_path, err);
			goto cleanup;
		}
	}

	err = wprof_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", err);
		goto cleanup;
	}

	signal(SIGALRM, sig_timer);
	signal(SIGINT, sig_term);
	signal(SIGTERM, sig_term);

	timer_ival.it_value.tv_sec = (env.print_stats ? env.stats_period_ms : env.run_dur_ms) / 1000;
	timer_ival.it_value.tv_usec = (env.print_stats ? env.stats_period_ms : env.run_dur_ms) * 1000 % 1000000;
	timer_ival.it_interval = timer_ival.it_value;
	err = setitimer(ITIMER_REAL, &timer_ival, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to setup stats timer: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "Running...\n");
	env.sess_start_ts = ktime_now_ns();
	skel->bss->session_start_ts = env.sess_start_ts;

	/* Wait and receive stack traces */
	while ((err = ring_buffer__poll(ring_buf, -1)) >= 0 || err == -EINTR) {
		if (exiting)
			break;
	}

cleanup:
	if (skel)
		wprof_bpf__detach(skel);
	if (links) {
		for (int cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}

	if (ring_buf) /* drain ringbuf */
		(void)ring_buffer__consume(ring_buf);

	if (stats_fd >= 0)
		close(stats_fd);

	if (env.trace) {
		ssize_t file_sz;

		(void)fprintf(env.trace, "]}\n");
		fflush(env.trace);

		file_sz = file_size(env.trace);
		fprintf(stderr, "Produced %.3lfMB trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.trace_path);

		fclose(env.trace);
	}

	if (skel) {
		print_stats(skel, num_cpus);
		fprintf(stderr, "Exited cleanly (after %.3lfs).\n",
			(ktime_now_ns() - env.sess_start_ts) / 1000000000.0);
	}

	ring_buffer__free(ring_buf);
	wprof_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	free(online_mask);
	return -err;
}
