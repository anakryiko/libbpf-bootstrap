// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <argp.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
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

 __attribute__((unused))
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

static long task_id(int pid, int cpu_id)
{
	return pid ?: -(cpu_id + 1);
}

struct task_stats {
	int tid, pid;
	uint64_t on_cpu_ns;
	uint64_t off_cpu_ns;
	char comm[TASK_COMM_FULL_LEN];
};

static struct hashmap *stats;

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
	struct task_stats *st;

	if (env.run_dur_ms) {
		exiting = true;
		return;
	}

	printf("===============================\n");
	hashmap__for_each_entry_safe(stats, cur, tmp, bkt) {
		st = cur->pvalue;
		if (cur->key < 0) {
			printf("IDLE #%ld: ONCPU = %.3lfms OFFCPU = %.3lfms\n",
			       -cur->key - 1, st->on_cpu_ns / 1000000.0, st->off_cpu_ns / 1000000.0);
		} else {
			printf("%s (%d/%d): ONCPU = %.3lfms OFFCPU = %.3lfms\n",
			       st->comm, st->tid, st->pid,
			       st->on_cpu_ns / 1000000.0, st->off_cpu_ns / 1000000.0);
		}

		free(st);
		hashmap__delete(stats, cur->key, NULL, NULL);
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
	return t->pid ? t->tid : -t->tid;
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

__attribute__((unused))
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

static int emit_trace_meta(const struct wprof_task *t)
{
	int ret;
	int tid = trace_tid(t);
	int pid = trace_pid(t);
	const char *pcomm = trace_pcomm(t);
	//int sort_idx = trace_sort_idx(t);

	ret = fprintf(env.trace,
		      "{\"ph\":\"M\",\"name\":\"thread_name\",\"tid\":%d,\"pid\":%d,\"args\":{\"name\":\"%s\"}},\n",
		      tid, pid, t->comm);
	if (ret < 0)
		return -errno;
	ret = fprintf(env.trace,
		      "{\"ph\":\"M\",\"name\":\"process_name\",\"pid\":%d,\"args\":{\"name\":\"%s\"}},\n",
		      pid, pcomm);
	if (ret < 0)
		return -errno;
	/*
	ret = fprintf(env.trace,
		      "{\"ph\":\"M\",\"name\":\"process_sort_index\",\"pid\":%d,\"args\":{\"sort_index\":%d}},\n",
		      pid, sort_idx);
	if (ret < 0)
		return -errno;
	*/
	return 0;
}

__attribute__((unused))
static void emit_trace_instant(__u64 ts, const struct wprof_task *t,
			      const char *name, const char *subname)
{
	fprintf(env.trace,
		"{\"ph\":\"i\",\"name\":\"%s%s%s\",\"s\":\"t\",\"ts\":%.3lf,\"tid\":%d,\"pid\":%d},\n",
		name, subname ? ":" : "", subname ?: "",
		(ts - env.sess_start_ts) / 1000.0,
		trace_tid(t), trace_pid(t));
}

__attribute__((unused))
static int emit_trace_slice_point(__u64 ts, const struct wprof_task *t,
				  const char *name, const char *subname,
				  const char *category, bool start)
{
	int ret;

	ret = fprintf(env.trace,
		      "{\"ph\":\"%c\",\"name\":\"%s%s%s\",\"cat\":\"%s\",\"ts\":%.3lf,\"tid\":%d,\"pid\":%d},\n",
		      start ? 'B' : 'E',
		      name, subname ? ":" : "", subname ?: "",
		      category,
		      (ts - env.sess_start_ts) / 1000.0,
		      trace_tid(t), trace_pid(t));
	if (ret < 0)
		return -errno;
	return 0;
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
	[EV_EXIT] = "EXIT",
	[EV_HARDIRQ_ENTER] = "HARDIRQ_ENTER",
	[EV_HARDIRQ_EXIT] = "HARDIRQ_EXIT",
	[EV_SOFTIRQ_ENTER] = "HARDIRQ_ENTER",
	[EV_SOFTIRQ_EXIT] = "SOFTIRQ_EXIT",
	[EV_WQ_START] = "WQ_START",
	[EV_WQ_END] = "WQ_END",
};

static const char *event_kind_str(enum event_kind kind)
{
	if (kind >= 0 && kind < ARRAY_SIZE(event_kind_str_map))
		return event_kind_str_map[kind] ?: "UNKNOWN";
	return "UNKNOWN";
}

static const char *task_name(char *buf, size_t buf_sz, const struct wprof_task *t)
{
	/*
	if (t->flags & PF_WQ_WORKER) {
		snprintf(buf, buf_sz, "W:%s", t->comm);
		return buf;
	} else if (t->flags & PF_KTHREAD) {
		snprintf(buf, buf_sz, "K:%s", t->comm);
		return buf;
	}
	*/
	return t->comm;
}

/* Receive events from the ring buffer. */
static int handle_event(void *_ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	const char *status;
	unsigned long key = task_id(e->task.pid, e->cpu_id);
	struct task_stats *st;
	char name_buf[256], buf[256];
	const char *name;


	if (!hashmap__find(stats, key, &st)) {
		st = calloc(1, sizeof(*st));
		st->tid = e->task.tid,
		st->pid = e->task.pid,
		memcpy(st->comm, e->task.comm, sizeof(st->comm));

		if (env.trace) {
			if (emit_trace_meta(&e->task))
				return -1;
		}

		hashmap__set(stats, key, st, NULL, NULL);
	}

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
	default:
	}
	status = event_kind_str(e->kind);

	if (env.verbose || env.trace)
		name = task_name(name_buf, sizeof(name_buf), &e->task);
	else
		name = "???";

	if (env.trace) {
		switch (e->kind) {
		case EV_ON_CPU:
			/* task finished running on CPU */
			//emit_trace_slice_point(e, name, NULL, "ON_CPU", false /* !start */);
			break;
		case EV_OFF_CPU:
			/* task starting to run on CPU */
			//emit_trace_slice_point(e, name, NULL, "ON_CPU", true /* start */);
			break;
		case EV_TIMER:
			/* task keeps running on CPU */
			emit_trace_instant(e->ts, &e->task, "TIMER", NULL);
			break;
		case EV_SWITCH: {
			char pbuf[256];
			const char *pname;

			pname = task_name(pbuf, sizeof(pbuf), &e->swtch.prev);
			snprintf(buf, sizeof(buf), "%d/%d(%s)->%d/%d(%s)",
				 e->swtch.prev.tid, e->swtch.prev.pid, pname,
				 e->task.tid, e->task.pid, name);

			emit_trace_slice_point(e->ts, &e->swtch.prev, pname, NULL, "ONCPU", false /*!start */);
		       /* !!!HACK to nest instant event at *EXACT* end of the slice within that slice,
			* because slice's end is considered to be *EXCLUSIVE*!
			* So, we adjust timestamp by one nanosecond BACKWARDS.
			*/
			emit_trace_instant(e->ts - 1, &e->swtch.prev, "SWITCH_OUT", buf);

			emit_trace_slice_point(e->ts, &e->task, name, NULL, "ONCPU", true /*start*/);

			emit_trace_instant(e->ts, &e->task, "SWITCH_IN", buf);
			break;
		}
		case EV_WAKEUP:
			emit_trace_instant(e->ts, &e->task, "WAKEUP", name);
			break;
		case EV_WAKEUP_NEW:
			emit_trace_instant(e->ts, &e->task, "WAKEUP_NEW", name);
			break;
		case EV_WAKING:
			emit_trace_instant(e->ts, &e->task, "WAKING", name);
			break;
		case EV_EXIT:
			emit_trace_instant(e->ts, &e->task, "EXIT", name);
			break;
		case EV_HARDIRQ_ENTER:
		case EV_HARDIRQ_EXIT:
			emit_trace_slice_point(e->ts, &e->task, "HARDIRQ", e->hardirq.name,
					       "HARDIRQ", e->kind == EV_HARDIRQ_ENTER /* start */);
			break;
		case EV_SOFTIRQ_ENTER:
		case EV_SOFTIRQ_EXIT:
			emit_trace_slice_point(e->ts, &e->task, "SOFTIRQ", softirq_str(e->softirq.vec_nr),
					       "SOFTIRQ",
					       e->kind == EV_SOFTIRQ_ENTER /* start */);
			break;
		case EV_WQ_START:
		case EV_WQ_END:
			emit_trace_slice_point(e->ts, &e->task, "WQ", e->wq.desc,
					       "WQ", e->kind == EV_WQ_START /* start */);
			break;
		default:
			break;
		}
	}

	if (!env.verbose)
		return 0;

	printf("%s (%d/%d) @ CPU %d %s %lldus\n", name, e->task.tid, e->task.pid, e->cpu_id,
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

	stats = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);

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
