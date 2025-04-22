// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
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
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <pthread.h>

#include "wprof.skel.h"
#include "wprof.h"
#include "blazesym.h"
#include "hashmap.h"

#include "pb_common.h"
#include "pb_encode.h"
#include "perfetto_trace.pb.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))
#define __unused __attribute__((unused))
#define __cleanup(fn) __attribute__((cleanup(fn)))

#define DEFAULT_RINGBUF_SZ (8 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ (4 * 4096)
#define DEFAULT_STATS_PERIOD_MS 5000

static struct env {
	bool verbose;
	bool bpf_stats;
	bool libbpf_logs;
	bool print_stats;
	bool breakout_counters;
	bool stack_traces;
	int freq;
	int stats_period_ms; 
	int run_dur_ms;
	int pid;
	int cpu;

	int ringbuf_sz;
	int task_state_sz;
	int ringbuf_cnt;

	__u64 sess_start_ts;
	__u64 sess_end_ts;
	const char *trace_path;

	bool pb_debug_interns;
	bool pb_disable_interns;

	int counter_cnt;
	int counter_ids[MAX_PERF_COUNTERS];
} env = {
	.freq = 100,
	.pid = -1,
	.cpu = -1,
	.ringbuf_sz = DEFAULT_RINGBUF_SZ,
	.ringbuf_cnt = 1,
	.task_state_sz = DEFAULT_TASK_STATE_SZ,
	.stats_period_ms = DEFAULT_STATS_PERIOD_MS,
	.stack_traces = true,
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
	OPT_PRINT_STATS = 1006,
	OPT_BREAKOUT_COUNTERS = 1008,
	OPT_PB_DEBUG_INTERNS = 1009,
	OPT_PB_DISABLE_INTERNS = 1010,
	OPT_RINGBUF_CNT = 1011,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "bpf-stats", OPT_BPF_STATS, NULL, 0, "Enable and print BPF runtime stats" },
	{ "libbpf-logs", OPT_LIBBPF_LOGS, NULL, 0, "Emit libbpf verbose logs" },

	{ "trace", 'T', "FILE", 0, "Emit trace to specified file" },

	{ "stack-traces", 's', NULL, 0, "Capture stack traces" },
	{ "no-stack-traces", 'S', NULL, 0, "Don't capture stack traces" },

	{ "pid", 'p', "PID", 0, "PID filter (track only specified PIDs)" },
	{ "cpu", 'c', "CPU", 0, "CPU filter (track only specified CPUs)" },

	{ "freq", 'f', "HZ", 0, "On-CPU timer interrupt frequency (default: 100Hz, i.e., every 10ms)" },

	{ "ringbuf-size", OPT_RINGBUF_SZ, "SIZE", 0, "BPF ringbuf size (in KBs)" },
	{ "task-state-size", OPT_TASK_STATE_SZ, "SIZE", 0, "BPF task state map size (in threads)" },
	{ "ringbuf-cnt", OPT_RINGBUF_CNT, "N", 0, "Number of BPF ringbufs to use" },

	{ "cpu-counter", 'C', "NAME", 0, "Capture and emit specified perf/CPU/hardware counter (cpu-cycles, cpu-insns, cache-hits, cache-misses, stalled-cycles-fe, stallec-cycles-be)" },
	{ "breakout-counters", OPT_BREAKOUT_COUNTERS, NULL, 0, "Emit separate track for counters" },

	{ "print-stats", OPT_PRINT_STATS, NULL, 0, "Print stats periodically" },
	{ "stats-period", OPT_STATS_PERIOD, "PERIOD", 0, "Stats printing period (in ms)" },
	{ "run-dur-ms", 'D', "DURATION", 0, "Limit running duration to given number of ms" },

	{ "debug-interns", OPT_PB_DEBUG_INTERNS, NULL, 0, "Emit interned strings" },
	{ "pb-disable-interns", OPT_PB_DISABLE_INTERNS, NULL, 0, "Disable string interning for Perfetto traces" },
	{},
};

static int round_pow_of_2(int n);

struct perf_counter_def {
	const char *alias;
	int perf_type;
	int perf_cfg;
	double mul;
	const char *trace_name;
	__u32 trace_name_iid;
};

static const struct perf_counter_def perf_counter_defs[];

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
	case 's':
		env.stack_traces = true;
		break;
	case 'S':
		env.stack_traces = false;
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
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 0);
		if (errno || env.freq <= 0) {
			fprintf(stderr, "Invalid frequency: %s\n", arg);
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
		env.ringbuf_sz = round_pow_of_2(env.ringbuf_sz * 1024);
		break;
	case OPT_TASK_STATE_SZ:
		errno = 0;
		env.task_state_sz = strtol(arg, NULL, 0);
		if (errno || env.task_state_sz < 0) {
			fprintf(stderr, "Invalid task state size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RINGBUF_CNT:
		errno = 0;
		env.ringbuf_cnt = strtol(arg, NULL, 0);
		if (errno || env.ringbuf_cnt < 0) {
			fprintf(stderr, "Invalid ringbuf count: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_cnt = round_pow_of_2(env.ringbuf_cnt);
		break;
	case OPT_PRINT_STATS:
		env.print_stats = true;
		break;
	case 'C': {
		int counter_idx = -1;

		for (int i = 0; perf_counter_defs[i].alias; i++) {
			if (strcmp(arg, perf_counter_defs[i].alias) != 0)
				continue;

			counter_idx = i;
			break;
		}

		if (counter_idx < 0) {
			fprintf(stderr, "Unrecognized counter '%s'!\n", arg);
			argp_usage(state);
		}

		for (int i = 0; i < env.counter_cnt; i++) {
			if (env.counter_ids[i] == counter_idx) {
				counter_idx = -1;
				break;
			}
		}

		if (counter_idx >= 0) {
			if (env.counter_cnt >= MAX_PERF_COUNTERS) {
				fprintf(stderr, "Too many perf counters requested, only %d are currently supported!\n", MAX_PERF_COUNTERS);
				return -E2BIG;
			}
			env.counter_ids[env.counter_cnt++] = counter_idx;
		}
		break;
	}
	case OPT_BREAKOUT_COUNTERS:
		env.breakout_counters = true;
		break;
	case OPT_STATS_PERIOD:
		errno = 0;
		env.stats_period_ms = strtol(arg, NULL, 0);
		if (errno || env.stats_period_ms < 0) {
			fprintf(stderr, "Invalid stats period: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'D':
		errno = 0;
		env.run_dur_ms = strtol(arg, NULL, 0);
		if (errno || env.run_dur_ms < 0) {
			fprintf(stderr, "Invalid running duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_PB_DEBUG_INTERNS:
		env.pb_debug_interns = true;
		break;
	case OPT_PB_DISABLE_INTERNS:
		env.pb_disable_interns = true;
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

static ssize_t file_size(FILE *f)
{
	int fd = fileno(f);
	struct stat st;

	fflush(f);

	if (fstat(fd, &st))
		return -errno;

	return st.st_size;
}

static inline bool is_pow_of_2(long x)
{
        return x && (x & (x - 1)) == 0;
}

static int round_pow_of_2(int n)
{
        int tmp_n;

        if (is_pow_of_2(n))
                return n;

        for (tmp_n = 1; tmp_n <= INT_MAX / 4; tmp_n *= 2) {
                if (tmp_n >= n)
                        break;
        }

        if (tmp_n >= INT_MAX / 2)
                return -E2BIG;

        return tmp_n;
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

#define FMT_BUF_LEVELS 16
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

__unused
static const char *vsfmt(const char *fmt, va_list ap)
{
	char *fmt_buf = fmt_bufs[fmt_buf_idx % FMT_BUF_LEVELS];

	(void)vsnprintf(fmt_buf, FMT_BUF_LEN, fmt, ap);

	fmt_buf_idx++;
	return fmt_buf;
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

/*
 * PROTOBUF UTILS
 */
typedef perfetto_protos_TracePacket TracePacket;
typedef perfetto_protos_TrackEvent TrackEvent;
typedef perfetto_protos_DebugAnnotation DebugAnnotation;
typedef perfetto_protos_InternedString InternedString;

enum pb_static_iid {
	IID_NONE = 0,

	CAT_START_IID, __CAT_RESET_IID = CAT_START_IID - 1,
		IID_CAT_ONCPU,					/* ONCPU */
		IID_CAT_OFFCPU,					/* OFFCPU */
		IID_CAT_HARDIRQ,				/* HARDIRQ */
		IID_CAT_SOFTIRQ,				/* SOFTIRQ */
		IID_CAT_WQ,					/* WQ */
	CAT_END_IID,

	NAME_START_IID, __NAME_RESET_IID = NAME_START_IID - 1,
		IID_NAME_TIMER,					/* TIMER */
		IID_NAME_EXEC,					/* EXEC */
		IID_NAME_EXIT,					/* EXIT */
		IID_NAME_FREE,					/* FREE */
		IID_NAME_WAKEUP,				/* WAKEUP */
		IID_NAME_WAKEUP_NEW,				/* WAKEUP_NEW */
		IID_NAME_WAKING,				/* WAKING */
		IID_NAME_AWOKEN_NEW,				/* AWOKEN_NEW */
		IID_NAME_AWAKING,				/* AWAKING */
		IID_NAME_FORKING,				/* FORKING */
		IID_NAME_FORKED,				/* FORKED */
		IID_NAME_RENAME,				/* RENAME */
		IID_NAME_HARDIRQ,				/* HARDIRQ */
		IID_NAME_SOFTIRQ,				/* SOFTIRQ:... */
		IID_NAME_SOFTIRQ_LAST = IID_NAME_SOFTIRQ + NR_SOFTIRQS - 1,
	NAME_END_IID,

	ANNK_START_IID, __ANNK_RESET_IID = ANNK_START_IID - 1,
		IID_ANNK_CPU,					/* cpu */
		IID_ANNK_SWITCH_TO,				/* switch_to */
		IID_ANNK_SWITCH_TO_TID,				/* switch_to_tid */
		IID_ANNK_SWITCH_TO_PID,				/* switch_to_pid */
		IID_ANNK_SWITCH_FROM,				/* switch_from */
		IID_ANNK_SWITCH_FROM_TID,			/* switch_from_tid */
		IID_ANNK_SWITCH_FROM_PID,			/* switch_from_pid */
		IID_ANNK_CPU_MEGA_CYCLES,			/* cpu_mega_cycles */
		IID_ANNK_RENAMED_TO,				/* renamed_to */
		IID_ANNK_WAKING_CPU,				/* waking_cpu */
		IID_ANNK_WAKING_DELAY_US,			/* waking_delay_us */
		IID_ANNK_WAKING_BY,				/* waking_by */
		IID_ANNK_WAKING_BY_TID,				/* waking_by_tid */
		IID_ANNK_WAKING_BY_PID,				/* waking_by_pid */
		IID_ANNK_WAKING_REASON,				/* waking_reason */
		IID_ANNK_WAKING_TARGET,				/* waking_target */
		IID_ANNK_WAKING_TARGET_TID,			/* waking_target_tid */
		IID_ANNK_WAKING_TARGET_PID,			/* waking_target_pid */
		IID_ANNK_FORKED_INTO,				/* forked_into */
		IID_ANNK_FORKED_INTO_TID,			/* forked_into_tid */
		IID_ANNK_FORKED_INTO_PID,			/* forked_into_pid */
		IID_ANNK_FORKED_FROM,				/* forked_from */
		IID_ANNK_FORKED_FROM_TID,			/* forked_from_tid */
		IID_ANNK_FORKED_FROM_PID,			/* forked_from_pid */
		IID_ANNK_FILENAME,				/* filename */
		IID_ANNK_TID_CHANGED_FROM,			/* tid_changed_from */
		IID_ANNK_OLD_NAME,				/* old_name */
		IID_ANNK_NEW_NAME,				/* new_name */
		IID_ANNK_ACTION,				/* action */
		IID_ANNK_IRQ,					/* irq */
		IID_ANNK_PERF_CPU_CYCLES,			/* cpu_cycles_kilo */
		IID_ANNK_PERF_CPU_INSNS,			/* cpu_insns_kilo */
		IID_ANNK_PERF_CACHE_HITS,			/* cache_hits_kilo */
		IID_ANNK_PERF_CACHE_MISSES,			/* cache_misses_kilo */
		IID_ANNK_PERF_STALL_CYCLES_FE,			/* stalled_cycles_fe_kilo */
		IID_ANNK_PERF_STALL_CYCLES_BE,			/* stalled_cycles_be_kilo */
	ANNK_END_IID,

	ANNV_START_IID, __ANNV_RESET_IID = ANNV_START_IID - 1,
		IID_ANNV_SOFTIRQ_ACTION,			/* sched, net-rx, rcu, ... */
		IID_ANNV_SOFTIRQ_ACTION_LAST = IID_ANNV_SOFTIRQ_ACTION + NR_SOFTIRQS - 1,
	ANNV_END_IID,

	IID_FIXED_LAST_ID,
};

typedef uint32_t pb_iid;

static const char *pb_strs[] = {
	[IID_CAT_ONCPU] = "ONCPU",
	[IID_CAT_OFFCPU] = "OFFCPU",
	[IID_CAT_HARDIRQ] = "HARDIRQ",
	[IID_CAT_SOFTIRQ] = "SOFTIRQ",
	[IID_CAT_WQ] = "WQ",

	[IID_NAME_TIMER] = "TIMER",
	[IID_NAME_EXEC] = "EXEC",
	[IID_NAME_EXIT] = "EXIT",
	[IID_NAME_FREE] = "FREE",
	[IID_NAME_WAKEUP] = "WAKEUP",
	[IID_NAME_WAKEUP_NEW] = "WAKEUP_NEW",
	[IID_NAME_WAKING] = "WAKING",
	[IID_NAME_AWOKEN_NEW] = "AWOKEN_NEW",
	[IID_NAME_AWAKING] = "AWAKING",
	[IID_NAME_FORKING] = "FORKING",
	[IID_NAME_FORKED] = "FORKED",
	[IID_NAME_RENAME] = "RENAME",
	[IID_NAME_HARDIRQ] = "HARDIRQ",
	[IID_NAME_SOFTIRQ + HI_SOFTIRQ] = "SOFTIRQ:hi",
	[IID_NAME_SOFTIRQ + TIMER_SOFTIRQ] = "SOFTIRQ:timer",
	[IID_NAME_SOFTIRQ + NET_TX_SOFTIRQ] = "SOFTIRQ:net-tx",
	[IID_NAME_SOFTIRQ + NET_RX_SOFTIRQ] = "SOFTIRQ:net-rx",
	[IID_NAME_SOFTIRQ + BLOCK_SOFTIRQ] = "SOFTIRQ:block",
	[IID_NAME_SOFTIRQ + IRQ_POLL_SOFTIRQ] = "SOFTIRQ:irq-poll",
	[IID_NAME_SOFTIRQ + TASKLET_SOFTIRQ] = "SOFTIRQ:tasklet",
	[IID_NAME_SOFTIRQ + SCHED_SOFTIRQ] = "SOFTIRQ:sched",
	[IID_NAME_SOFTIRQ + HRTIMER_SOFTIRQ] = "SOFTIRQ:hrtimer",
	[IID_NAME_SOFTIRQ + RCU_SOFTIRQ] = "SOFTIRQ:rcu",

	[IID_ANNK_SWITCH_TO] = "switch_to",
	[IID_ANNK_SWITCH_TO_TID] = "switch_to_tid",
	[IID_ANNK_SWITCH_TO_PID] = "switch_to_pid",
	[IID_ANNK_SWITCH_FROM] = "switch_from",
	[IID_ANNK_SWITCH_FROM_TID] = "switch_from_tid",
	[IID_ANNK_SWITCH_FROM_PID] = "switch_from_pid",
	[IID_ANNK_CPU] = "cpu",
	[IID_ANNK_CPU_MEGA_CYCLES] = "cpu_mega_cycles",
	[IID_ANNK_RENAMED_TO] = "renamed_to",
	[IID_ANNK_WAKING_CPU] = "waking_cpu",
	[IID_ANNK_WAKING_DELAY_US] = "waking_delay_us",
	[IID_ANNK_WAKING_BY] = "waking_by",
	[IID_ANNK_WAKING_BY_TID] = "waking_by_tid",
	[IID_ANNK_WAKING_BY_PID] = "waking_by_pid",
	[IID_ANNK_WAKING_REASON] = "waking_reason",
	[IID_ANNK_WAKING_TARGET] = "waking_target",
	[IID_ANNK_WAKING_TARGET_TID] = "waking_target_tid",
	[IID_ANNK_WAKING_TARGET_PID] = "waking_target_pid",
	[IID_ANNK_FORKED_INTO] = "forked_into",
	[IID_ANNK_FORKED_INTO_TID] = "forked_into_tid",
	[IID_ANNK_FORKED_INTO_PID] = "forked_into_pid",
	[IID_ANNK_FORKED_FROM] = "forked_from",
	[IID_ANNK_FORKED_FROM_TID] = "forked_from_tid",
	[IID_ANNK_FORKED_FROM_PID] = "forked_from_pid",
	[IID_ANNK_FILENAME] = "filename",
	[IID_ANNK_TID_CHANGED_FROM] = "tid_changed_from",
	[IID_ANNK_OLD_NAME] = "old_name",
	[IID_ANNK_NEW_NAME] = "new_name",
	[IID_ANNK_ACTION] = "action",
	[IID_ANNK_IRQ] = "irq",
	[IID_ANNK_PERF_CPU_CYCLES] = "cpu_cycles_kilo",
	[IID_ANNK_PERF_CPU_INSNS] = "cpu_insns_kilo",
	[IID_ANNK_PERF_CACHE_HITS] = "cache_hits_kilo",
	[IID_ANNK_PERF_CACHE_MISSES] = "cache_misses_kilo",
	[IID_ANNK_PERF_STALL_CYCLES_FE] = "stalled_cycles_fe_kilo",
	[IID_ANNK_PERF_STALL_CYCLES_BE] = "stalled_cycles_be_kilo",

	[IID_ANNV_SOFTIRQ_ACTION + HI_SOFTIRQ] = "hi",
	[IID_ANNV_SOFTIRQ_ACTION + TIMER_SOFTIRQ] = "timer",
	[IID_ANNV_SOFTIRQ_ACTION + NET_TX_SOFTIRQ] = "net-tx",
	[IID_ANNV_SOFTIRQ_ACTION + NET_RX_SOFTIRQ] = "net-rx",
	[IID_ANNV_SOFTIRQ_ACTION + BLOCK_SOFTIRQ] = "block",
	[IID_ANNV_SOFTIRQ_ACTION + IRQ_POLL_SOFTIRQ] = "irq-poll",
	[IID_ANNV_SOFTIRQ_ACTION + TASKLET_SOFTIRQ] = "tasklet",
	[IID_ANNV_SOFTIRQ_ACTION + SCHED_SOFTIRQ] = "sched",
	[IID_ANNV_SOFTIRQ_ACTION + HRTIMER_SOFTIRQ] = "hrtimer",
	[IID_ANNV_SOFTIRQ_ACTION + RCU_SOFTIRQ] = "rcu",

};

static size_t str_hash_fn(long key, void *ctx)
{
	return str_hash((void *)key);
}

static bool str_equal_fn(long a, long b, void *ctx)
{
	return strcmp((void *)a, (void *)b) == 0;
}

struct pb_str {
	int iid;
	const char *s;
};

static bool file_stream_cb(pb_ostream_t *stream, const uint8_t *buf, size_t count)
{
	FILE *f = stream->state;

	return fwrite(buf, 1, count, f) == count;
}

#define PB_INIT(field) .has_##field = true, .field

#define PB_TRUST_SEQ_ID() \
	.which_optional_trusted_packet_sequence_id = perfetto_protos_TracePacket_trusted_packet_sequence_id_tag, \
	.optional_trusted_packet_sequence_id = { (0x42) }

#define PB_NONE ((pb_callback_t){})
#define PB_ONEOF(field, _type) .which_##field = perfetto_protos_##_type##_tag, .field

static bool enc_string(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const char *s = *arg;

	return pb_encode_tag_for_field(stream, field) &&
	       pb_encode_string(stream, (void *)s, strlen(s));
}

static bool enc_string_iid(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	pb_iid iid = *(pb_iid *)arg;

	return pb_encode_tag_for_field(stream, field) &&
	       pb_encode_varint(stream, iid);
}

#define PB_STRING(s) ((pb_callback_t){{.encode=enc_string}, (void *)(s)})
#define PB_STRING_IID(iid) ((pb_callback_t){{.encode=enc_string_iid}, (void *)(unsigned long)(iid)})

#define PB_NAME(_type, field, iid, name_str)							\
	.which_##field = (iid && !env.pb_disable_interns)					\
			 ? perfetto_protos_##_type##_name_iid_tag				\
			 : perfetto_protos_##_type##_name_tag,					\
	.field = { .name = (iid && !env.pb_disable_interns)					\
			   ? (pb_callback_t){.funcs={(void *)(long)(iid)}}			\
			   : PB_STRING(name_str) }

enum pb_ann_kind {
	PB_ANN_BOOL,
	PB_ANN_UINT,
	PB_ANN_INT,
	PB_ANN_DOUBLE,
	PB_ANN_PTR,
	PB_ANN_STR,
	PB_ANN_STR_IID,
};

struct pb_ann_val {
	enum pb_ann_kind kind;
	union {
		bool val_bool;
		uint64_t val_uint;
		int64_t val_int;
		double val_double;
		const void *val_ptr;
		const char *val_str;
		__u64 val_str_iid;
	};
};

struct pb_ann_kv {
	const char *name;
	__u64 name_iid;
	struct pb_ann_val val;
};

struct pb_ann {
	const char *name;
	__u64 name_iid;
	struct pb_ann_kv **dict;
	struct pb_ann_val **arr;
	struct pb_ann_val *val;
};

#define MAX_ANN_CNT 16
struct pb_anns {
	int cnt;
	struct pb_ann *ann_ptrs[MAX_ANN_CNT];
	struct pb_ann anns[MAX_ANN_CNT];
	struct pb_ann_val vals[MAX_ANN_CNT];
};

static void anns_reset(struct pb_anns *anns)
{
	anns->cnt = 0;
}

__unused
static void anns_add_ann(struct pb_anns *anns, struct pb_ann *ann)
{
	if (anns->cnt == MAX_ANN_CNT) {
		fprintf(stderr, "Annotations overflow!\n");
		exit(1);
	}

	anns->ann_ptrs[anns->cnt++] = ann;
}

static struct pb_ann_val *anns_add_val(struct pb_anns *anns, pb_iid key_iid, const char *key)
{
	struct pb_ann_val *val;
	struct pb_ann *ann;

	if (anns->cnt == ARRAY_SIZE(anns->anns)) {
		fprintf(stderr, "Annotations overflow!\n");
		exit(1);
	}

	val = &anns->vals[anns->cnt];
	ann = &anns->anns[anns->cnt];
	anns->ann_ptrs[anns->cnt++] = ann;

	ann->name = key;
	ann->name_iid = key_iid;
	ann->val = val;
	ann->dict = NULL;
	ann->arr = NULL;

	return val;
}

__unused
static void anns_add_str(struct pb_anns *anns, pb_iid key_iid, const char *key,
			 pb_iid value_iid, const char *value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	if (value_iid && !env.pb_disable_interns) {
		val->kind = PB_ANN_STR_IID;
		val->val_str_iid = value_iid;
	} else {
		val->kind = PB_ANN_STR;
		val->val_str = value;
	}
}

__unused
static void anns_add_uint(struct pb_anns *anns, pb_iid key_iid, const char *key, uint64_t value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_UINT;
	val->val_int = value;
}

__unused
static void anns_add_int(struct pb_anns *anns, pb_iid key_iid, const char *key, int64_t value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_INT;
	val->val_int = value;
}

__unused
static void anns_add_double(struct pb_anns *anns, pb_iid key_iid, const char *key, double value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_DOUBLE;
	val->val_double = value;
}

static void ann_set_value(DebugAnnotation *ann_proto, const struct pb_ann_val *val)
{
	switch (val->kind) {
		case PB_ANN_BOOL:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_bool_value_tag;
			ann_proto->value.bool_value = val->val_bool;
			break;
		case PB_ANN_UINT:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_uint_value_tag;
			ann_proto->value.uint_value = val->val_uint;
			break;
		case PB_ANN_INT:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_int_value_tag;
			ann_proto->value.int_value = val->val_int;
			break;
		case PB_ANN_DOUBLE:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_double_value_tag;
			ann_proto->value.double_value = val->val_double;
			break;
		case PB_ANN_PTR:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_pointer_value_tag;
			ann_proto->value.pointer_value = (uint64_t)val->val_ptr;
			break;
		case PB_ANN_STR:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_string_value_tag;
			ann_proto->value.string_value = PB_STRING(val->val_str);
			break;
		case PB_ANN_STR_IID:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_string_value_iid_tag;
			ann_proto->value.string_value_iid = val->val_str_iid;
			break;
	}
}

static bool enc_ann_dict(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_ann *ann = *arg;
	struct pb_ann_kv **kvs = ann->dict;

	while (*kvs) {
		const struct pb_ann_kv *kv = *kvs;
		DebugAnnotation ann_proto = {
			PB_NAME(DebugAnnotation, name_field, kv->name_iid, kv->name),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;

		ann_set_value(&ann_proto, &kv->val);

		if (!pb_encode_submessage(stream, perfetto_protos_DebugAnnotation_fields, &ann_proto))
			return false;
		kvs++;
	}

	return true;
}

static bool enc_ann_arr(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_ann *ann = *arg;
	struct pb_ann_val **vals = ann->arr;

	while (*vals) {
		const struct pb_ann_val *v = *vals;
		DebugAnnotation ann_proto = {};

		ann_set_value(&ann_proto, v);

		if (!pb_encode_tag_for_field(stream, field))
			return false;

		if (!pb_encode_submessage(stream, perfetto_protos_DebugAnnotation_fields, &ann_proto))
			return false;
		vals++;
	}

	return true;
}

static bool enc_annotations(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_anns *anns = *arg;

	for (int i = 0; i < anns->cnt; i++) {
		const struct pb_ann *ann = anns->ann_ptrs[i];
		DebugAnnotation ann_proto = {
			PB_NAME(DebugAnnotation, name_field, ann->name_iid, ann->name),
		};

		if (ann->dict)
			ann_proto.dict_entries = (pb_callback_t){{.encode=enc_ann_dict}, (void *)ann};
		if (ann->arr)
			ann_proto.array_values = (pb_callback_t){{.encode=enc_ann_arr}, (void *)ann};
		if (ann->val)
			ann_set_value(&ann_proto, ann->val);

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_DebugAnnotation_fields, &ann_proto))
			return false;
	}

	return true;
}

#define PB_ANNOTATIONS(p) ((pb_callback_t){{.encode=enc_annotations}, (void *)(p)})

struct pb_str_iid_range {
	int start_id;
	int end_id;
};

static bool enc_str_iid_range(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_str_iid_range *intern_set = *arg;

	for (int iid = intern_set->start_id; iid < intern_set->end_id; iid++) {
		InternedString pb = {
			PB_INIT(iid) = iid,
			.str = PB_STRING(pb_strs[iid]),
		};

		if (!pb_strs[iid]) {
			fprintf(stderr, "Missing string value mapping for IID #%d!\n", iid);
			exit(1);
		}

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_InternedString_fields, &pb))
			return false;
	}

	return true;
}

struct pb_str_iid {
	pb_iid iid;
	const char *s;
};

static bool enc_str_iid(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_str_iid *pair = *arg;
	InternedString pb = {
		PB_INIT(iid) = pair->iid,
		.str = PB_STRING(pair->s),
	};

	if (!pb_encode_tag_for_field(stream, field))
		return false;
	if (!pb_encode_submessage(stream, perfetto_protos_InternedString_fields, &pb))
		return false;

	return true;
}

struct pb_str_iids {
	int cnt, cap;
	int *iids;
	const char **strs;
};

static bool enc_str_iids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_str_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		InternedString pb = {
			PB_INIT(iid) = iids->iids[i],
			.str = PB_STRING(iids->strs[i]),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_InternedString_fields, &pb))
			return false;
	}

	return true;
}

#define PB_STR_IID_RANGE(start_id, end_id) ((pb_callback_t){{.encode=enc_str_iid_range}, (void *)&((struct pb_str_iid_range){ start_id, end_id })})
#define PB_STR_IID(iid, str) ((pb_callback_t){{.encode=enc_str_iid}, (void *)&((struct pb_str_iid){ iid, str })})
#define PB_STR_IIDS(p) ((pb_callback_t){{.encode=enc_str_iids}, (void *)(p)})

struct pb_mapping {
	int iid;
	__u64 start;
	__u64 end;
	__u64 start_offset;
};

struct pb_mapping_iids {
	int cnt, cap;
	struct pb_mapping *mappings;
};

static bool enc_mappings(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_mapping_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		perfetto_protos_Mapping pb = {
			PB_INIT(iid) = iids->mappings[i].iid,
			PB_INIT(start) = iids->mappings[i].start,
			PB_INIT(end) = iids->mappings[i].end,
			PB_INIT(start_offset) = iids->mappings[i].start_offset,
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_Mapping_fields, &pb))
			return false;
	}

	return true;
}

#define PB_MAPPINGS(p) ((pb_callback_t){{.encode=enc_mappings}, (void *)(p)})

struct pb_frame {
	int iid;
	int function_name_id;
	int mapping_id;
	__u64 rel_pc;
};

struct pb_frame_iids {
	int cnt, cap;
	struct pb_frame *frames;
};

static bool enc_frames(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_frame_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		perfetto_protos_Frame pb = {
			PB_INIT(iid) = iids->frames[i].iid,
			PB_INIT(mapping_id) = iids->frames[i].mapping_id,
			PB_INIT(function_name_id) = iids->frames[i].function_name_id,
			PB_INIT(rel_pc) = iids->frames[i].rel_pc,
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_Frame_fields, &pb))
			return false;
	}

	return true;
}

#define PB_FRAMES(p) ((pb_callback_t){{.encode=enc_frames}, (void *)(p)})

struct pb_callstack {
	int iid;
	int frame_cnt;
	int *frame_ids;
};

struct pb_callstack_iids {
	int cnt, cap;
	struct pb_callstack *callstacks;
};

static bool enc_callstack_frame_ids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_callstack *callstack = *arg;

	for (int i = 0; i < callstack->frame_cnt; i++) {
		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_varint(stream, callstack->frame_ids[i]))
			return false;
	}

	return true;
}

#define PB_CALLSTACK_FRAME_IDS(p) ((pb_callback_t){{.encode=enc_callstack_frame_ids}, (void *)(p)})

static bool enc_callstacks(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_callstack_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		perfetto_protos_Callstack pb = {
			PB_INIT(iid) = iids->callstacks[i].iid,
			.frame_ids = PB_CALLSTACK_FRAME_IDS(&iids->callstacks[i]),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_Callstack_fields, &pb))
			return false;
	}

	return true;
}

#define PB_CALLSTACKS(p) ((pb_callback_t){{.encode=enc_callstacks}, (void *)(p)})

static void append_str_iid(struct pb_str_iids *iids, int iid, const char *s)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 1024 ? 1024 : iids->cnt * 4 / 3;
		iids->iids = realloc(iids->iids, new_cap * sizeof(*iids->iids));
		iids->strs = realloc(iids->strs, new_cap * sizeof(*iids->strs));
		iids->cap = new_cap;
	}
	iids->iids[iids->cnt] = iid;
	iids->strs[iids->cnt] = s;
	iids->cnt += 1;
}

static void append_mapping_iid(struct pb_mapping_iids *iids, int iid, __u64 start, __u64 end, __u64 offset)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 256 ? 256 : iids->cnt * 4 / 3;
		iids->mappings = realloc(iids->mappings, new_cap * sizeof(*iids->mappings));
		iids->cap = new_cap;
	}
	iids->mappings[iids->cnt].iid = iid;
	iids->mappings[iids->cnt].start = start;
	iids->mappings[iids->cnt].end = end;
	iids->mappings[iids->cnt].start_offset = offset;
	iids->cnt += 1;
}

static void append_frame_iid(struct pb_frame_iids *iids, int iid, int mapping_iid, int fname_iid, __u64 rel_pc)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 256 ? 256 : iids->cnt * 4 / 3;
		iids->frames = realloc(iids->frames, new_cap * sizeof(*iids->frames));
		iids->cap = new_cap;
	}
	iids->frames[iids->cnt].iid = iid;
	iids->frames[iids->cnt].mapping_id = mapping_iid;
	iids->frames[iids->cnt].function_name_id = fname_iid;
	iids->frames[iids->cnt].rel_pc = rel_pc;
	iids->cnt += 1;
}

static void append_callstack_frame_iid(struct pb_callstack_iids *iids, int iid, int frame_iid)
{
	struct pb_callstack *cs = NULL;

	if (iids->cnt > 0 && iids->callstacks[iids->cnt - 1].iid == iid)
		cs = &iids->callstacks[iids->cnt - 1];

	if (!cs) {
		if (iids->cnt == iids->cap) {
			int new_cap = iids->cnt < 32 ? 32 : iids->cnt * 4 / 3;
			iids->callstacks = realloc(iids->callstacks, new_cap * sizeof(*iids->callstacks));
			iids->cap = new_cap;
		}
		iids->callstacks[iids->cnt].iid = iid;
		iids->callstacks[iids->cnt].frame_cnt = 0;
		iids->callstacks[iids->cnt].frame_ids = NULL;
		cs = &iids->callstacks[iids->cnt];

		iids->cnt += 1;
	}

	cs->frame_ids = realloc(cs->frame_ids, (cs->frame_cnt + 1) * sizeof(*cs->frame_ids));
	cs->frame_ids[cs->frame_cnt] = frame_iid;
	cs->frame_cnt++;
}

static pb_field_iter_t trace_pkt_it;

static void enc_trace_packet(pb_ostream_t *stream, TracePacket *msg)
{
	if (!pb_encode_tag_for_field(stream, &trace_pkt_it)) {
		fprintf(stderr, "Failed to encode Trace.packet field tag!\n");
		exit(1);
	}
	if (!pb_encode_submessage(stream, perfetto_protos_TracePacket_fields, msg)) {
		fprintf(stderr, "Failed to encode TracePacket value!\n");
		exit(1);
	}
}
/*
 * HIGH-LEVEL TRACE RECORD EMITTING INTERFACES
 */
struct emit_state {
	TracePacket pb;
	struct pb_anns anns;
};

static __thread struct emit_state em;
static __thread pb_ostream_t *cur_stream;

__unused
static void emit_kv_str(pb_iid key_iid, const char *key, pb_iid value_iid, const char *value)
{
	anns_add_str(&em.anns, key_iid, key, value_iid, value);
}

__unused
__attribute__((format(printf, 3, 4)))
static void emit_kv_fmt(pb_iid key_iid, const char *key, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	anns_add_str(&em.anns, key_iid, key, IID_NONE, vsfmt(fmt, ap));

	va_end(ap);
}

__unused
static void emit_kv_int(pb_iid key_iid, const char *key, int64_t value)
{
	anns_add_int(&em.anns, key_iid, key, value);
}

__unused
static void emit_kv_float(pb_iid key_iid, const char *key, const char *fmt, double value)
{
	anns_add_double(&em.anns, key_iid, key, value);
}

struct emit_rec { bool done; };

static void emit_cleanup(struct emit_rec *r)
{
	enc_trace_packet(cur_stream, &em.pb);
}

/*
 * SYMBOLIZATION
 */
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
static void show_stack_trace(struct blaze_symbolizer *symbolizer, __u64 *stack, int stack_sz, pid_t pid)
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

static const struct perf_counter_def perf_counter_defs[] = {
	{ "cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 1e-3, "cpu_cycles_kilo", IID_ANNK_PERF_CPU_CYCLES },
	{ "cpu-insns", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, 1e-3, "cpu_insns_kilo", IID_ANNK_PERF_CPU_INSNS },
	{ "cache-hits", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES, 1e-3, "cache_hits_kilo", IID_ANNK_PERF_CACHE_HITS },
	{ "cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, 1e-3, "cache_misses_kilo", IID_ANNK_PERF_CACHE_MISSES },
	{ "stall-cycles-fe", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, 1e-3, "stalled_cycles_fe_kilo", IID_ANNK_PERF_STALL_CYCLES_FE },
	{ "stall-cycles-be", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND, 1e-3, "stalled_cycles_be_kilo", IID_ANNK_PERF_STALL_CYCLES_BE },
	{},
};

struct task_state {
	int tid, pid;
	pb_iid name_iid;
	pb_iid rename_iid;
	char comm[TASK_COMM_FULL_LEN];
	/* task renames */
	__u64 rename_ts;
	char old_comm[TASK_COMM_FULL_LEN];
	/* perf counters */
	__u64 oncpu_ts;
	struct perf_counters oncpu_ctrs;
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
	if (env.run_dur_ms) {
		exiting = true;
		return;
	}
}

static void sig_term(int sig)
{
	exiting = true;
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

enum task_kind {
	TASK_NORMAL,
	TASK_IDLE,
	TASK_KWORKER,
	TASK_KTHREAD,
};

#define TRACK_UUID_IDLE		2000000000ULL
#define TRACK_UUID_KWORKER	2000000001ULL
#define TRACK_UUID_KTHREAD	2000000002ULL

#define TRACK_RANK_IDLE		-3
#define TRACK_RANK_KWORKER	-2
#define TRACK_RANK_KTHREAD	-1

static enum task_kind task_kind(const struct wprof_task *t)
{
	if (t->pid == 0)
		return TASK_IDLE;
	else if (t->flags & PF_WQ_WORKER)
		return TASK_KWORKER;
	else if (t->flags & PF_KTHREAD)
		return TASK_KTHREAD;
	else
		return TASK_NORMAL;
}

static int task_tid(const struct wprof_task *t)
{
	return t->pid ? t->tid : 0;
}

static int track_tid(const struct wprof_task *t)
{
	return t->pid ? t->tid : (-t->tid - 1);
}

static int track_pid(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pid;
	case TASK_IDLE:
		return TRACK_UUID_IDLE;
	case TASK_KWORKER:
		return TRACK_UUID_KWORKER;
	case TASK_KTHREAD:
		return TRACK_UUID_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in track_pid(): %d\n", kind);
		exit(1);
	}
}

static int track_thread_rank(const struct wprof_task *t)
{
	return task_tid(t);
}

static int track_process_rank(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pid + 1000000000ULL;
	case TASK_IDLE:
		return TRACK_RANK_IDLE;
	case TASK_KWORKER:
		return TRACK_RANK_KWORKER;
	case TASK_KTHREAD:
		return TRACK_RANK_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in track_process_rank(): %d\n", kind);
		exit(1);
	}
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

#define TRACK_NAME_IDLE "IDLE"
#define TRACK_NAME_KWORKER "KWORKER"
#define TRACK_NAME_KTHREAD "KTHREAD"

static const char *track_pcomm(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pcomm;
	case TASK_IDLE:
		return TRACK_NAME_IDLE;
	case TASK_KWORKER:
		return TRACK_NAME_KWORKER;
	case TASK_KTHREAD:
		return TRACK_NAME_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in track_pcomm(): %d\n", kind);
		exit(1);
	}
}

__unused
static const __u64 kind_track_uuid(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_UUID_IDLE;
	case TASK_KWORKER:
		return TRACK_UUID_KWORKER;
	case TASK_KTHREAD:
		return TRACK_UUID_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_uuid(): %d\n", kind);
		exit(1);
	}
}

__unused
static const char *kind_track_name(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_NAME_IDLE;
	case TASK_KWORKER:
		return TRACK_NAME_KWORKER;
	case TASK_KTHREAD:
		return TRACK_NAME_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_name(): %d\n", kind);
		exit(1);
	}
}

__unused
static const int kind_track_rank(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_RANK_IDLE;
	case TASK_KWORKER:
		return TRACK_RANK_KWORKER;
	case TASK_KTHREAD:
		return TRACK_RANK_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_rank(): %d\n", kind);
		exit(1);
	}
}

static uint64_t task_track_uuid(const struct wprof_task *t)
{
	return track_pid(t) * 1000000000ULL + track_tid(t);
}

static uint64_t process_track_uuid(const struct wprof_task *t)
{
	enum task_kind k = task_kind(t);

	if (k == TASK_NORMAL)
		return track_pid(t) * 1000000000ULL;
	return kind_track_uuid(k);
}

static const char *event_kind_str_map[] = {
	[EV_TIMER] = "TIMER",
	[EV_SWITCH_FROM] = "SWITCH_FROM",
	[EV_SWITCH_TO] = "SWITCH_TO",
	[EV_WAKEUP_NEW] = "WAKEUP_NEW",
	[EV_WAKEUP] = "WAKEUP",
	[EV_WAKING] = "WAKING",
	[EV_HARDIRQ_EXIT] = "HARDIRQ_EXIT",
	[EV_SOFTIRQ_EXIT] = "SOFTIRQ_EXIT",
	[EV_WQ_END] = "WQ_END",
	[EV_FORK] = "FORK",
	[EV_EXEC] = "EXEC",
	[EV_TASK_RENAME] = "TASK_RENAME",
	[EV_TASK_EXIT] = "TASK_EXIT",
	[EV_TASK_FREE] = "TASK_FREE",
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
					pb_iid name_iid, const char *name)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = task_track_uuid(t),
			PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
			PB_NAME(TrackEvent, name_field, name_iid, name),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_instant(ts, t, name_iid, name)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, t, name_iid, name);						\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_slice_point_pre(__u64 ts, const struct wprof_task *t,
					    pb_iid name_iid, const char *name,
					    pb_iid cat_iid, const char *category,
					    bool start)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = task_track_uuid(t),
			PB_INIT(type) = start ? perfetto_protos_TrackEvent_Type_TYPE_SLICE_BEGIN
					      : perfetto_protos_TrackEvent_Type_TYPE_SLICE_END,
			.category_iids = cat_iid ? PB_STRING_IID(cat_iid) : PB_NONE,
			.categories = cat_iid ? PB_NONE : PB_STRING(category),
			PB_NAME(TrackEvent, name_field, name_iid, name),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	/* allow explicitly not providing the name */
	if (!name_iid && !name)
		em.pb.data.track_event.which_name_field = 0;
	/* end slice points don't need to repeat the name */
	if (!start)
		em.pb.data.track_event.which_name_field = 0;
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_slice_point(ts, t, name_iid, name, cat_iid, category, start)			\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, t, name_iid, name, cat_iid, category, start);		\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_counter_pre(__u64 ts, const struct wprof_task *t,
					pb_iid name_iid, const char *name)
{
	/* TODO: support counters */
	return (struct emit_rec){ .done = true };
}

#define emit_counter(ts, t, name_iid, name)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_counter_pre(ts, t, name_iid, name);						\
	     !___r.done; ___r.done = true)

struct pb_clock {
	uint32_t clock_id;
	uint64_t timestamp;
};

static bool enc_clock(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_clock **clocks = *arg;

	while (*clocks) {
		const struct pb_clock *clock = *clocks;
		perfetto_protos_ClockSnapshot_Clock pb = {
			PB_INIT(clock_id) = clock->clock_id,
			PB_INIT(timestamp) = clock->timestamp,
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_ClockSnapshot_Clock_fields, &pb))
			return false;
		clocks++;
	}
	return true;
}

#define PB_CLOCK(s) ((pb_callback_t){{.encode=enc_clock}, (void *)(s)})

__unused
static void emit_clock_snapshot(pb_ostream_t *stream)
{
	struct pb_clock boot_clock = {
		.clock_id = perfetto_protos_ClockSnapshot_Clock_BuiltinClocks_BOOTTIME,
		.timestamp = 0,
	};
	struct pb_clock mono_clock = {
		.clock_id = perfetto_protos_ClockSnapshot_Clock_BuiltinClocks_MONOTONIC,
		.timestamp = env.sess_start_ts,
	};
	struct pb_clock *clocks[] = { &boot_clock, &mono_clock, NULL };
	TracePacket pb = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_clock_snapshot) = { .clock_snapshot = {
			PB_INIT(primary_trace_clock) = perfetto_protos_BuiltinClock_BUILTIN_CLOCK_MONOTONIC,
			.clocks = PB_CLOCK(clocks),
		}},
	};
	enc_trace_packet(stream, &pb);
}

static int init_protobuf(pb_ostream_t *stream)
{
	if (!pb_field_iter_begin(&trace_pkt_it, perfetto_protos_Trace_fields, NULL)) {
		fprintf(stderr, "Failed to start Trace fields iterator!\n");
		return -1;
	}
	if (!pb_field_iter_find(&trace_pkt_it, 1)) {
		fprintf(stderr, "Failed to find Trace field!\n");
		return -1;
	}

	//emit_clock_snapshot(stream);

	/* emit fake instant event to establish strict zero timestamp */
	TracePacket ev_pb = {
		PB_INIT(timestamp) = 0,
		PB_TRUST_SEQ_ID(),
		PB_INIT(sequence_flags) = perfetto_protos_TracePacket_SequenceFlags_SEQ_INCREMENTAL_STATE_CLEARED,
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
			PB_ONEOF(name_field, TrackEvent_name) = { .name = PB_STRING("START") },
		}},
		PB_INIT(interned_data) = {
			.event_categories = PB_STR_IID_RANGE(CAT_START_IID, CAT_END_IID),
			.event_names = PB_STR_IID_RANGE(NAME_START_IID, NAME_END_IID),
			.debug_annotation_names = PB_STR_IID_RANGE(ANNK_START_IID, ANNK_END_IID),
			.debug_annotation_string_values = PB_STR_IID_RANGE(ANNV_START_IID, ANNV_END_IID),
		},
	};
	enc_trace_packet(stream, &ev_pb);

	if (env.pb_debug_interns) {
		struct { const char *name; int start, end; } ranges[] = {
			{"category", CAT_START_IID, CAT_END_IID},
			{"event_name", NAME_START_IID, NAME_END_IID},
			{"ann_name", ANNK_START_IID, ANNK_END_IID},
			{"ann_value", ANNV_START_IID, ANNV_END_IID},
		};

		for (int k = 0; k < ARRAY_SIZE(ranges); k++)
			for (int i = ranges[k].start; i < ranges[k].end; i++)
				fprintf(stderr, "% 3d: %-20s [%s]\n", i, pb_strs[i], ranges[k].name);
	}

	return 0;
}

static bool kind_track_emitted[] = {
	[TASK_IDLE] = false,
	[TASK_KWORKER] = false,
	[TASK_KTHREAD] = false,
};

static void emit_kind_track_descr(pb_ostream_t *stream, enum task_kind k)
{
	__u64 track_uuid = kind_track_uuid(k);
	const char *track_name = kind_track_name(k);
	int track_rank = kind_track_rank(k);

	TracePacket desc_pb = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_uuid,
			PB_INIT(process) = {
				PB_INIT(pid) = track_uuid,
				.process_name = PB_STRING(track_name),
			},
			PB_INIT(child_ordering) = k == TASK_KWORKER
				? perfetto_protos_TrackDescriptor_ChildTracksOrdering_LEXICOGRAPHIC
				: perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_rank,
		}},
	};
	enc_trace_packet(stream, &desc_pb);
}

static void emit_process_track_descr(pb_ostream_t *stream, const struct wprof_task *t, pb_iid pname_iid)
{
	const char *pcomm;

	pcomm = track_pcomm(t);
	TracePacket proc_desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = process_track_uuid(t),
			PB_INIT(process) = {
				PB_INIT(pid) = track_pid(t),
				.process_name = PB_STRING(pcomm),
			},
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_process_rank(t),
		}},
		PB_INIT(interned_data) = {
			.event_names = PB_STR_IID(pname_iid, pcomm),
			.debug_annotation_string_values = PB_STR_IID(pname_iid, pcomm),
		}
	};
	enc_trace_packet(stream, &proc_desc);
}

static void emit_thread_track_descr(pb_ostream_t *stream, const struct wprof_task *t, pb_iid tname_iid, const char *comm)
{
	TracePacket thread_desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = task_track_uuid(t),
			PB_INIT(thread) = {
				PB_INIT(tid) = track_tid(t),
				PB_INIT(pid) = track_pid(t),
				.thread_name = PB_STRING(comm),
			},
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_thread_rank(t),
		}},
		PB_INIT(interned_data) = {
			.event_names = PB_STR_IID(tname_iid, comm),
			.debug_annotation_string_values = PB_STR_IID(tname_iid, comm),
		}
	};
	enc_trace_packet(stream, &thread_desc);
}

struct str_iid_domain {
	struct hashmap *str_iids;
	int next_str_iid;
	const char *domain_desc;
};

static pb_iid str_iid_for(struct str_iid_domain *d, const char *s, bool *new_iid, const char **out_str)
{
	long iid;
	char *sdup;
	struct hashmap_entry *entry;

	hashmap__for_each_key_entry(d->str_iids, entry, (long)s) {
		iid = entry->value;
		if (new_iid)
			*new_iid = false;
		if (out_str)
			*out_str = entry->pkey;
		return iid;
	}

	sdup = strdup(s);
	iid = d->next_str_iid++;

	hashmap__set(d->str_iids, sdup, iid, NULL, NULL);

	if (env.pb_debug_interns)
		fprintf(stderr, "%03ld: %-20s [%s]\n", iid, sdup, d->domain_desc);
	if (new_iid)
		*new_iid = true;
	if (out_str)
		*out_str = sdup;

	return iid;
}

struct stack_trace_iids {
	struct pb_str_iids func_names;
	struct pb_frame_iids frames;
	struct pb_callstack_iids callstacks;
	struct pb_mapping_iids mappings;
};

struct stack_trace_index {
	int orig_idx;
	int pid;
	int start_frame_idx;
	int frame_cnt;
	int callstack_iid;
	int kframe_cnt;
	bool combine;
};

struct stack_frame_index {
	int pid;
	int orig_idx;
	int orig_pid;
	__u64 addr;
	const struct blaze_sym *sym;
	int frame_cnt;
	/* if sym has no inlined frames */
	int frame_iid;
	/* if sym has inlined frames */
	int *frame_iids;
};

struct worker_state {
	struct str_iid_domain name_iids;

	FILE *trace;
	pb_ostream_t stream;

	char *dump_path;
	FILE *dump;

	struct stack_frame_index *sframe_idx;
	size_t sframe_cap, sframe_cnt;
	struct stack_trace_index *strace_idx;
	size_t strace_cap, strace_cnt;
	struct stack_trace_iids strace_iids;
	struct str_iid_domain fname_iids;
	size_t next_stack_trace_id;

	/* stats */
	__u64 rb_handled_cnt;
	__u64 rb_handled_sz;
	__u64 rb_ignored_cnt;
	__u64 rb_ignored_sz;
} __attribute__((aligned(64)));

static struct worker_state *worker;

static struct task_state *task_state(struct worker_state *w, struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	if (!hashmap__find(tasks, key, &st)) {
		st = calloc(1, sizeof(*st));
		st->tid = t->tid;
		st->pid = t->pid;
		strlcpy(st->comm, t->comm, sizeof(st->comm));
		st->name_iid = str_iid_for(&w->name_iids, t->comm, NULL, NULL);

		hashmap__set(tasks, key, st, NULL, NULL);

		/* Proactively setup process group leader tasks info */
		enum task_kind tkind = task_kind(t);
		if (tkind == TASK_NORMAL) {
			unsigned long pkey = t->pid;
			struct task_state *pst = NULL;

			if (t->tid == t->pid) {
				/* we are the new task group leader */
				emit_process_track_descr(&w->stream, t, str_iid_for(&w->name_iids, t->pcomm, NULL, NULL));
			} else if (!hashmap__find(tasks, pkey, &pst)) {
				/* no task group leader task yet */
				pst = calloc(1, sizeof(*st));
				pst->tid = pst->pid = t->pid;
				strlcpy(pst->comm, t->pcomm, sizeof(pst->comm));
				pst->name_iid = str_iid_for(&w->name_iids, pst->comm, NULL, NULL);

				hashmap__set(tasks, pkey, pst, NULL, NULL);

				struct wprof_task pt = {
					.tid = t->pid,
					.pid = t->pid,
					.flags = 0,
				};
				strlcpy(pt.comm, t->pcomm, sizeof(pt.comm));
				strlcpy(pt.pcomm, t->pcomm, sizeof(pt.comm));

				emit_process_track_descr(&w->stream, &pt, pst->name_iid);
				emit_thread_track_descr(&w->stream, &pt, pst->name_iid, pst->comm);
			} else {
				/* otherwise someone already emitted descriptors */
			}
		} else if (!kind_track_emitted[tkind]) {
			emit_kind_track_descr(&w->stream, tkind);
			kind_track_emitted[tkind] = true;
		}

		emit_thread_track_descr(&w->stream, t, st->name_iid, t->comm);
	}

	return st;
}

static void task_state_delete(struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	hashmap__delete(tasks, key, NULL, &st);

	free(st);
}

/* Receive events from the ring buffer. */
static int handle_event(void *ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	struct worker_state *w = ctx;

	if (exiting)
		return -EINTR;

	if (env.sess_end_ts && (long long)(env.sess_end_ts - e->ts) <= 0) {
		w->rb_ignored_cnt++;
		w->rb_ignored_sz += size;
		return 0;
	}

	if (fwrite(&size, sizeof(size), 1, w->dump) != 1 ||
	    fwrite(data, size, 1, w->dump) != 1) {
		int err = -errno;

		fprintf(stderr, "Failed to write raw data dump: %d\n", err);
		return err;
	}

	w->rb_handled_cnt++;
	w->rb_handled_sz += size;

	return 0;
}

static bool stack_trace_eq(const struct stack_trace_index *x,
			   const struct stack_trace_index *y,
			   const struct worker_state *w)
{
	if (x->pid != y->pid)
		return false;

	if (x->frame_cnt != y->frame_cnt)
		return false;

	for (int i = 0; i < x->frame_cnt; i++) {
		__u64 xa = w->sframe_idx[x->start_frame_idx + i].addr;
		__u64 ya = w->sframe_idx[y->start_frame_idx + i].addr;

		if (xa != ya)
			return false;
	}

	return true;
}

static int stack_trace_cmp_by_content(const void *a, const void *b, void *ctx)
{
	const struct worker_state *w = ctx;
	const struct stack_trace_index *x = a, *y = b;

	if (x->pid != y->pid)
		return x->pid < y->pid ? -1 : 1;

	if (x->frame_cnt != y->frame_cnt)
		return x->frame_cnt < y->frame_cnt ? -1 : 1;

	for (int i = 0; i < x->frame_cnt; i++) {
		__u64 xa = w->sframe_idx[x->start_frame_idx + i].addr;
		__u64 ya = w->sframe_idx[y->start_frame_idx + i].addr;

		if (xa != ya)
			return xa < ya ? -1 : 1;
	}

	return x->start_frame_idx < y->start_frame_idx ? -1 : 1;
}

static int stack_trace_cmp_by_orig_idx(const void *a, const void *b)
{
	const struct stack_trace_index *x = a, *y = b;

	return x->orig_idx < y->orig_idx ? -1 : 1;
}

static int stack_frame_cmp_by_pid_addr(const void *a, const void *b)
{
	const struct stack_frame_index *x = a, *y = b;

	if (x->pid != y->pid)
		return x->pid < y->pid ? -1 : 1;
	if (x->addr != y->addr)
		return x->addr < y->addr ? -1 : 1;
	return x->orig_idx < y->orig_idx ? -1 : 1;
}

static int stack_frame_cmp_by_orig_idx(const void *a, const void *b)
{
	const struct stack_frame_index *x = a, *y = b;

	return x->orig_idx < y->orig_idx ? -1 : 1;
}

static void stack_trace_append(struct worker_state *w, int pid, int start_frame_idx, int frame_cnt, bool combine)
{
	if (w->strace_cnt == w->strace_cap) {
		size_t new_cap = w->strace_cnt < 64 ? 64 : w->strace_cnt * 4 / 3;

		w->strace_idx = realloc(w->strace_idx, new_cap * sizeof(*w->strace_idx));
		w->strace_cap = new_cap;
	}
	w->strace_idx[w->strace_cnt] = (struct stack_trace_index){
		.orig_idx = w->strace_cnt,
		.pid = pid,
		.start_frame_idx = start_frame_idx,
		.frame_cnt = frame_cnt,
		.combine = combine,
	};

	w->strace_cnt++;
}

static void stack_frame_append(struct worker_state *w, int pid, int orig_pid, __u64 addr)
{
	if (w->sframe_cnt == w->sframe_cap) {
		size_t new_cap = w->sframe_cnt < 256 ? 256 : w->sframe_cnt * 4 / 3;

		w->sframe_idx = realloc(w->sframe_idx, new_cap * sizeof(*w->sframe_idx));
		w->sframe_cap = new_cap;
	}
	w->sframe_idx[w->sframe_cnt] = (struct stack_frame_index){
		.orig_idx = w->sframe_cnt,
		.pid = pid,
		.orig_pid = orig_pid,
		.addr = addr,
		.sym = NULL,
	};

	w->sframe_cnt++;
}

static int process_event_stack_trace(struct worker_state *w, struct wprof_event *e, size_t size)
{
	struct stack_trace *tr;
	const __u64 *kaddrs = NULL, *uaddrs = NULL;
	int ucnt = 0, kcnt = 0;


	if (e->sz == size) /* no variable-length part of event */
		return 0;

	tr = (void *)e + e->sz;

	if (tr->kstack_sz > 0) {
		kcnt = tr->kstack_sz / 8;
		kaddrs = tr->addrs;
	}

	if (tr->ustack_sz > 0) {
		ucnt = tr->ustack_sz / 8;
		uaddrs = tr->addrs + kcnt;
	}

	/* we need user stack to come in front of kernel stack for further
	 * Perfetto-related stack merging to work correctly
	 */
	if (uaddrs) {
		stack_trace_append(w, e->task.pid, w->sframe_cnt, ucnt, false /*!combine*/);
		for (int i = ucnt - 1; i >= 0; i--)
			stack_frame_append(w, e->task.pid, e->task.pid, uaddrs[i]);
	}

	if (kaddrs) {
		stack_trace_append(w, 0, w->sframe_cnt, kcnt, !!uaddrs /*combine*/);
		for (int i = kcnt - 1; i >= 0; i--)
			stack_frame_append(w, 0 /* kernel */, e->task.pid, kaddrs[i]);
	}

	return 0;
}

static int process_stack_traces(struct worker_state *w, const void *dump_mem, size_t dump_sz)
{
	struct wprof_event *rec;
	size_t rec_sz, off, idx, kaddr_cnt = 0, uaddr_cnt = 0, unkn_cnt = 0, comb_cnt = 0;
	__u64 start_ns = ktime_now_ns();
	int err;

	if (!env.stack_traces)
		return 0;
	if (!w->trace)
		goto skip_trace;

	fprintf(stderr, "Symbolizing...\n");

	off = 0;
	idx = 0;
	while (off < dump_sz) {
		rec_sz = *(size_t *)(dump_mem + off);
		rec = (struct wprof_event *)(dump_mem + off + sizeof(rec_sz));
		err = process_event_stack_trace(w, rec, rec_sz);
		if (err) {
			fprintf(stderr, "Failed to pre-process stack trace for event #%zu (kind %d, size %zu, offset %zu): %d\n",
				idx, rec->kind, rec_sz, off, err);
			return err;
		}
		off += sizeof(rec_sz) + rec_sz;
		idx += 1;
	}

	/* group by pid+addr */
	qsort(w->sframe_idx, w->sframe_cnt, sizeof(*w->sframe_idx), stack_frame_cmp_by_pid_addr);

	__u64 symb_start_ns = ktime_now_ns();
	__u64 *addrs = NULL;
	size_t addr_cap = 0;
	for (int start = 0, end = 1; end <= w->sframe_cnt; end++) {
		if (end < w->sframe_cnt && w->sframe_idx[start].pid == w->sframe_idx[end].pid)
			continue;

		if (end - start > addr_cap) {
			addr_cap = end - start;
			addrs = realloc(addrs, sizeof(*addrs) * addr_cap);
		}

		size_t addr_cnt = 0;
		for (int i = 0; i < end - start; i++) {
			__u64 addr = w->sframe_idx[start + i].addr;

			if (addr_cnt > 0 && addr == addrs[addr_cnt - 1])
				continue;

			addrs[addr_cnt] = addr;
			addr_cnt += 1;
		}

		struct blaze_symbolizer_opts blaze_opts = {
			.type_size = sizeof(struct blaze_symbolizer_opts),
			.auto_reload = false,
			.code_info = false,
			.inlined_fns = true,
			.demangle = true,
		};
		struct blaze_symbolizer *symbolizer = blaze_symbolizer_new_opts(&blaze_opts);
		if (!symbolizer) {
			enum blaze_err berr = blaze_err_last();
			const char *berr_str = blaze_err_str(berr);

			fprintf(stderr, "Failed to create a symbolizer: %s (%d)\n", berr_str, berr);
			return berr;
		}

		/* symbolize [start .. end - 1] range */
		const struct blaze_syms *syms;
		if (w->sframe_idx[start].pid == 0) { /* kernel addresses */
			struct blaze_symbolize_src_kernel src = {
				.type_size = sizeof(src),
				.debug_syms = true,
			};
			syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			kaddr_cnt += addr_cnt;
		} else {
			struct blaze_symbolize_src_process src = {
				.type_size = sizeof(src),
				.pid = w->sframe_idx[start].pid,
				.map_files = true,
				.debug_syms = true,
			};
			syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			if (!syms && blaze_err_last() != BLAZE_ERR_NOT_FOUND) {
				src.debug_syms = false;
				syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			}
			uaddr_cnt += addr_cnt;
		}
		if (!syms) {
			enum blaze_err berr = blaze_err_last();
			const char *berr_str = blaze_err_str(berr);

			unkn_cnt += end - start;

			fprintf(stderr, "Symbolization failed for PID %d: %s (%d)\n",
				w->sframe_idx[start].pid, berr_str, berr);
		} else {
			for (int i = 0, j = 0; i < end - start; i++) {
				if (i > 0 && w->sframe_idx[start + i - 1].addr == w->sframe_idx[start + i].addr) {
					w->sframe_idx[start + i].sym = w->sframe_idx[start + i - 1].sym;
				} else {
					w->sframe_idx[start + i].sym = &syms->syms[j];
					j++;
				}
			}
		}

#if 0
		int pid_of_interest = 869620;
		for (int k = start; k < end; k++) {
			struct stack_frame_index *f = &w->sframe_idx[k];

			if (f->sym && f->sym->name && f->orig_pid != pid_of_interest)
				continue;

			if (k > start && w->sframe_idx[k - 1].pid == f->pid &&
			    w->sframe_idx[k - 1].addr == f->addr)
				continue;

			if (!f->sym) {
				printf("FAILED SYMBOLIZATION PID %d (ORIG PID %d): %s\n",
					f->pid, f->orig_pid, blaze_err_str(blaze_err_last()));
			} else {
				if (f->sym->name == NULL) {
					printf("[PID %d] %016llx: <no-symbol>\n", f->orig_pid, f->addr);
					continue;
				}

				print_frame(f->sym->name, f->addr, f->sym->addr, f->sym->offset, &f->sym->code_info);

				for (int j = 0; j < f->sym->inlined_cnt; j++) {
					printf("[PID %d] ", f->orig_pid);
					print_frame(f->sym->name, 0, 0, 0, &f->sym->inlined[j].code_info);
				}
			}
		}
#endif
		start = end;
		blaze_symbolizer_free(symbolizer);
	}
	free(addrs);

	__u64 symb_end_ns = ktime_now_ns();
	fprintf(stderr, "Symbolized %zu user and %zu kernel unique addresses (%zu total, failed %zu) in %.3lfms.\n",
		uaddr_cnt, kaddr_cnt, uaddr_cnt + kaddr_cnt, unkn_cnt,
		(symb_end_ns - symb_start_ns) / 1000000.0);

	/* XXX: mapping singleton */
	pb_iid mapping_iid = 1;
	append_mapping_iid(&w->strace_iids.mappings, mapping_iid, 0, 0x7fffffffffffffff, 0);

	w->fname_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = 1,
		.domain_desc = "func_name",
	};

	pb_iid unkn_iid = str_iid_for(&w->fname_iids, "<unknown>", NULL, NULL);
	append_str_iid(&w->strace_iids.func_names, unkn_iid, "<unknown>");

	char sym_buf[1024];
	size_t frames_deduped = 0, frames_total = 0, frames_failed = 0;
	pb_iid frame_iid = 1;
	for (int i = 0; i < w->sframe_cnt; i++) {
		struct stack_frame_index *f = &w->sframe_idx[i];

		if (i > 0 && w->sframe_idx[i - 1].pid == f->pid && w->sframe_idx[i - 1].addr == f->addr) {
			f->frame_cnt = w->sframe_idx[i - 1].frame_cnt;
			f->frame_iid = w->sframe_idx[i - 1].frame_iid;
			f->frame_iids = w->sframe_idx[i - 1].frame_iids;
			frames_deduped += f->frame_cnt;
			frames_total += f->frame_cnt;
			if (!f->sym || !f->sym->name)
				frames_failed += f->frame_cnt;
			continue;
		}

		f->frame_cnt = f->sym ? 1 + f->sym->inlined_cnt : 1;
		frames_total += f->frame_cnt;
		if (!f->sym || !f->sym->name)
			frames_failed += 1;
		if (f->frame_cnt > 1)
			f->frame_iids = calloc(f->frame_cnt, sizeof(*f->frame_iids));

		for (int j = 0; j < f->frame_cnt; j++) {
			const char *sym_name;
			size_t offset;
			pb_iid fname_iid = unkn_iid;
			bool new_iid = false;

			offset = j == 0 ? (f->sym && f->sym->name ? f->sym->offset : f->addr) : 0;
			sym_name = j == 0 ? (f->sym ? f->sym->name : NULL) : f->sym->inlined[j - 1].name;

			if (sym_name) {
				snprintf(sym_buf, sizeof(sym_buf),
					 "[%c] %s%s", f->pid ? 'U' : 'K', sym_name, j > 0 ? "inlined" : "");
				sym_name = sym_buf;
			}

			if (sym_name && (fname_iid = str_iid_for(&w->fname_iids, sym_name, &new_iid, &sym_name)) && new_iid)
				append_str_iid(&w->strace_iids.func_names, fname_iid, sym_name);

			append_frame_iid(&w->strace_iids.frames, frame_iid, mapping_iid, fname_iid, offset);

			if (f->frame_iids)
				f->frame_iids[j] = frame_iid;
			else
				f->frame_iid = frame_iid;

			frame_iid += 1;
		}
	}

	qsort(w->sframe_idx, w->sframe_cnt, sizeof(*w->sframe_idx), stack_frame_cmp_by_orig_idx);

	/* combine kernel and user stack traces into one callstack */
	comb_cnt = 0;
	for (int i = 0; i < w->strace_cnt; i++) {
		struct stack_trace_index *s = &w->strace_idx[i];

		if (s->combine) {
			struct stack_trace_index *c = &w->strace_idx[comb_cnt - 1];

			c->kframe_cnt = s->frame_cnt;
			c->frame_cnt += s->frame_cnt;
		} else {
			w->strace_idx[comb_cnt] = *s;
			comb_cnt += 1;
		}
	}
	w->strace_cnt = comb_cnt;

	/* dedup and assign callstack IIDs */
	qsort_r(w->strace_idx, w->strace_cnt, sizeof(*w->strace_idx), stack_trace_cmp_by_content, w);

	size_t callstacks_deduped = 0;
	pb_iid trace_iid = 1;
	for (int i = 0; i < w->strace_cnt; i++) {
		struct stack_trace_index *t = &w->strace_idx[i];
		
		if (i > 0 && stack_trace_eq(&w->strace_idx[i - 1], t, w)) {
			t->callstack_iid = w->strace_idx[i - 1].callstack_iid;
			callstacks_deduped += 1;
			continue;
		}

		for (int j = 0; j < t->frame_cnt; j++) {
			const struct stack_frame_index *f = &w->sframe_idx[t->start_frame_idx + j];

			for (int k = 0; k < f->frame_cnt; k++) {
				pb_iid frame_iid = f->frame_cnt > 1 ? f->frame_iids[k] : f->frame_iid;

				append_callstack_frame_iid(&w->strace_iids.callstacks, trace_iid, frame_iid);
			}
		}

		t->callstack_iid = trace_iid;
		trace_iid += 1;
	}

	qsort(w->sframe_idx, w->sframe_cnt, sizeof(*w->sframe_idx), stack_frame_cmp_by_orig_idx);
	qsort(w->strace_idx, w->strace_cnt, sizeof(*w->strace_idx), stack_trace_cmp_by_orig_idx);

	ssize_t pb_sz_before = file_size(w->trace);
	TracePacket ev_pb = {
		PB_INIT(timestamp) = 0,
		PB_TRUST_SEQ_ID(),
		PB_INIT(interned_data) = {
			.function_names = PB_STR_IIDS(&w->strace_iids.func_names),
			.frames = PB_FRAMES(&w->strace_iids.frames),
			.callstacks = PB_CALLSTACKS(&w->strace_iids.callstacks),
			.mappings = PB_MAPPINGS(&w->strace_iids.mappings),
		},
	};
	enc_trace_packet(&w->stream, &ev_pb);
	ssize_t pb_sz_after = file_size(w->trace);
	fprintf(stderr, "Emitted %.3lfMB of stack traces data.\n", (pb_sz_after - pb_sz_before) / 1024.0 / 1024.0);

skip_trace:
	__u64 end_ns = ktime_now_ns();
	fprintf(stderr, "Symbolized %zu stack traces with %zu frames (%zu traces and %zu frames deduped, %zu unknown frames) in %.3lfms.\n",
		w->strace_cnt, frames_total,
		callstacks_deduped, frames_deduped,
		frames_failed,
		(end_ns - start_ns) / 1000000.0);

	return 0;
}

static int event_stack_trace_id(struct worker_state *w, const struct wprof_event *e, size_t size)
{
	struct stack_trace *tr;

	if (e->sz == size) /* no variable-length part of event */
		return -1;

	tr = (void *)e + e->sz;
	if (tr->kstack_sz > 0 || tr->ustack_sz > 0) {
		w->next_stack_trace_id += 1;
		return w->next_stack_trace_id - 1;
	}

	return -1;
}

static int process_event(struct worker_state *w, struct wprof_event *e, size_t size)
{
	const char *status;
	struct task_state *st, *pst = NULL, *fst = NULL, *nst = NULL;
	int strace_id;

	st = task_state(w, &e->task);

	switch (e->kind) {
	case EV_TIMER:
		break;
	case EV_SWITCH_FROM:
		nst = task_state(w, &e->swtch_from.next);
		break;
	case EV_SWITCH_TO:
		/* init switched-from task state, if necessary */
		pst = task_state(w, &e->swtch_to.prev);
		st->oncpu_ctrs = e->swtch_to.ctrs;
		st->oncpu_ts = e->ts;
		break;
	case EV_FORK:
		/* init forked child task state */
		fst = task_state(w, &e->fork.child);
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

	strace_id = event_stack_trace_id(w, e, size);

	if (w->trace) {
		switch (e->kind) {
		case EV_TIMER:
			/* task keeps running on CPU */
			emit_instant(e->ts, &e->task, IID_NAME_TIMER, "TIMER") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			}

			TracePacket pb = (TracePacket) {
				PB_INIT(timestamp) = e->ts - env.sess_start_ts,
				PB_TRUST_SEQ_ID(),
				PB_ONEOF(data, TracePacket_perf_sample) = { .perf_sample = {
					PB_INIT(pid) = track_pid(&e->task),
					PB_INIT(tid) = track_tid(&e->task),
					PB_INIT(callstack_iid) = w->strace_idx[strace_id].callstack_iid,
				}},
			};
			enc_trace_packet(&w->stream, &pb);
			break;
		case EV_SWITCH_FROM: {
			const char *prev_name;
			pb_iid prev_name_iid;

			/* take into account task rename for switched-out task
			 * to maintain consistently named trace slice
			 */
			prev_name = st->rename_ts ? st->old_comm : st->comm;
			prev_name_iid = st->rename_ts ? st->rename_iid : st->name_iid;

			/* We are about to emit SLICE_END without
			 * corresponding SLICE_BEGIN ever being emitted;
			 * normally, Perfetto will just skip such SLICE_END
			 * and won't render anything, which is annoying and
			 * confusing. We want to avoid this, so we'll emit
			 * a fake SLICE_BEGIN with fake timestamp ZERO.
			 */
			if (st->oncpu_ts == 0) {
				emit_slice_point(env.sess_start_ts, &e->task,
						 prev_name_iid, prev_name,
						 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
					emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				}
			}

			emit_slice_point(e->ts, &e->task,
					 prev_name_iid, prev_name,
					 IID_CAT_ONCPU, "ONCPU", false /*!start*/) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);

				emit_kv_str(IID_ANNK_SWITCH_TO, "switch_to", nst->name_iid, e->swtch_from.next.comm);
				emit_kv_int(IID_ANNK_SWITCH_TO_TID, "switch_to_tid", task_tid(&e->swtch_from.next));
				emit_kv_int(IID_ANNK_SWITCH_TO_PID, "switch_to_pid", e->swtch_from.next.pid);

				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
					const struct perf_counters *st_ctrs = &st->oncpu_ctrs;
					const struct perf_counters *ev_ctrs = &e->swtch_from.ctrs;

					if (st_ctrs->val[i] && ev_ctrs->val[i]) {
						emit_kv_float(def->trace_name_iid, def->trace_name,
							      "%.6lf", (ev_ctrs->val[i] - st_ctrs->val[i]) * def->mul);
					}
				}

				if (st->rename_ts)
					emit_kv_str(IID_ANNK_RENAMED_TO, "renamed_to", IID_NONE, e->task.comm);
			}

			/*
			if (env.cpu_counters && env.breakout_counters &&
			    st->oncpu_ts && st->cpu_cycles && e->swtch_from.cpu_cycles) {
				emit_counter(st->oncpu_ts, &e->task, IID_NONE, "cpu_cycles") {
					emit_kv_float(IID_NONE, "mega_cycles", "%.6lf",
						      (e->swtch_from.cpu_cycles - st->cpu_cycles) / 1000000.0);
				}
				emit_counter(e->ts, &e->task, IID_NONE, "cpu_cycles") {
					emit_kv_float(IID_NONE, "mega_cycles", "%.6lf", 0.0);
				}
			}
			*/

			TracePacket pb = (TracePacket) {
				PB_INIT(timestamp) = e->ts - env.sess_start_ts,
				PB_TRUST_SEQ_ID(),
				PB_ONEOF(data, TracePacket_perf_sample) = { .perf_sample = {
					PB_INIT(pid) = track_pid(&e->task),
					PB_INIT(tid) = track_tid(&e->task),
					PB_INIT(callstack_iid) = w->strace_idx[strace_id].callstack_iid,
				}},
			};
			enc_trace_packet(&w->stream, &pb);

			if (st->rename_ts) {
				st->rename_ts = 0;
				st->name_iid = st->rename_iid;
			}
			break;
		}
		case EV_SWITCH_TO: {
			struct task_state *wst = NULL;

			if (e->swtch_to.waking_ts) {
				wst = task_state(w, &e->swtch_to.waking);

				/* event on awaker's timeline */
				emit_instant(e->swtch_to.waking_ts, &e->swtch_to.waking,
					     e->swtch_to.waking_flags == WF_AWOKEN_NEW ? IID_NAME_WAKEUP_NEW : IID_NAME_WAKING,
					     e->swtch_to.waking_flags == WF_AWOKEN_NEW ? "WAKEUP_NEW" : "WAKING") {
					emit_kv_int(IID_ANNK_CPU, "cpu", e->swtch_to.waking_cpu);
					emit_kv_str(IID_ANNK_WAKING_TARGET, "waking_target", st->name_iid, e->task.comm);
					emit_kv_int(IID_ANNK_WAKING_TARGET_TID, "waking_target_tid", task_tid(&e->task));
					emit_kv_int(IID_ANNK_WAKING_TARGET_PID, "waking_target_pid", e->task.pid);
				}

				/* event on awoken's timeline */
				if (e->swtch_to.waking_cpu != e->cpu) {
					emit_instant(e->swtch_to.waking_ts, &e->task,
						     e->swtch_to.waking_flags == WF_AWOKEN_NEW ? IID_NAME_AWOKEN_NEW : IID_NAME_AWAKING,
						     e->swtch_to.waking_flags == WF_AWOKEN_NEW ? "AWOKEN_NEW" : "AWAKING") {
						emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
					}
				}
			}

			emit_slice_point(e->ts, &e->task, st->name_iid, e->task.comm,
					 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);

				if (e->swtch_to.waking_ts) {
					emit_kv_str(IID_ANNK_WAKING_BY, "waking_by", wst->name_iid, e->swtch_to.waking.comm);
					emit_kv_int(IID_ANNK_WAKING_BY_TID, "waking_by_tid", task_tid(&e->swtch_to.waking));
					emit_kv_int(IID_ANNK_WAKING_BY_PID, "waking_by_pid", e->swtch_to.waking.pid);
					emit_kv_str(IID_ANNK_WAKING_REASON, "waking_reason",
						    IID_NONE, waking_reason_str(e->swtch_to.waking_flags));
					emit_kv_int(IID_ANNK_WAKING_CPU, "waking_cpu", e->swtch_to.waking_cpu);
					emit_kv_float(IID_ANNK_WAKING_DELAY_US, "waking_delay_us",
						      "%.3lf", (e->ts - e->swtch_to.waking_ts) / 1000.0);
				}

				emit_kv_str(IID_ANNK_SWITCH_FROM, "switch_from", pst->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_SWITCH_FROM_TID, "switch_from_tid", task_tid(&e->swtch_to.prev));
				emit_kv_int(IID_ANNK_SWITCH_FROM_PID, "switch_from_pid", e->swtch_to.prev.pid);
			}

			if (env.breakout_counters && e->swtch_to.waking_ts) {
				emit_counter(e->ts, &e->task, IID_NONE, "waking_delay") {
					emit_kv_float(IID_NONE, "us", "%.3lf", (e->ts - e->swtch_to.waking_ts) / 1000.0);
				}
			}

			if (pst->rename_ts) {
				pst->rename_ts = 0;
				pst->name_iid = pst->rename_iid;
			}
			break;
		}
		case EV_FORK: {
			emit_instant(e->ts, &e->task, IID_NAME_FORKING, "FORKING") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_str(IID_ANNK_FORKED_INTO, "forked_into", fst->name_iid, e->fork.child.comm);
				emit_kv_int(IID_ANNK_FORKED_INTO_TID, "forked_into_tid", task_tid(&e->fork.child));
				emit_kv_int(IID_ANNK_FORKED_INTO_PID, "forked_into_pid", e->fork.child.pid);
			}
			emit_instant(e->ts, &e->fork.child, IID_NAME_FORKED, "FORKED") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_str(IID_ANNK_FORKED_FROM, "forked_from", st->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_FORKED_FROM_TID, "forked_from_tid", task_tid(&e->task));
				emit_kv_int(IID_ANNK_FORKED_FROM_PID, "forked_from_pid", e->task.pid);
			}
			break;
		}
		case EV_EXEC: {
			emit_instant(e->ts, &e->task, IID_NAME_EXEC, "EXEC") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_str(IID_ANNK_FILENAME, "filename", IID_NONE, e->exec.filename);
				if (e->task.tid != e->exec.old_tid)
					emit_kv_int(IID_ANNK_TID_CHANGED_FROM, "tid_changed_from", e->exec.old_tid);
			}
			break;
		}
		case EV_TASK_RENAME: {
			emit_instant(e->ts, &e->task, IID_NAME_RENAME, "RENAME") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_str(IID_ANNK_OLD_NAME, "old_name", IID_NONE, e->task.comm);
				emit_kv_str(IID_ANNK_NEW_NAME, "new_name", IID_NONE, e->rename.new_comm);
			}

			st->rename_iid = str_iid_for(&w->name_iids, e->rename.new_comm, NULL, NULL);
			emit_thread_track_descr(&w->stream, &e->task, st->rename_iid, e->rename.new_comm);
			break;
		}
		case EV_TASK_EXIT:
			emit_instant(e->ts, &e->task, IID_NAME_EXIT, "EXIT") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			}
			break;
		case EV_TASK_FREE:
			emit_instant(e->ts, &e->task, IID_NAME_FREE, "FREE") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			}
			break;
		case EV_WAKEUP:
			emit_instant(e->ts, &e->task, IID_NAME_WAKEUP, "WAKEUP") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			}
			break;
		case EV_WAKEUP_NEW:
			emit_instant(e->ts, &e->task, IID_NAME_WAKEUP_NEW, "WAKEUP_NEW") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			}
			break;
		case EV_WAKING:
			emit_instant(e->ts, &e->task, IID_NAME_WAKING, "WAKING") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			}
			break;
		case EV_HARDIRQ_EXIT:
			emit_slice_point(e->hardirq.hardirq_ts, &e->task,
					 IID_NAME_HARDIRQ, "HARDIRQ",
					 IID_CAT_HARDIRQ, "HARDIRQ", true /* start */) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_IRQ, "irq", e->hardirq.irq);
				emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->hardirq.name);
			}
			emit_slice_point(e->ts, &e->task,
					 IID_NAME_HARDIRQ, "HARDIRQ",
					 IID_CAT_HARDIRQ, "HARDIRQ", false /* !start */) {
				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];

					emit_kv_float(def->trace_name_iid, def->trace_name,
						      "%.6lf", e->hardirq.ctrs.val[i] * def->mul);
				}
			}
			break;
		case EV_SOFTIRQ_EXIT: {
			pb_iid name_iid, act_iid;

			if (e->softirq.vec_nr >= 0 && e->softirq.vec_nr < NR_SOFTIRQS) {
				name_iid = IID_NAME_SOFTIRQ + e->softirq.vec_nr;
				act_iid = IID_ANNV_SOFTIRQ_ACTION + e->softirq.vec_nr;
			} else {
				name_iid = IID_NONE;
				act_iid = IID_NONE;
			}

			emit_slice_point(e->softirq.softirq_ts, &e->task,
					 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
					 IID_CAT_SOFTIRQ, "SOFTIRQ", true /* start */) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_str(IID_ANNK_ACTION, "action", act_iid, softirq_str(e->softirq.vec_nr));
			}

			emit_slice_point(e->ts, &e->task,
					 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
					 IID_CAT_SOFTIRQ, "SOFTIRQ", false /* !start */) {
				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];

					emit_kv_float(def->trace_name_iid, def->trace_name,
						      "%.6lf", e->softirq.ctrs.val[i] * def->mul);
				}
			}
			break;
		}
		case EV_WQ_END:
			emit_slice_point(e->wq.wq_ts, &e->task,
					 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
					 IID_CAT_WQ, "WQ", true /* start */) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->wq.desc);
			}
			emit_slice_point(e->ts, &e->task,
					 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
					 IID_CAT_WQ, "WQ", false /* !start */) {
				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];

					emit_kv_float(def->trace_name_iid, def->trace_name,
						      "%.6lf", e->wq.ctrs.val[i] * def->mul);
				}
			}
			break;
		default:
			fprintf(stderr, "UNHANDLED EVENT %d\n", e->kind);
			exit(1);
			break;
		}
	}

	/* event post-processing logic */
	switch (e->kind) {
	case EV_SWITCH_FROM:
		/* init switched-from task state, if necessary */
		memset(&st->oncpu_ctrs, 0, sizeof(struct perf_counters));
		st->oncpu_ts = 0;
		break;
	default:
	}

	if (!env.verbose)
		return 0;

	printf("%s (%d/%d) @ CPU %d %s %lldus\n",
	       e->task.comm, e->task.tid, e->task.pid, e->cpu,
	       status, 0LL /* e->dur_ns / 1000 */);

	return 0;
}

static int process_raw_dump(struct worker_state *w)
{
	void *dump_mem;
	struct wprof_event *rec;
	size_t dump_sz, rec_sz, off, idx;
	int err;

	cur_stream = &w->stream;

	fflush(w->dump);
	dump_sz = file_size(w->dump);

	dump_mem = mmap(NULL, dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(w->dump), 0);
	if (dump_mem == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to mmap dump file '%s': %d\n", w->dump_path, err);
		return err;
	}

	err = process_stack_traces(w, dump_mem, dump_sz);
	if (err) {
		fprintf(stderr, "Failed to process stack traces: %d\n", err);
		return err;
	}

	fprintf(stderr, "Processing...\n");

	off = 0;
	idx = 0;
	while (off < dump_sz) {
		rec_sz = *(size_t *)(dump_mem + off);
		rec = (struct wprof_event *)(dump_mem + off + sizeof(rec_sz));
		err = process_event(w, rec, rec_sz);
		if (err) {
			fprintf(stderr, "Failed to process event #%zu (kind %d, size %zu, offset %zu): %d\n",
				idx, rec->kind, rec_sz, off, err);
			return err; /* YEAH, I know about all the clean up, whatever */
		}
		off += sizeof(rec_sz) + rec_sz;
		idx += 1;
	}

	err = munmap(dump_mem, dump_sz);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to munmap() dump file '%s': %d\n", w->dump_path, err);
		return err;
	}
	fclose(w->dump);
	w->dump = NULL;
	unlink(w->dump_path);
	return 0;
}

static void print_exit_summary(struct wprof_bpf *skel, int num_cpus, int exit_code)
{
	int err;
	__u64 total_run_cnt = 0, total_run_ns = 0;
	__u64 rb_handled_cnt = 0, rb_ignored_cnt = 0;
	__u64 rb_handled_sz = 0, rb_ignored_sz = 0;

	if (worker) {
		rb_handled_cnt += worker->rb_handled_cnt;
		rb_handled_sz += worker->rb_handled_sz;
		rb_ignored_cnt += worker->rb_ignored_cnt;
		rb_ignored_sz += worker->rb_ignored_sz;
	}

	if (!skel)
		goto skip_prog_stats;

	struct bpf_program *prog;

	fprintf(stderr, "BPF program runtime stats:\n");
	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_prog_info info;
		__u32 info_sz = sizeof(info);

		if (bpf_program__fd(prog) < 0) /* optional inactive program */
			continue;

		memset(&info, 0, sizeof(info));
		err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_sz);
		if (err) {
			fprintf(stderr, "!!! %s: failed to fetch prog info: %d\n",
				bpf_program__name(prog), err);
			continue;
		}

		if (info.recursion_misses) {
			fprintf(stderr, "!!! %s: %llu execution misses!\n",
				bpf_program__name(prog), info.recursion_misses);
		}

		if (env.bpf_stats) {
			fprintf(stderr, "\t%s%-*s %8llu (%6llu/CPU) runs for total of %.3lfms (%.3lfms/CPU).\n",
				bpf_program__name(prog),
				(int)max(1, 24 - strlen(bpf_program__name(prog))), ":",
				info.run_cnt, info.run_cnt / num_cpus,
				info.run_time_ns / 1000000.0, info.run_time_ns / 1000000.0 / num_cpus);
			total_run_cnt += info.run_cnt;
			total_run_ns += info.run_time_ns;
		}
	}

	if (env.bpf_stats) {
		fprintf(stderr, "\t%-24s %8llu (%6llu/CPU) runs for total of %.3lfms (%.3lfms/CPU).\n",
			"TOTAL:", total_run_cnt, total_run_cnt / num_cpus,
			total_run_ns / 1000000.0, total_run_ns / 1000000.0 / num_cpus);
		fprintf(stderr, "\t%-24s %8llu records (%.3lfMBs) processed, %llu records (%.3lfMBs) ignored.\n",
			"DATA:", rb_handled_cnt, rb_handled_sz / 1024.0 / 1024.0,
			rb_ignored_cnt, rb_ignored_sz / 1024.0 / 1024.0);
	}

skip_prog_stats:
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru)) {
		fprintf(stderr, "Failed to get wprof's resource usage data!..\n");
		goto skip_rusage;
	}

	fprintf(stderr, "wprof's own resource usage:\n");
	fprintf(stderr, "\tCPU time (user/system, s):\t\t%.3lf/%.3lf\n",
		ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1000000.0,
		ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1000000.0);
	fprintf(stderr, "\tMemory (max RSS, MB):\t\t\t%.3lf\n",
		ru.ru_maxrss / 1024.0);
	fprintf(stderr, "\tPage faults (maj/min, K)\t\t%.3lf/%.3lf\n",
		ru.ru_majflt / 1000.0, ru.ru_minflt / 1000.0);
	fprintf(stderr, "\tBlock I/Os (K):\t\t\t\t%.3lf/%.3lf\n",
		ru.ru_inblock / 1000.0, ru.ru_oublock / 1000.0);
	fprintf(stderr, "\tContext switches (vol/invol, K):\t%.3lf/%.3lf\n",
		ru.ru_nvcsw / 1000.0, ru.ru_nivcsw / 1000.0);

skip_rusage:
	struct wprof_stats *stats;
	struct wprof_stats s = {};
	int zero = 0;

	if (!skel || bpf_map__fd(skel->maps.stats) < 0)
		goto skip_drop_stats;

	stats = calloc(num_cpus, sizeof(*stats));
	err = bpf_map__lookup_elem(skel->maps.stats, &zero, sizeof(int),
				   stats, sizeof(*stats) * num_cpus, 0);
	if (err) {
		fprintf(stderr, "Failed to fetch BPF-side stats: %d\n", err);
		goto skip_drop_stats;
	}

	for (int i = 0; i < num_cpus; i++) {
		s.rb_misses += stats[i].rb_misses;
		s.rb_drops += stats[i].rb_drops;
		s.task_state_drops += stats[i].task_state_drops;
	}
	free(stats);

	if (s.rb_misses)
		fprintf(stderr, "!!! Ringbuf fetch misses: %llu\n", s.rb_misses);
	if (s.rb_drops) {
		fprintf(stderr, "!!! Ringbuf drops: %llu (%llu handled, %.3lf%% drop rate)\n",
			s.rb_drops, rb_handled_cnt, s.rb_drops * 100.0 / (rb_handled_cnt + s.rb_drops));
	}
	if (s.task_state_drops)
		fprintf(stderr, "!!! Task state drops: %llu\n", s.task_state_drops);

skip_drop_stats:
	fprintf(stderr, "Exited %s (after %.3lfs).\n",
		exit_code ? "with errors" : "cleanly",
		(ktime_now_ns() - env.sess_start_ts) / 1000000000.0);
}

struct timer_plan {
	int cpu;
	__u64 delay_ns;
};

static int timer_plan_cmp(const void *a, const void *b)
{
	const struct timer_plan *x = a, *y = b;

	if (x->delay_ns != y->delay_ns)
		return x->delay_ns < y->delay_ns ? -1 : 1;

	return x->cpu - y->cpu;
}

int main(int argc, char **argv)
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	struct wprof_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus = 0, num_online_cpus;
	int *perf_timer_fds = NULL, *perf_counter_fds = NULL, perf_counter_fd_cnt = 0, pefd;
	int *ringbuf_fds = NULL;
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

	bpf_map__set_max_entries(skel->maps.rbs, env.ringbuf_cnt);
	bpf_map__set_max_entries(skel->maps.task_states, env.task_state_sz);
	if (env.cpu >= 0) {
		skel->rodata->cpu_filter = true;
		skel->data_cpus->cpus[env.cpu / 64] |= (1ULL << ((env.cpu) % 64));
	}

	perf_counter_fd_cnt = num_cpus * env.counter_cnt;
	skel->rodata->perf_ctr_cnt = env.counter_cnt;
	bpf_map__set_max_entries(skel->maps.perf_cntrs, perf_counter_fd_cnt);

	skel->rodata->rb_cnt_bits = 0;
	while ((1ULL << skel->rodata->rb_cnt_bits) < env.ringbuf_cnt)
		skel->rodata->rb_cnt_bits++;

	skel->rodata->capture_stack_traces = env.stack_traces;

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

	ringbuf_fds = calloc(env.ringbuf_cnt, sizeof(*ringbuf_fds));
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int map_fd;

		map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, sfmt("wprof_rb_%d", i), 0, 0, env.ringbuf_sz, NULL);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to create BPF ringbuf #%d: %d\n", i, map_fd);
			err = map_fd;
			goto cleanup;
		}

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.rbs), &i, &map_fd, BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Failed to set BPF ringbuf #%d into ringbuf map-of-maps: %d\n", i, err);
			close(map_fd);
			goto cleanup;
		}

		ringbuf_fds[i] = map_fd;
	}

	struct worker_state *w = calloc(1, sizeof(*w));
	char tmp_path[] = "wprof.dump.XXXXXX";
	int tmp_fd;

	w->name_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = IID_FIXED_LAST_ID,
		.domain_desc = "dynamic",
	};

	tmp_fd = mkstemp(tmp_path);
	if (tmp_fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to create data dump file '%s': %d\n", tmp_path, err);
		goto cleanup;
	}
	w->dump_path = strdup(tmp_path);
	fprintf(stderr, "Using '%s' for raw data dump...\n", w->dump_path);
	w->dump = fdopen(tmp_fd, "w+");
	if (!w->dump) {
		err = -errno;
		fprintf(stderr, "Failed to setup data dump file '%s': %d\n", w->dump_path, err);
		goto cleanup;
	}

	worker = w;

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(ringbuf_fds[0], handle_event, worker, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}
	for (i = 1; i < env.ringbuf_cnt; i++) {
		err = ring_buffer__add(ring_buf, ringbuf_fds[i], handle_event, worker);
		if (err) {
			fprintf(stderr, "Failed to create ring buffer manager for ringbuf #%d: %d\n", i, err);
			goto cleanup;
		}
	}

	perf_timer_fds = malloc(num_cpus * sizeof(int));
	perf_counter_fds = malloc(perf_counter_fd_cnt * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		perf_timer_fds[i] = -1;
		for (int j = 0; j < env.counter_cnt; j++)
			perf_counter_fds[i * env.counter_cnt + j] = -1;
	}

	/* determine randomized spread-out "plan" for attaching to timers to
	 * avoid too aligned (in time) triggerings across all CPUs
	 */
	__u64 timer_start_ts = ktime_now_ns();
	struct timer_plan *timer_plan = calloc(num_cpus, sizeof(*timer_plan));

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		timer_plan[cpu].cpu = cpu;
		timer_plan[cpu].delay_ns = 1000000000ULL / env.freq * ((double)rand() / RAND_MAX);
	}
	qsort(timer_plan, num_cpus, sizeof(*timer_plan), timer_plan_cmp);

	for (int i = 0; i < num_cpus; i++) {
		int cpu = timer_plan[i].cpu;

		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* timer perf event */
		memset(&attr, 0, sizeof(attr));
		attr.size = sizeof(attr);
		attr.type = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_freq = env.freq;
		attr.freq = 1;

		__u64 now = ktime_now_ns();
		if (now < timer_start_ts + timer_plan[i].delay_ns)
			usleep((timer_start_ts + timer_plan[i].delay_ns - now) / 1000);

		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		perf_timer_fds[cpu] = pefd;

		/* CPU cycles perf event, if supported */
		/* set up requested perf counters */
		for (int j = 0; j < env.counter_cnt; j++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[j]];
			int pe_idx = cpu * env.counter_cnt + j;

			memset(&attr, 0, sizeof(attr));
			attr.size = sizeof(attr);
			attr.type = def->perf_type;
			attr.config = def->perf_cfg;

			pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (pefd < 0) {
				fprintf(stderr, "Failed to create %s PMU for CPU #%d, skipping...\n", def->alias, cpu);
			} else {
				perf_counter_fds[pe_idx] = pefd;
				err = bpf_map__update_elem(skel->maps.perf_cntrs,
							   &pe_idx, sizeof(pe_idx),
							   &pefd, sizeof(pefd), 0);
				if (err) {
					fprintf(stderr, "Failed to set up %s PMU on CPU#%d for BPF: %d\n", def->alias, cpu, err);
					goto cleanup;
				}
				err = ioctl(pefd, PERF_EVENT_IOC_ENABLE, 0);
				if (err) {
					fprintf(stderr, "Failed to enable %s PMU on CPU#%d: %d\n", def->alias, cpu, err);
					goto cleanup;
				}
			}
		}
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));
	for (int cpu = 0; cpu < num_cpus; cpu++) {
		if (perf_timer_fds[cpu] < 0)
			continue;

		links[cpu] = bpf_program__attach_perf_event(skel->progs.wprof_timer_tick, perf_timer_fds[cpu]);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	if (env.trace_path) {
		struct worker_state *w = worker;

		w->trace = fopen(env.trace_path, "w+");
		if (!w->trace) {
			err = -errno;
			fprintf(stderr, "Failed to create trace file '%s': %d\n", env.trace_path, err);
			goto cleanup;
		}
		w->stream = (pb_ostream_t){&file_stream_cb, w->trace, SIZE_MAX, 0};

		if (init_protobuf(&w->stream)) {
			err = -1;
			fprintf(stderr, "Failed to init protobuf!\n");
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
	timer_ival.it_interval = env.print_stats ? timer_ival.it_value : (struct timeval){};
	err = setitimer(ITIMER_REAL, &timer_ival, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to setup stats timer: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "Running...\n");
	env.sess_start_ts = ktime_now_ns();
	if (env.run_dur_ms)
		env.sess_end_ts = env.sess_start_ts + env.run_dur_ms * 1000000ULL;
	skel->bss->session_start_ts = env.sess_start_ts;

	/* Wait and receive stack traces */
	while ((err = ring_buffer__poll(ring_buf, -1)) >= 0 || err == -EINTR) {
		if (exiting) {
			err = 0;
			break;
		}
	}

	fprintf(stderr, "Stopping...\n");

cleanup:
	if (skel)
		wprof_bpf__detach(skel);
	if (stats_fd >= 0)
		close(stats_fd);
	if (links) {
		for (int cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (perf_timer_fds || perf_counter_fds) {
		for (i = 0; i < num_cpus; i++) {
			if (perf_timer_fds[i] >= 0)
				close(perf_timer_fds[i]);
		}
		for (i = 0; i < perf_counter_fd_cnt; i++) {
			if (perf_counter_fds[i] >= 0) {
				(void)ioctl(perf_counter_fds[i], PERF_EVENT_IOC_DISABLE, 0);
				close(perf_counter_fds[i]);
			}
		}
		free(perf_timer_fds);
		free(perf_counter_fds);
	}

	fprintf(stderr, "Draining...\n");
	if (ring_buf) { /* drain ringbuf */
		exiting = false; /* ringbuf callback will stop early, if exiting is set */
		(void)ring_buffer__consume(ring_buf);
	}

	ring_buffer__free(ring_buf);
	if (ringbuf_fds) {
		for (i = 0; i < env.ringbuf_cnt; i++)
			if (ringbuf_fds[i])
				close(ringbuf_fds[i]);
	}

	/* process dumped events, if no error happened */
	if (err == 0) {
		ssize_t file_sz;

		err = process_raw_dump(worker);
		if (err) {
			fprintf(stderr, "Failed to process raw data dump: %d\n", err);
			goto cleanup2;
		}

		fflush(worker->trace);
		file_sz = file_size(worker->trace);
		fprintf(stderr, "Produced %.3lfMB trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.trace_path);

		fclose(worker->trace);
	}

cleanup2:
	print_exit_summary(skel, num_cpus, err);

	wprof_bpf__destroy(skel);
	free(online_mask);
	return -err;
}
