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
#include <sys/ioctl.h>
#include <sys/resource.h>
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

#include "pb_common.h"
#include "pb_encode.h"
#include "perfetto_trace.pb.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define __unused __attribute__((unused))
#define __cleanup(fn) __attribute__((cleanup(fn)))

#define DEFAULT_RINGBUF_SZ (64 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ (4 * 4096)
#define DEFAULT_STATS_PERIOD_MS 5000

static struct env {
	bool verbose;
	bool bpf_stats;
	bool libbpf_logs;
	bool print_stats;
	bool cpu_counters;
	bool breakout_counters;
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
	pb_ostream_t trace_stream;

	bool pb_debug_interns;
	bool pb_disable_interns;

	const char *json_trace_path;
	FILE *jtrace;
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
	OPT_CPU_COUNTERS = 1007,
	OPT_BREAKOUT_COUNTERS = 1008,
	OPT_PB_DEBUG_INTERNS = 1009,
	OPT_PB_DISABLE_INTERNS = 1010,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "bpf-stats", OPT_BPF_STATS, NULL, 0, "Enable and print BPF runtime stats" },
	{ "libbpf-logs", OPT_LIBBPF_LOGS, NULL, 0, "Emit libbpf verbose logs" },

	{ "trace", 'T', "FILE", 0, "Emit trace to specified file" },
	{ "trace-json", 'J', "FILE", 0, "Emit JSON trace to specified file" },

	{ "pid", 'p', "PID", 0, "PID filter (track only specified PIDs)" },
	{ "cpu", 'c', "CPU", 0, "CPU filter (track only specified CPUs)" },

	{ "freq", 'f', "HZ", 0, "On-CPU timer interrupt frequency (default: 100Hz, i.e., every 10ms)" },

	{ "ringbuf-size", OPT_RINGBUF_SZ, "SIZE", 0, "BPF ringbuf size (in KBs)" },
	{ "task-state-size", OPT_TASK_STATE_SZ, "SIZE", 0, "BPF task state map size (in threads)" },

	{ "cpu-counters", OPT_CPU_COUNTERS, NULL, 0, "Capture and emit CPU cycles counters" },
	{ "breakout-counters", OPT_BREAKOUT_COUNTERS, NULL, 0, "Emit separate track for counters" },

	{ "print-stats", OPT_PRINT_STATS, NULL, 0, "Print stats periodically" },
	{ "stats-period", OPT_STATS_PERIOD, "PERIOD", 0, "Stats printing period (in ms)" },
	{ "run-dur-ms", OPT_RUN_DUR_MS, "DURATION", 0, "Limit running duration to given number of ms" },

	{ "debug-interns", OPT_PB_DEBUG_INTERNS, NULL, 0, "Emit interned strings" },
	{ "pb-disable-interns", OPT_PB_DISABLE_INTERNS, NULL, 0, "Disable string interning for Perfetto traces" },
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
	case 'J':
		if (env.json_trace_path) {
			fprintf(stderr, "Only one JSON trace file can be specified!\n");
			return -EINVAL;
		}
		env.json_trace_path = strdup(arg);
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
	case OPT_CPU_COUNTERS:
		env.cpu_counters = true;
		break;
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
	case OPT_RUN_DUR_MS:
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
		IID_ANNK_WAKING_FROM,				/* waking_from */
		IID_ANNK_WAKING_FROM_TID,			/* waking_from_tid */
		IID_ANNK_WAKING_FROM_PID,			/* waking_from_pid */
		IID_ANNK_WAKING_REASON,				/* waking_reason */
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
		IID_ANNK_ACTION,					/* action */
		IID_ANNK_IRQ,					/* irq */
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
	[IID_ANNK_WAKING_FROM] = "waking_from",
	[IID_ANNK_WAKING_FROM_TID] = "waking_from_tid",
	[IID_ANNK_WAKING_FROM_PID] = "waking_from_pid",
	[IID_ANNK_WAKING_REASON] = "waking_reason",
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

static __u64 next_str_iid = IID_FIXED_LAST_ID;
static struct hashmap *str_iids;

static pb_iid str_iid_for(const char *s)
{
	long iid;
	char *sdup;

	if (hashmap__find(str_iids, s, &iid))
		return iid;

	sdup = strdup(s);
	iid = next_str_iid++;

	hashmap__set(str_iids, sdup, iid, NULL, NULL);

	if (env.pb_debug_interns)
		fprintf(stderr, "%03ld: %-20s [dynamic]\n", iid, sdup);
	return iid;
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
	.optional_trusted_packet_sequence_id = { (0x42) }, \
	.which_data = perfetto_protos_TracePacket_track_event_tag

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

struct pb_intern_range {
	int start_id;
	int end_id;
};

static bool enc_intern_range(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_intern_range *intern_set = *arg;

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

struct pb_intern_pair {
	pb_iid iid;
	const char *s;
};

static bool enc_intern_pair(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_intern_pair *pair = *arg;
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

#define PB_IID_RANGE(start_id, end_id) ((pb_callback_t){{.encode=enc_intern_range}, (void *)&((struct pb_intern_range){ start_id, end_id })})

#define PB_IID_PAIR(iid, str) ((pb_callback_t){{.encode=enc_intern_pair}, (void *)&((struct pb_intern_pair){ iid, str })})

static pb_field_iter_t trace_pkt_it;

static void enc_trace_packet(TracePacket *msg)
{
	if (!env.trace)
		return;

	if (!pb_encode_tag_for_field(&env.trace_stream, &trace_pkt_it)) {
		fprintf(stderr, "Failed to encode Trace.packet field tag!\n");
		exit(1);
	}
	if (!pb_encode_submessage(&env.trace_stream, perfetto_protos_TracePacket_fields, msg)) {
		fprintf(stderr, "Failed to encode TracePacket value!\n");
		exit(1);
	}
}
/*
 * HIGH-LEVEL TRACE RECORD EMITTING INTERFACES
 */
enum emit_scope {
	EMIT_ARR,
	EMIT_OBJ,
};

struct emit_state {
	int lvl;
	enum emit_scope scope[5];
	int cnt[5]; /* object field or array items counts, per-level */

	bool is_pb;
	TracePacket pb;
	struct pb_anns anns;
};

static __thread struct emit_state em = {.lvl = -1};

static void emit_obj_start(void)
{
	if (!env.jtrace)
		return;

	em.scope[++em.lvl] = EMIT_OBJ;
	fprintf(env.jtrace, "{");
}

static void emit_obj_end(void)
{
	if (!env.jtrace)
		return;

	em.cnt[em.lvl--] = 0;
	if (em.lvl < 0) /* outermost level, we are done with current record */
		fprintf(env.jtrace, "},\n");
	else
		fprintf(env.jtrace, "}");
}

static void emit_key(const char *key)
{
	fprintf(env.jtrace, "%s\"%s\":", em.cnt[em.lvl] ? "," : "", key);
	em.cnt[em.lvl]++;
}

static void emit_subobj_start(const char *key)
{
	if (!env.jtrace)
		return;

	emit_key(key);
	emit_obj_start();
}

__unused
static void emit_kv_str(pb_iid key_iid, const char *key, pb_iid value_iid, const char *value)
{
	if (env.jtrace) {
		emit_key(key);
		fprintf(env.jtrace, "\"%s\"", value);
	}
	if (env.trace && em.is_pb)
		anns_add_str(&em.anns, key_iid, key, value_iid, value);
}

__unused
__attribute__((format(printf, 3, 4)))
static void emit_kv_fmt(pb_iid key_iid, const char *key, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (env.jtrace) {
		emit_key(key);

		fprintf(env.jtrace, "\"");

		va_list apj;
		va_copy(apj, ap);

		vfprintf(env.jtrace, fmt, apj);
		va_end(apj);

		fprintf(env.jtrace, "\"");
	}

	if (env.trace && em.is_pb)
		anns_add_str(&em.anns, key_iid, key, IID_NONE, vsfmt(fmt, ap));

	va_end(ap);
}

__unused
static void emit_kv_int(pb_iid key_iid, const char *key, int64_t value)
{
	if (env.jtrace) {
		emit_key(key);
		fprintf(env.jtrace, "%lld", (long long)value);
	}
	if (env.trace && em.is_pb)
		anns_add_int(&em.anns, key_iid, key, value);
}

__unused
static void emit_kv_float(pb_iid key_iid, const char *key, const char *fmt, double value)
{
	if (env.jtrace) {
		emit_key(key);
		fprintf(env.jtrace, fmt, value);
		em.cnt[em.lvl]++;
	}
	if (env.trace && em.is_pb)
		anns_add_double(&em.anns, key_iid, key, value);
}

__unused
static void emit_arr_start(void)
{
	if (!env.jtrace)
		return;

	em.scope[++em.lvl] = EMIT_ARR;
	fprintf(env.jtrace, "[");
}

__unused
static void emit_arr_end(void)
{
	if (!env.jtrace)
		return;

	em.cnt[em.lvl--] = 0;
	fprintf(env.jtrace, "]");
}

__unused
static void emit_subarr_start(const char *key)
{
	if (!env.jtrace)
		return;

	emit_key(key);
	emit_arr_start();
}

static void emit_arr_elem(void)
{
	if (!env.jtrace)
		return;

	if (em.cnt[em.lvl])
		fprintf(env.jtrace, ",");
	em.cnt[em.lvl]++;
}

__unused
static void emit_arr_str(const char *value)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();
	fprintf(env.jtrace, "\"%s\"", value);
}

__unused
__attribute__((format(printf, 1, 2)))
static void emit_arr_fmt(const char *fmt, ...)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();

	fprintf(env.jtrace, "\"");

	va_list ap;
	va_start(ap, fmt);
	vfprintf(env.jtrace, fmt, ap);
	va_end(ap);

	fprintf(env.jtrace, "\"");
}

__unused
static void emit_arr_int(long long value)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();
	fprintf(env.jtrace, "%lld", value);
}

__unused
static void emit_arr_float(const char *fmt, double value)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();
	fprintf(env.jtrace, fmt, value);
}

struct emit_rec { bool done; };

static void emit_cleanup(struct emit_rec *r)
{
	if (env.jtrace) {
		while (em.lvl >= 0) {
			if (em.scope[em.lvl] == EMIT_OBJ)
				emit_obj_end();
			else
				emit_arr_end();
		}
	}
	if (env.trace && em.is_pb) {
		enc_trace_packet(&em.pb);
		em.is_pb = false;
	}
}

/*
 * SYMBOLIZATION
 */
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

struct task_state {
	int tid, pid;
	pb_iid name_iid;
	pb_iid rename_iid;
	char comm[TASK_COMM_FULL_LEN];
	/* task renames */
	__u64 rename_ts;
	char old_comm[TASK_COMM_FULL_LEN];
	/* periodic stats */
	uint64_t on_cpu_ns;
	uint64_t off_cpu_ns;
	/* perf counters */
	__u64 oncpu_ts;
	__u64 cpu_cycles;
	__u64 hardirq_ts;
	__u64 softirq_ts;
	__u64 wq_ts;
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
	if (env.jtrace) {
		emit_obj_start();
			emit_kv_str(0, "ph", 0, "i");
			emit_kv_float(0, "ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
			emit_kv_fmt(0, "name", name);
			/* assume thread-scoped instant event */
			// emit_kv_str("s", "t");
			emit_kv_int(0, "tid", track_tid(t));
			emit_kv_int(0, "pid", track_pid(t));
	}

	if (env.trace) {
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
		em.is_pb = true;
	}

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
	if (env.jtrace) {
		emit_obj_start();
			emit_kv_str(0, "ph", 0, start ? "B" : "E");
			emit_kv_float(0, "ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
			emit_kv_fmt(0, "name", "%s", name);
			emit_kv_str(0, "cat", 0, category);
			emit_kv_int(0, "tid", track_tid(t));
			emit_kv_int(0, "pid", track_pid(t));
	}

	if (env.trace) {
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
		em.is_pb = true;
	}

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_slice_point(ts, t, name_iid, name, cat_iid, category, start)			\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, t, name_iid, name, cat_iid, category, start);		\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_counter_pre(__u64 ts, const struct wprof_task *t,
					const char *name, const char *subname)
{
	if (!env.jtrace)
		return (struct emit_rec){ .done = true };

	emit_obj_start();
		emit_kv_str(0, "ph", 0, "C");
		emit_kv_float(0, "ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
		/* counters are process-scoped, so include TID into counter name */
		emit_kv_fmt(0, "name", "%s%s%s:%d", name, subname ? ":" : "", subname ?: "", track_tid(t));
		//emit_kv_int(0, "tid", track_tid(t));
		emit_kv_int(0, "pid", track_pid(t));
		emit_subobj_start("args");
	return (struct emit_rec){};
}

#define emit_counter(ts, t, name, subname)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_counter_pre(ts, t, name, subname);						\
	     !___r.done; ___r.done = true)

static int emit_trace_meta(const struct wprof_task *t)
{
	int tid, pid;
	const char *pcomm;
	//int sort_idx = trace_sort_idx(t);

	if (!env.jtrace)
		return 0;

	tid = track_tid(t);
	pid = track_pid(t);
	pcomm = track_pcomm(t);
	
	emit_obj_start();
		emit_kv_str(0, "ph", 0, "M");
		emit_kv_str(0, "name", 0, "process_name");
		emit_kv_int(0, "pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_str(0, "name", 0, pcomm);
		emit_obj_end();
	emit_obj_end();
	emit_obj_start();
		emit_kv_str(0, "ph", 0, "M");
		emit_kv_str(0, "name", 0, "process_sort_index");
		emit_kv_int(0, "pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_int(0, "sort_index", pid);
		emit_obj_end();
	emit_obj_end();

	emit_obj_start();
		emit_kv_str(0, "ph", 0, "M");
		emit_kv_str(0, "name", 0, "thread_name");
		emit_kv_int(0, "tid", tid);
		emit_kv_int(0, "pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_str(0, "name", 0, t->comm);
		emit_obj_end();
	emit_obj_end();
	emit_obj_start();
		emit_kv_str(0, "ph", 0, "M");
		emit_kv_str(0, "name", 0, "thread_sort_index");
		emit_kv_int(0, "tid", tid);
		emit_kv_int(0, "pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_int(0, "sort_index", tid);
		emit_obj_end();
	emit_obj_end();

	return 0;
}

static void emit_thread_meta(const struct wprof_task *t, const char *name)
{
	int tid, pid;

	if (!env.jtrace)
		return;

	tid = track_tid(t);
	pid = track_pid(t);
	
	emit_obj_start();
		emit_kv_str(0, "ph", 0, "M");
		emit_kv_str(0, "name", 0, "thread_name");
		emit_kv_int(0, "tid", tid);
		emit_kv_int(0, "pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_str(0, "name", 0, name);
		emit_obj_end();
	emit_obj_end();
}

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
static void emit_clock_snapshot(void)
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
	enc_trace_packet(&pb);
}

static int init_protobuf(void)
{
	if (!pb_field_iter_begin(&trace_pkt_it, perfetto_protos_Trace_fields, NULL)) {
		fprintf(stderr, "Failed to start Trace fields iterator!\n");
		return -1;
	}
	if (!pb_field_iter_find(&trace_pkt_it, 1)) {
		fprintf(stderr, "Failed to find Trace field!\n");
		return -1;
	}

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
			.event_categories = PB_IID_RANGE(CAT_START_IID, CAT_END_IID),
			.event_names = PB_IID_RANGE(NAME_START_IID, NAME_END_IID),
			.debug_annotation_names = PB_IID_RANGE(ANNK_START_IID, ANNK_END_IID),
			.debug_annotation_string_values = PB_IID_RANGE(ANNV_START_IID, ANNV_END_IID),
		},
	};
	enc_trace_packet(&ev_pb);

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

static void emit_kind_track_descr(enum task_kind k)
{
	if (!env.trace)
		return;

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
	enc_trace_packet(&desc_pb);
}

static void emit_process_track_descr(const struct wprof_task *t, pb_iid pname_iid)
{
	const char *pcomm;

	if (!env.trace)
		return;

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
			.event_names = PB_IID_PAIR(pname_iid, pcomm),
			.debug_annotation_string_values = PB_IID_PAIR(pname_iid, pcomm),
		}
	};
	enc_trace_packet(&proc_desc);
}

static void emit_thread_track_descr(const struct wprof_task *t, pb_iid tname_iid, const char *comm)
{
	if (!env.trace)
		return;

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
			.event_names = PB_IID_PAIR(tname_iid, comm),
			.debug_annotation_string_values = PB_IID_PAIR(tname_iid, comm),
		}
	};
	enc_trace_packet(&thread_desc);
}

static struct task_state *task_state(struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	if (!hashmap__find(tasks, key, &st)) {
		st = calloc(1, sizeof(*st));
		st->tid = t->tid;
		st->pid = t->pid;
		strlcpy(st->comm, t->comm, sizeof(st->comm));
		st->name_iid = str_iid_for(t->comm);

		hashmap__set(tasks, key, st, NULL, NULL);

		emit_trace_meta(t);

		/* Proactively setup process group leader tasks info */
		enum task_kind tkind = task_kind(t);
		if (tkind == TASK_NORMAL) {
			unsigned long pkey = t->pid;
			struct task_state *pst = NULL;

			if (t->tid == t->pid) {
				/* we are the new task group leader */
				emit_process_track_descr(t, str_iid_for(t->pcomm));
			} else if (!hashmap__find(tasks, pkey, &pst)) {
				/* no task group leader task yet */
				pst = calloc(1, sizeof(*st));
				pst->tid = pst->pid = t->pid;
				strlcpy(pst->comm, t->pcomm, sizeof(pst->comm));
				pst->name_iid = str_iid_for(pst->comm);

				hashmap__set(tasks, pkey, pst, NULL, NULL);

				struct wprof_task pt = {
					.tid = t->pid,
					.pid = t->pid,
					.flags = 0,
				};
				strlcpy(pt.comm, t->pcomm, sizeof(pt.comm));
				strlcpy(pt.pcomm, t->pcomm, sizeof(pt.comm));

				emit_process_track_descr(&pt, pst->name_iid);
				emit_thread_track_descr(&pt, pst->name_iid, pst->comm);
			} else {
				/* otherwise someone already emitted descriptors */
			}
		} else if (!kind_track_emitted[tkind]) {
			emit_kind_track_descr(tkind);
			kind_track_emitted[tkind] = true;
		}

		emit_thread_track_descr(t, st->name_iid, t->comm);
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
		st->cpu_cycles = e->swtch.cpu_cycles;
		st->oncpu_ts = e->ts;
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

	if (env.trace || env.jtrace) {
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
			emit_instant(e->ts, &e->task, IID_NAME_TIMER, "TIMER") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
			}
			break;
		case EV_SWITCH: {
			struct task_state *wst;
			const char *prev_name;
			pb_iid prev_name_iid;

			/* take into account task rename for switched-out task
			 * to maintain consistently named trace slice
			 */
			prev_name = pst->rename_ts ? pst->old_comm : e->swtch.prev.comm;
			prev_name_iid = pst->rename_ts ? IID_NONE : pst->name_iid;

			if (e->swtch.waking_ts)
				wst = task_state(&e->swtch.waking);

			/* We are about to emit SLICE_END without
			 * corresponding SLICE_BEING ever being emitted;
			 * normally, Perfetto will just skip such SLICE_END
			 * and won't render anything, which is annoying and
			 * confusing. We want to avoid this, so we'll emit
			 * a fake SLICE_BEGIN with fake timestamp ZERO.
			 */
			if (pst->oncpu_ts == 0) {
				emit_slice_point(env.sess_start_ts, &e->swtch.prev, prev_name_iid, prev_name,
						 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
					emit_subobj_start("args");
					emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				}
			}

			emit_slice_point(e->ts, &e->swtch.prev,
					 prev_name_iid, prev_name,
					 IID_CAT_ONCPU, "ONCPU", false /*!start*/) {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);

				emit_kv_str(IID_ANNK_SWITCH_TO, "switch_to", st->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_SWITCH_TO_TID, "switch_to_tid", task_tid(&e->task));
				emit_kv_int(IID_ANNK_SWITCH_TO_PID, "switch_to_pid", e->task.pid);
				if (env.cpu_counters && pst->cpu_cycles && e->swtch.cpu_cycles) {
					emit_kv_float(IID_ANNK_CPU_MEGA_CYCLES, "cpu_mega_cycles",
						      "%.6lf", (e->swtch.cpu_cycles - pst->cpu_cycles) / 1000000.0);
				}
				if (pst->rename_ts)
					emit_kv_str(IID_ANNK_RENAMED_TO, "renamed_to", IID_NONE, e->swtch.prev.comm);
			}

			emit_slice_point(e->ts, &e->task, st->name_iid, e->task.comm,
					 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);

				if (e->swtch.waking_ts) {
					emit_kv_str(IID_ANNK_WAKING_FROM, "waking_from", wst->name_iid, e->swtch.waking.comm);
					emit_kv_int(IID_ANNK_WAKING_FROM_TID, "waking_from_tid", task_tid(&e->swtch.waking));
					emit_kv_int(IID_ANNK_WAKING_FROM_PID, "waking_from_pid", e->swtch.waking.pid);
					emit_kv_str(IID_ANNK_WAKING_REASON, "waking_reason",
						    IID_NONE, waking_reason_str(e->swtch.waking_flags));
					emit_kv_int(IID_ANNK_WAKING_CPU, "waking_cpu", e->swtch.waking_cpu);
					emit_kv_float(IID_ANNK_WAKING_DELAY_US, "waking_delay_us",
						      "%.3lf", (e->ts - e->swtch.waking_ts) / 1000.0);
				}
				emit_kv_str(IID_ANNK_SWITCH_FROM, "switch_from", pst->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_SWITCH_FROM_TID, "switch_from_tid", task_tid(&e->swtch.prev));
				emit_kv_int(IID_ANNK_SWITCH_FROM_PID, "switch_from_pid", e->swtch.prev.pid);

				emit_obj_end();
			}

			if (env.cpu_counters && env.breakout_counters &&
			    pst->oncpu_ts && pst->cpu_cycles && e->swtch.cpu_cycles) {
				emit_counter(pst->oncpu_ts, &e->swtch.prev, "cpu_cycles", NULL) {
					emit_kv_float(IID_NONE, "mega_cycles", "%.6lf",
						      (e->swtch.cpu_cycles - pst->cpu_cycles) / 1000000.0);
				}
				emit_counter(e->ts, &e->swtch.prev, "cpu_cycles", NULL) {
					emit_kv_float(IID_NONE, "mega_cycles", "%.6lf", 0.0);
				}
			}
			if (env.breakout_counters && e->swtch.waking_ts) {
				emit_counter(e->ts, &e->task, "waking_delay", NULL) {
					emit_kv_float(IID_NONE, "us", "%.3lf", (e->ts - e->swtch.waking_ts) / 1000.0);
				}
			}

			if (pst->rename_ts) {
				pst->rename_ts = 0;
				pst->name_iid = pst->rename_iid;
			}
			break;
		}
		case EV_FORK: {
			struct task_state *fst = task_state(&e->fork.child);

			emit_instant(e->ts, &e->task, IID_NAME_FORKING, "FORKING") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_str(IID_ANNK_FORKED_INTO, "forked_into", fst->name_iid, e->fork.child.comm);
				emit_kv_int(IID_ANNK_FORKED_INTO_TID, "forked_into_tid", task_tid(&e->fork.child));
				emit_kv_int(IID_ANNK_FORKED_INTO_PID, "forked_into_pid", e->fork.child.pid);
			}
			emit_instant(e->ts, &e->fork.child, IID_NAME_FORKED, "FORKED") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_str(IID_ANNK_FORKED_FROM, "forked_from", st->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_FORKED_FROM_TID, "forked_from_tid", task_tid(&e->task));
				emit_kv_int(IID_ANNK_FORKED_FROM_PID, "forked_from_pid", e->task.pid);
			}
			break;
		}
		case EV_EXEC: {
			emit_instant(e->ts, &e->task, IID_NAME_EXEC, "EXEC") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_str(IID_ANNK_FILENAME, "filename", IID_NONE, e->exec.filename);
				if (e->task.tid != e->exec.old_tid)
					emit_kv_int(IID_ANNK_TID_CHANGED_FROM, "tid_changed_from", e->exec.old_tid);
			}
			break;
		}
		case EV_TASK_RENAME: {
			emit_instant(e->ts, &e->task, 0, "RENAME") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_str(IID_ANNK_OLD_NAME, "old_name", IID_NONE, e->task.comm);
				emit_kv_str(IID_ANNK_NEW_NAME, "new_name", IID_NONE, e->rename.new_comm);
			}

			st->rename_iid = str_iid_for(e->rename.new_comm);
			emit_thread_track_descr(&e->task, st->rename_iid, e->rename.new_comm);

			emit_thread_meta(&e->task, e->rename.new_comm);
			break;
		}
		case EV_TASK_EXIT:
			emit_instant(e->ts, &e->task, IID_NAME_EXIT, "EXIT") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
			}
			break;
		case EV_TASK_FREE:
			emit_instant(e->ts, &e->task, IID_NAME_FREE, "FREE") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
			}
			break;
		case EV_WAKEUP:
			emit_instant(e->ts, &e->task, IID_NAME_WAKEUP, "WAKEUP") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
			}
			break;
		case EV_WAKEUP_NEW:
			emit_instant(e->ts, &e->task, IID_NAME_WAKEUP_NEW, "WAKEUP_NEW") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
			}
			break;
		case EV_WAKING:
			emit_instant(e->ts, &e->task, IID_NAME_WAKING, "WAKING") {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
			}
			break;
		case EV_HARDIRQ_ENTER:
		case EV_HARDIRQ_EXIT:
			/* see EV_SWITCH handling of fake (because missing) SLICE_BEGIN */
			if (e->kind == EV_HARDIRQ_EXIT && st->hardirq_ts == 0) {
				emit_slice_point(env.sess_start_ts, &e->task, IID_NAME_HARDIRQ, "HARDIRQ",
						 IID_CAT_HARDIRQ, "HARDIRQ", true /* start */) {
					emit_subobj_start("args");
					emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
					emit_kv_int(IID_ANNK_IRQ, "irq", e->hardirq.irq);
					emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->hardirq.name);
				}
			}
			emit_slice_point(e->ts, &e->task, IID_NAME_HARDIRQ, "HARDIRQ",
					 IID_CAT_HARDIRQ, "HARDIRQ", e->kind == EV_HARDIRQ_ENTER /* start */) {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_int(IID_ANNK_IRQ, "irq", e->hardirq.irq);
				emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->hardirq.name);
			}
			if (e->kind == EV_HARDIRQ_ENTER)
				st->hardirq_ts = e->ts;
			else
				st->hardirq_ts = 0;
			break;
		case EV_SOFTIRQ_ENTER:
		case EV_SOFTIRQ_EXIT: {
			pb_iid name_iid, act_iid;

			if (e->softirq.vec_nr >= 0 && e->softirq.vec_nr < NR_SOFTIRQS) {
				name_iid = IID_NAME_SOFTIRQ + e->softirq.vec_nr;
				act_iid = IID_ANNV_SOFTIRQ_ACTION + e->softirq.vec_nr;
			} else {
				name_iid = IID_NONE;
				act_iid = IID_NONE;
			}

			/* see EV_SWITCH handling of fake (because missing) SLICE_BEGIN */
			if (e->kind == EV_SOFTIRQ_EXIT && st->softirq_ts == 0) {
				emit_slice_point(env.sess_start_ts, &e->task,
						 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
						 IID_CAT_SOFTIRQ, "SOFTIRQ", true /* start */) {
					emit_subobj_start("args");
					emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
					emit_kv_str(IID_ANNK_ACTION, "action", act_iid, softirq_str(e->softirq.vec_nr));
				}
			}

			emit_slice_point(e->ts, &e->task,
					 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
					 IID_CAT_SOFTIRQ, "SOFTIRQ", e->kind == EV_SOFTIRQ_ENTER /* start */) {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_str(IID_ANNK_ACTION, "action", act_iid, softirq_str(e->softirq.vec_nr));
			}

			if (e->kind == EV_SOFTIRQ_ENTER)
				st->softirq_ts = e->ts;
			else
				st->softirq_ts = 0;
			break;
		}
		case EV_WQ_START:
		case EV_WQ_END:
			/* see EV_SWITCH handling of fake (because missing) SLICE_BEGIN */
			if (e->kind == EV_WQ_END && st->wq_ts == 0) {
				emit_slice_point(env.sess_start_ts, &e->task,
						 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
						 IID_CAT_WQ, "WQ", true /* start */) {
					emit_subobj_start("args");
					emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
					emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->wq.desc);
				}
			}
			emit_slice_point(e->ts, &e->task,
					 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
					 IID_CAT_WQ, "WQ", e->kind == EV_WQ_START /* start */) {
				emit_subobj_start("args");
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu_id);
				emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->wq.desc);
			}
			if (e->kind == EV_WQ_START)
				st->wq_ts = e->ts;
			else
				st->wq_ts = 0;
			break;
		default:
			break;
		}
	}

	/* event post-processing logic */
	switch (e->kind) {
	case EV_SWITCH:
		/* init switched-from task state, if necessary */
		pst->cpu_cycles = 0;
		pst->oncpu_ts = 0;
		break;
	default:
	}

	if (exiting)
		return -EINTR;

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

static void print_exit_summary(struct wprof_bpf *skel, int num_cpus, int exit_code)
{
	int err;

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
			fprintf(stderr, "\t%s: %llu runs for total of %.3lfms.\n",
				bpf_program__name(prog), info.run_cnt, info.run_time_ns / 1000000.0);
		}
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
	fprintf(stderr, "\tPage faults (maj/min, M)\t\t%.3lf/%.3lf\n",
		ru.ru_majflt / 1000000.0, ru.ru_minflt / 1000000.0);
	fprintf(stderr, "\tBlock I/Os (K):\t\t\t\t%.3lf/%.3lf\n",
		ru.ru_inblock / 1000.0, ru.ru_oublock / 1000.0);
	fprintf(stderr, "\tContext switches (vol/invol, M):\t%.3lf/%.3lf\n",
		ru.ru_nvcsw / 1000000.0, ru.ru_nivcsw / 1000000.0);

skip_rusage:
	struct wprof_stats *stats;
	struct wprof_stats s = {};
	int zero = 0;

	if (!skel)
		goto skip_drop_stats;

	stats = calloc(num_cpus, sizeof(*stats));
	err = bpf_map__lookup_elem(skel->maps.stats, &zero, sizeof(int),
				   stats, sizeof(*stats) * num_cpus, 0);
	if (err) {
		fprintf(stderr, "Failed to fetch BPF-side stats: %d\n", err);
		goto skip_drop_stats;
	}

	for (int i = 0; i < num_cpus; i++) {
		s.rb_drops += stats[i].rb_drops;
		s.task_state_drops += stats[i].task_state_drops;
	}
	free(stats);

	if (s.rb_drops)
		fprintf(stderr, "!!! Ringbuf drops: %llu\n", s.rb_drops);
	if (s.task_state_drops)
		fprintf(stderr, "!!! Task state drops: %llu\n", s.task_state_drops);

skip_drop_stats:
	fprintf(stderr, "Exited %s (after %.3lfs).\n",
		exit_code ? "with errors" : "cleanly",
		(ktime_now_ns() - env.sess_start_ts) / 1000000000.0);
}

static ssize_t file_size(FILE *f)
{
	int fd = fileno(f);
	struct stat st;

	if (fstat(fd, &st))
		return -errno;

	return st.st_size;
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
	int num_cpus, num_online_cpus;
	int *perf_timer_fds = NULL, *perf_counter_fds = NULL, pefd;
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
	str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL);

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
	bpf_map__set_max_entries(skel->maps.perf_cntrs, num_cpus);
	if (env.cpu >= 0) {
		skel->rodata->cpu_filter = true;
		skel->data_cpus->cpus[env.cpu / 64] |= (1ULL << ((env.cpu) % 64));
	}
	skel->rodata->cpu_counters = env.cpu_counters;

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

	perf_timer_fds = malloc(num_cpus * sizeof(int));
	perf_counter_fds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		perf_timer_fds[i] = -1;
		perf_counter_fds[i] = -1;
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
		memset(&attr, 0, sizeof(attr));
		attr.size = sizeof(attr);
		attr.type = PERF_TYPE_HARDWARE;
		attr.config = PERF_COUNT_HW_CPU_CYCLES;

		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Failed to create CPU cycles PMU for CPU #%d, skipping...\n", cpu);
		} else {
			perf_counter_fds[cpu] = pefd;
			err = bpf_map__update_elem(skel->maps.perf_cntrs,
						   &cpu, sizeof(cpu),
						   &pefd, sizeof(pefd), 0);
			if (err) {
				fprintf(stderr, "Failed to set up cpu-cycles PMU on CPU#%d for BPF: %d\n", cpu, err);
				goto cleanup;
			}
			err = ioctl(pefd, PERF_EVENT_IOC_ENABLE, 0);
			if (err) {
				fprintf(stderr, "Failed to enable cpu-cycles PMU on CPU#%d: %d\n", cpu, err);
				goto cleanup;
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
		env.trace = fopen(env.trace_path, "w");
		if (!env.trace) {
			err = -errno;
			fprintf(stderr, "Failed to create trace file at '%s': %d\n", env.trace_path, err);
			goto cleanup;
		}
		env.trace_stream = (pb_ostream_t){&file_stream_cb, env.trace, SIZE_MAX, 0};

		if (init_protobuf()) {
			err = -1;
			fprintf(stderr, "Failed to init protobuf!\n");
			goto cleanup;
		}
	}
	if (env.json_trace_path) {
		env.jtrace = fopen(env.json_trace_path, "w");
		if (!env.jtrace) {
			err = -errno;
			fprintf(stderr, "Failed to create JSON trace file at '%s': %d\n", env.json_trace_path, err);
			goto cleanup;
		}
		if (fprintf(env.jtrace, "{\"traceEvents\":[\n") < 0) {
			err = -errno;
			fprintf(stderr, "Failed to write trace preamble: %d\n", err);
			goto cleanup;
		}
		/* emit fake instant event to establish strict zero timestamp */
		err = fprintf(env.jtrace, "{\"ph\":\"i\",\"name\":\"START\",\"s\":\"t\",\"ts\":0.0,\"tid\":0,\"pid\":0},\n");
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "Failed to start trace at '%s' with time origin instant event: %d\n", env.json_trace_path, err);
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
	skel->bss->session_start_ts = env.sess_start_ts;

	/*
	if (env.trace)
		emit_clock_snapshot();
	*/

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
	if (links) {
		for (int cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (perf_timer_fds || perf_counter_fds) {
		for (i = 0; i < num_cpus; i++) {
			if (perf_timer_fds[i] >= 0)
				close(perf_timer_fds[i]);
			if (perf_counter_fds[i] >= 0) {
				(void)ioctl(perf_counter_fds[i], PERF_EVENT_IOC_DISABLE, 0);
				close(perf_counter_fds[i]);
			}
		}
		free(perf_timer_fds);
		free(perf_counter_fds);
	}

	fprintf(stderr, "Draining...\n");
	if (ring_buf) /* drain ringbuf */
		(void)ring_buffer__consume(ring_buf);

	if (stats_fd >= 0)
		close(stats_fd);

	if (env.trace) {
		ssize_t file_sz;

		fflush(env.trace);

		file_sz = file_size(env.trace);
		fprintf(stderr, "Produced %.3lfMB trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.trace_path);

		fclose(env.trace);
	}
	if (env.jtrace) {
		ssize_t file_sz;

		(void)fprintf(env.jtrace, "]}\n");
		fflush(env.jtrace);

		file_sz = file_size(env.jtrace);
		fprintf(stderr, "Produced %.3lfMB JSON trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.json_trace_path);

		fclose(env.jtrace);
	}

	print_exit_summary(skel, num_cpus, err);

	ring_buffer__free(ring_buf);
	wprof_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	free(online_mask);
	return -err;
}
