// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Facebook */
#define _XOPEN_SOURCE
#define _GNU_SOURCE
#include <termios.h>
#include <fcntl.h>
#include <stdlib.h>

#include <argp.h>
#include <ctype.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "minimal.h"
#include "minimal.skel.h"
#include "trace_helpers.h"

struct symb_resp
{
	char fname[128];
	char line[512];
};

struct addr2line;
static void addr2line__free(struct addr2line *a2l);
static struct addr2line *addr2line__init(const char *filename, const char *vmlinux, bool inlines);
static int addr2line__symbolize(const struct addr2line *a2l, long addr, struct symb_resp *resp);

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

static struct env {
	bool verbose;
	bool debug;
	bool debug_libbpf;
	bool symb_lines;
	bool symb_inlines;
	const char *vmlinux_path;

	const struct preset **presets;
	char **allow_globs;
	char **deny_globs;
	char **entry_globs;
	int preset_cnt;
	int allow_glob_cnt;
	int deny_glob_cnt;
	int entry_glob_cnt;
} env;

const char *argp_program_version = "dude-where-is-my-error (dwime) 0.0";
const char *argp_program_bug_address = "andrii@kernel.org";
const char argp_program_doc[] =
"dude-where-is-my-error tool.\n"
"\n"
"\n"
"USAGE: ./dwime [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', "LEVEL", OPTION_ARG_OPTIONAL,
	  "Verbose output (use -vv for debug-level verbosity, -vvv for libbpf debug log)" },
	{ "preset", 'p', "PRESET", 0,
	  "Use a pre-defined set of entry/allow/deny globs for a given use case (supported presets: bpf, perf)" },
	{ "entry", 'e', "GLOB", 0,
	  "Glob for entry functions that trigger error stack trace collection" },
	{ "allow", 'a', "GLOB", 0,
	  "Glob for allowed functions captured in error stack trace collection" },
	{ "deny", 'd', "GLOB", 0,
	  "Glob for denied functions ignored during error stack trace collection" },
	{ "kernel", 'k', "PATH", 0,
	  "Path to vmlinux image with DWARF information embedded" },
	{ "symbolize", 's', "LEVEL", OPTION_ARG_OPTIONAL,
	  "Perform extra (more expensive) symbolization (-s gives line numbers, -ss gives also inline symbols). Relies on having vmlinux with DWARF available." },
	{},
};

struct preset {
	const char *name;
	const char **entry_globs;
	const char **allow_globs;
	const char **deny_globs;
};

static const char *bpf_entry_globs[];
static const char *bpf_allow_globs[];
static const char *bpf_deny_globs[];

static const char *perf_entry_globs[];
static const char *perf_allow_globs[];
static const char *perf_deny_globs[];

static const struct preset presets[] = {
	{"bpf", bpf_entry_globs, bpf_allow_globs, bpf_deny_globs},
	{"perf", perf_entry_globs, perf_allow_globs, perf_deny_globs},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	void *tmp, *s;
	int i;

	switch (key) {
	case 'v':
		env.verbose = true;
		if (arg) {
			if (strcmp(arg, "v") == 0) {
				env.debug = true;
			} else if (strcmp(arg, "vv") == 0) {
				env.debug = true;
				env.debug_libbpf = true;
			} else {
				fprintf(stderr,
					"Unrecognized verbosity setting '%s', only -v, -vv, and -vvv are supported\n",
					arg);
				return -EINVAL;
			}
		}
		break;
	case 'p':
		for (i = 0; i < ARRAY_SIZE(presets); i++) {
			const struct preset *p = &presets[i];

			if (strcmp(p->name, arg) != 0)
				continue;

			tmp = realloc(env.presets, (env.preset_cnt + 1) * sizeof(*env.presets));
			if (!tmp)
				return -ENOMEM;

			env.presets = tmp;
			env.presets[env.preset_cnt++] = p;

			return 0;
		}
		fprintf(stderr, "Unknown preset '%s' specified.\n", arg);
		break;
	case 'a':
		tmp = realloc(env.allow_globs, (env.allow_glob_cnt + 1) * sizeof(*env.allow_globs));
		if (!tmp)
			return -ENOMEM;
		s = strdup(arg);
		if (!s)
			return -ENOMEM;
		env.allow_globs = tmp;
		env.allow_globs[env.allow_glob_cnt++] = s;
		break;
	case 'd':
		tmp = realloc(env.deny_globs, (env.deny_glob_cnt + 1) * sizeof(*env.deny_globs));
		if (!tmp)
			return -ENOMEM;
		s = strdup(arg);
		if (!s)
			return -ENOMEM;
		env.deny_globs = tmp;
		env.deny_globs[env.deny_glob_cnt++] = s;
		break;
	case 'e':
		tmp = realloc(env.entry_globs, (env.entry_glob_cnt + 1) * sizeof(*env.entry_globs));
		if (!tmp)
			return -ENOMEM;
		s = strdup(arg);
		if (!s)
			return -ENOMEM;
		env.entry_globs = tmp;
		env.entry_globs[env.entry_glob_cnt++] = s;
		break;
	case 's':
		env.symb_lines = true;
		if (arg) {
			if (strcmp(arg, "s") == 0) {
				env.symb_inlines = true;
			} else {
				fprintf(stderr,
					"Unrecognized symbolization setting '%s', only -s, and -ss are supported\n",
					arg);
				return -EINVAL;
			}
		}
		break;
	case 'k':
		env.vmlinux_path = arg;
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

struct func_info {
	const char *name;
	long addr;
	int arg_cnt;
	int btf_id;

	int fentry_prog_fd;
	int fexit_prog_fd;
};

#define MAX_FUNC_ARG_CNT 11

struct mass_attacher;

static _Thread_local struct mass_attacher *cur_attacher;

typedef bool (*func_filter_fn)(const struct mass_attacher *att,
			       const struct btf *btf, __u32 func_btf_id,
			       const char *name, __u32 func_id);

struct mass_attacher_opts {
	int max_func_cnt;
	bool verbose;
	bool debug;
	func_filter_fn func_filter;
};

struct mass_attacher {
	struct ksyms *ksyms;
	struct btf *vmlinux_btf;
	struct minimal_bpf *skel;

	struct bpf_program *fentries[MAX_FUNC_ARG_CNT + 1];
	struct bpf_program *fexits[MAX_FUNC_ARG_CNT + 1];
	struct bpf_insn *fentries_insns[MAX_FUNC_ARG_CNT + 1];
	struct bpf_insn *fexits_insns[MAX_FUNC_ARG_CNT + 1];
	size_t fentries_insn_cnts[MAX_FUNC_ARG_CNT + 1];
	size_t fexits_insn_cnts[MAX_FUNC_ARG_CNT + 1];

	bool verbose;
	bool debug;
	int max_func_cnt;
	func_filter_fn func_filter;

	struct func_info *func_infos;
	int func_cnt;

	int func_info_cnts[MAX_FUNC_ARG_CNT + 1];
	int func_info_id_for_arg_cnt[MAX_FUNC_ARG_CNT + 1];

	char **kprobes;
	int kprobe_cnt;

	int allow_glob_cnt;
	int deny_glob_cnt;
	char **allow_globs;
	char **deny_globs;
};

static struct mass_attacher *mass_attacher__new(struct mass_attacher_opts *opts)
{
	struct mass_attacher *att;

	att = calloc(1, sizeof(*att));
	if (!att)
		return NULL;

	if (!opts)
		return att;

	att->max_func_cnt = opts->max_func_cnt;
	att->verbose = opts->verbose;
	att->debug = opts->debug;
	if (att->debug)
		att->verbose = true;

	att->func_filter = opts->func_filter;

	return att;
}

static void mass_attacher__free(struct mass_attacher *att)
{
	int i;

	if (!att)
		return;

	if (att->skel)
		att->skel->bss->ready = false;

	ksyms__free(att->ksyms);
	btf__free(att->vmlinux_btf);

	free(att->func_infos);

	if (att->kprobes) {
		for (i = 0; i < att->kprobe_cnt; i++)
			free(att->kprobes[i]);
		free(att->kprobes);
	}

	for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
		free(att->fentries_insns[i]);
		free(att->fexits_insns[i]);
	}

	minimal_bpf__destroy(att->skel);

	free(att);
}

static bool is_valid_glob(const char *glob)
{
	int i, n;

	if (!glob) {
		fprintf(stderr, "NULL glob provided.\n");
		return false;
	}
	
	n = strlen(glob);
	if (n == 0) {
		fprintf(stderr, "Empty glob provided.\n");
		return false;
	}

	for (i = 0; i < n; i++) {
		if (glob[i] == '*' && i != 0 && i != n - 1) {
			fprintf(stderr,
				"Unsupported glob '%s': '*' allowed only at the beginning or end of a glob.\n",
				glob);
			return false;
		}
	}

	if (strcmp(glob, "**") == 0) {
		fprintf(stderr, "Unsupported glob '%s'.\n", glob);
		return false;
	}

	return true;
}

static bool glob_matches(const char *glob, const char *s)
{
	int n = strlen(glob);

	if (n == 1 && glob[0] == '*')
		return true;

	if (glob[0] == '*' && glob[n - 1] == '*') {
		const char *subs;
		/* substring match */

		/* this is hacky, but we don't want to allocate for no good reason */
		((char *)glob)[n - 1] = '\0';
		subs = strstr(s, glob + 1);
		((char *)glob)[n - 1] = '*';

		return subs != NULL;
	} else if (glob[0] == '*') {
		size_t nn = strlen(s);
		/* suffix match */

		/* too short for a given suffix */
		if (nn < n - 1)
			return false;

		return strcmp(s + nn - (n - 1), glob + 1) == 0;
	} else if (glob[n - 1] == '*') {
		/* prefix match */
		return strncmp(s, glob, n - 1) == 0;
	} else {
		/* exact match */
		return strcmp(glob, s) == 0;
	}
}

static int mass_attacher__allow_glob(struct mass_attacher *att, const char *glob)
{
	void *tmp, *s;

	if (!is_valid_glob(glob))
		return -EINVAL;

	tmp = realloc(att->allow_globs, (att->allow_glob_cnt + 1) * sizeof(*att->allow_globs));
	if (!tmp)
		return -ENOMEM;
	att->allow_globs = tmp;

	s = strdup(glob);
	att->allow_globs[att->allow_glob_cnt++] = s;
	if (!s)
		return -ENOMEM;

	return 0;
}

static int mass_attacher__deny_glob(struct mass_attacher *att, const char *glob)
{
	void *tmp, *s;

	if (!is_valid_glob(glob))
		return -EINVAL;

	tmp = realloc(att->deny_globs, (att->deny_glob_cnt + 1) * sizeof(*att->deny_globs));
	if (!tmp)
		return -ENOMEM;
	att->deny_globs = tmp;

	s = strdup(glob);
	att->deny_globs[att->deny_glob_cnt++] = s;
	if (!s)
		return -ENOMEM;

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.debug_libbpf)
		return 0;
	return vfprintf(stderr, format, args);
}

static int bump_rlimit(int resource, rlim_t max);
static int load_available_kprobes(struct mass_attacher *attacher);
static int hijack_prog(struct bpf_program *prog, int n,
		       struct bpf_insn *insns, int insns_cnt,
		       struct bpf_prog_prep_result *res);

static int func_arg_cnt(const struct btf *btf, int id);
static bool is_kprobe_ok(const struct mass_attacher *att, const char *name);
static bool is_func_type_ok(const struct btf *btf, const struct btf_type *t);

static int mass_attacher__prepare(struct mass_attacher *att)
{
	struct minimal_bpf *skel;
	int err, i, j, n;
	int func_skip;
	void *tmp;

	/* Load and cache /proc/kallsyms for IP <-> kfunc mapping */
	att->ksyms = ksyms__load();
	if (!att->ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms\n");
		return -EINVAL;
	}

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	err = bump_rlimit(RLIMIT_MEMLOCK, RLIM_INFINITY);
	if (err) {
		fprintf(stderr, "Failed to set RLIM_MEMLOCK. Won't be able to load BPF programs: %d\n", err);
		return err;
	}

	/* Allow opening lots of BPF programs */
	err = bump_rlimit(RLIMIT_NOFILE, 300000);
	if (err) {
		fprintf(stderr, "Failed to set RLIM_NOFILE. Won't be able to attach many BPF programs: %d\n", err);
		return err;
	}

	/* Load names of possible kprobes */
	err = load_available_kprobes(att);
	if (err) {
		fprintf(stderr, "Failed to read the list of available kprobes: %d\n", err);
		return err;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	att->skel = skel = minimal_bpf__open();
	if (!att->skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -EINVAL;
	}

	_Static_assert(MAX_FUNC_ARG_CNT == 11, "Unexpected maximum function arg count");
	att->fentries[0] = skel->progs.fentry0;
	att->fentries[1] = skel->progs.fentry1;
	att->fentries[2] = skel->progs.fentry2;
	att->fentries[3] = skel->progs.fentry3;
	att->fentries[4] = skel->progs.fentry4;
	att->fentries[5] = skel->progs.fentry5;
	att->fentries[6] = skel->progs.fentry6;
	att->fentries[7] = skel->progs.fentry7;
	att->fentries[8] = skel->progs.fentry8;
	att->fentries[9] = skel->progs.fentry9;
	att->fentries[10] = skel->progs.fentry10;
	att->fentries[11] = skel->progs.fentry11;
	att->fexits[0] = skel->progs.fexit0;
	att->fexits[1] = skel->progs.fexit1;
	att->fexits[2] = skel->progs.fexit2;
	att->fexits[3] = skel->progs.fexit3;
	att->fexits[4] = skel->progs.fexit4;
	att->fexits[5] = skel->progs.fexit5;
	att->fexits[6] = skel->progs.fexit6;
	att->fexits[7] = skel->progs.fexit7;
	att->fexits[8] = skel->progs.fexit8;
	att->fexits[9] = skel->progs.fexit9;
	att->fexits[10] = skel->progs.fexit10;
	att->fexits[11] = skel->progs.fexit11;

	att->vmlinux_btf = libbpf_find_kernel_btf();
	err = libbpf_get_error(att->vmlinux_btf);
	if (err) {
		fprintf(stderr, "Failed to load vmlinux BTF: %d\n", err);
		return -EINVAL;
	}

	n = btf__get_nr_types(att->vmlinux_btf);
	for (i = 1; i <= n; i++) {
		const struct btf_type *t = btf__type_by_id(att->vmlinux_btf, i);
		const char *func_name;
		const struct ksym *ksym;
		struct func_info *finfo;
		int arg_cnt;

		if (!btf_is_func(t))
			continue;

		func_name = btf__str_by_offset(att->vmlinux_btf, t->name_off);
		ksym = ksyms__get_symbol(att->ksyms, func_name);
		if (!ksym) {
			if (att->verbose)
				printf("Function '%s' not found in /proc/kallsyms! Skipping.\n", func_name);
			func_skip++;
			continue;
		}

		/* any deny glob forces skipping a function */
		for (j = 0; j < att->deny_glob_cnt; j++) {
			if (!glob_matches(att->deny_globs[j], func_name))
				continue;
			if (att->debug)
				printf("Function '%s' is denied by '%s' glob.\n",
				       func_name, att->deny_globs[j]);
			goto skip;
		}
		/* if any allow glob is specified, function has to match one of them */
		if (att->allow_glob_cnt) {
			for (j = 0; j < att->allow_glob_cnt; j++) {
				if (!glob_matches(att->allow_globs[j], func_name))
					continue;
				if (att->debug)
					printf("Function '%s' is allowed by '%s' glob.\n", func_name, att->allow_globs[j]);
				goto proceed;
			}
			if (att->debug)
				printf("Function '%s' doesn't match any allow glob, skipping.\n", func_name);
skip:
			func_skip++;
			continue;
		}

proceed:
		if (!is_kprobe_ok(att, func_name)) {
			if (att->debug)
				printf("Function '%s' is not attachable kprobe, skipping.\n", func_name);
			func_skip++;
			continue;
		}
		if (!is_func_type_ok(att->vmlinux_btf, t)) {
			if (att->debug)
				printf("Function '%s' has prototype incompatible with fentry/fexit, skipping.\n", func_name);
			func_skip++;
			continue;
		}
		if (att->max_func_cnt && att->func_cnt >= att->max_func_cnt) {
			if (att->verbose)
				printf("Maximum allowed number of functions (%d) reached, skipping the rest.\n",
				       att->max_func_cnt);
			break;
		}

		if (att->func_filter && !att->func_filter(att, att->vmlinux_btf, i, func_name, att->func_cnt)) {
			if (att->debug)
				printf("Function '%s' skipped due to custom filter function.\n", func_name);
			func_skip++;
			continue;
		}

		arg_cnt = func_arg_cnt(att->vmlinux_btf, i);

		tmp = realloc(att->func_infos, (att->func_cnt + 1) * sizeof(*att->func_infos));
		if (!tmp)
			return -ENOMEM;
		att->func_infos = tmp;

		finfo = &att->func_infos[att->func_cnt];
		memset(finfo, 0, sizeof(*finfo));

		finfo->addr = ksym->addr;
		finfo->name = ksym->name;
		finfo->arg_cnt = arg_cnt;
		finfo->btf_id = i;

		att->func_info_cnts[arg_cnt]++;
		if (!att->func_info_id_for_arg_cnt[arg_cnt])
			att->func_info_id_for_arg_cnt[arg_cnt] = att->func_cnt;

		att->func_cnt++;

		if (att->debug)
			printf("Found function '%s' at address 0x%lx...\n", func_name, ksym->addr);
	}

	if (att->func_cnt == 0) {
		fprintf(stderr, "No matching functions found.\n");
		return -ENOENT;
	}

	for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
		struct func_info *finfo;

		if (att->func_info_cnts[i]) {
			finfo = &att->func_infos[att->func_info_id_for_arg_cnt[i]];
			bpf_program__set_attach_target(att->fentries[i], 0, finfo->name);
			bpf_program__set_attach_target(att->fexits[i], 0, finfo->name);
			bpf_program__set_prep(att->fentries[i], 1, hijack_prog);
			bpf_program__set_prep(att->fexits[i], 1, hijack_prog);
			
			if (att->verbose)
				printf("Found total %d functions with %d arguments.\n", att->func_info_cnts[i], i);
		} else {
			bpf_program__set_autoload(att->fentries[i], false);
			bpf_program__set_autoload(att->fexits[i], false);
		}
	}

	if (att->verbose) {
		printf("Found %d attachable functions in total.\n", att->func_cnt);
		printf("Skipped %d functions in total.\n", func_skip);
	}

	bpf_map__set_max_entries(skel->maps.ip_to_id, att->func_cnt);

	return 0;
}

static int bump_rlimit(int resource, rlim_t max)
{
	struct rlimit rlim_new = {
		.rlim_cur	= max,
		.rlim_max	= max,
	};

	if (setrlimit(resource, &rlim_new))
		return -errno;

	return 0;
}

static int str_cmp(const void *a, const void *b)
{
	const char * const *s1 = a, * const *s2 = b;

	return strcmp(*s1, *s2);
}

static int load_available_kprobes(struct mass_attacher *att)
{
	static char buf[512];
	static char buf2[512];
	const char *fname = "/sys/kernel/tracing/available_filter_functions";
	int cnt, err;
	void *tmp, *s;
	FILE *f;

	f = fopen(fname, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open %s: %d\n", fname, err);
		return err;
	}

	while ((cnt = fscanf(f, "%s%[^\n]\n", buf, buf2)) == 1) {
		tmp = realloc(att->kprobes, (att->kprobe_cnt + 1) * sizeof(*att->kprobes));
		if (!tmp)
			return -ENOMEM;
		att->kprobes = tmp;

		s = strdup(buf);
		att->kprobes[att->kprobe_cnt++] = s;
		if (!s)
			return -ENOMEM;
	}

	qsort(att->kprobes, att->kprobe_cnt, sizeof(char *), str_cmp);

	if (att->verbose)
		printf("Discovered %d available kprobes!\n", att->kprobe_cnt);

	return 0;
}

static int prog_arg_cnt(const struct mass_attacher *att, const struct bpf_program *p)
{
	int i;

	for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
		if (att->fentries[i] == p || att->fexits[i] == p)
			return i;
	}

	return -1;
}

static int hijack_prog(struct bpf_program *prog, int n,
		       struct bpf_insn *insns, int insns_cnt,
		       struct bpf_prog_prep_result *res)
{
	struct mass_attacher *att = cur_attacher;
	struct bpf_insn **insns_ptr;
	size_t *insn_cnt_ptr;
	int arg_cnt;

	arg_cnt = prog_arg_cnt(att, prog);

	if (strncmp(bpf_program__name(prog), "fexit", sizeof("fexit") - 1) == 0) {
		insn_cnt_ptr = &att->fexits_insn_cnts[arg_cnt];
		insns_ptr = &att->fexits_insns[arg_cnt];
	} else {
		insn_cnt_ptr = &att->fentries_insn_cnts[arg_cnt];
		insns_ptr = &att->fentries_insns[arg_cnt];
	}

	*insns_ptr = malloc(sizeof(*insns) * insns_cnt);
	memcpy(*insns_ptr, insns, sizeof(*insns) * insns_cnt);
	*insn_cnt_ptr = insns_cnt;

	/* By not setting res->new_insn_ptr and res->new_insns_cnt we are
	 * preventing unnecessary load of the "prototype" BPF program.
	 * But we do load those programs in debug mode to use libbpf's logic
	 * of showing BPF verifier log, which is useful to debug verification
	 * errors.
	 */
	if (att->debug) {
		res->new_insn_ptr = insns;
		res->new_insn_cnt = insns_cnt;
	}

	return 0;
}


static int clone_prog(const struct bpf_program *prog,
		      struct bpf_insn *insns, size_t insn_cnt, int attach_btf_id);

static int mass_attacher__load(struct mass_attacher *att)
{
	int err, i;

	/* we can't pass extra context to hijack_progs, so we set thread-local
	 * cur_attacher variable temporarily for the duration of skeleton's
	 * load phase
	 */
	cur_attacher = att;
	/* Load & verify BPF programs */
	err = minimal_bpf__load(att->skel);
	cur_attacher = NULL;

	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return err;
	}

	if (att->debug)
		printf("Preparing %d BPF program copies...\n", att->func_cnt * 2);

	for (i = 0; i < att->func_cnt; i++) {
		struct func_info *finfo = &att->func_infos[i];
		const char *func_name = att->func_infos[i].name;
		long func_addr = att->func_infos[i].addr;

		err = bpf_map_update_elem(bpf_map__fd(att->skel->maps.ip_to_id), &func_addr, &i, 0);
		if (err) {
			err = -errno;
			fprintf(stderr, "Failed to add 0x%lx -> '%s' lookup entry to BPF map: %d\n",
				func_addr, func_name, err);
			return err;
		}

		err = clone_prog(att->fentries[finfo->arg_cnt],
				 att->fentries_insns[finfo->arg_cnt],
				 att->fentries_insn_cnts[finfo->arg_cnt],
				 finfo->btf_id);
		if (err < 0) {
			fprintf(stderr, "Failed to clone FENTRY BPF program for function '%s': %d\n", func_name, err);
			return err;
		}
		finfo->fentry_prog_fd = err;

		err = clone_prog(att->fexits[finfo->arg_cnt],
				 att->fexits_insns[finfo->arg_cnt],
				 att->fexits_insn_cnts[finfo->arg_cnt],
				 finfo->btf_id);
		if (err < 0) {
			fprintf(stderr, "Failed to clone FEXIT BPF program for function '%s': %d\n", func_name, err);
			return err;
		}
		finfo->fexit_prog_fd = err;
	}
	return 0;
}

static int clone_prog(const struct bpf_program *prog,
		      struct bpf_insn *insns, size_t insn_cnt, int attach_btf_id)
{
	struct bpf_load_program_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));

	attr.prog_type = bpf_program__get_type(prog);
	attr.expected_attach_type = bpf_program__get_expected_attach_type(prog);
	attr.name = bpf_program__name(prog);
	attr.insns = insns;
	attr.insns_cnt = insn_cnt;
	attr.license = "Dual BSD/GPL";
	attr.attach_btf_id = attach_btf_id;

	fd = bpf_load_program_xattr(&attr, NULL, 0);
	if (fd < 0)
		return -errno;

	return fd;
}

static int mass_attacher__attach(struct mass_attacher *att)
{
	int i, err, prog_fd;

	for (i = 0; i < att->func_cnt; i++) {
		if (att->debug)
			printf("Attaching function '%s' (#%d at addr %lx)...\n",
			       att->func_infos[i].name, i + 1, att->func_infos[i].addr);

		prog_fd = att->func_infos[i].fentry_prog_fd;
		err = bpf_raw_tracepoint_open(NULL, prog_fd);
		if (err < 0) {
			fprintf(stderr, "Failed to attach FENTRY prog (fd %d) for func #%d (%s), skipping: %d\n",
				prog_fd, i + 1, att->func_infos[i].name, -errno);
		}

		prog_fd = att->func_infos[i].fexit_prog_fd;
		err = bpf_raw_tracepoint_open(NULL, prog_fd);
		if (err < 0) {
			fprintf(stderr, "Failed to attach FEXIT prog (fd %d) for func #%d (%s), skipping: %d\n",
				prog_fd, i + 1, att->func_infos[i].name, -errno);
		}
	}

	if (att->verbose)
		printf("Total %d BPF programs attached successfully!\n", 2 * att->func_cnt);

	return 0;
}

static struct minimal_bpf *mass_attacher__skeleton(struct mass_attacher *att)
{
	return att->skel;
}

static const struct btf *mass_attacher__btf(const struct mass_attacher *att)
{
	return att->vmlinux_btf;
}

static void mass_attacher__activate(struct mass_attacher *att)
{
	att->skel->bss->ready = true;
}

static int mass_attacher__func_cnt(const struct mass_attacher *att)
{
	return att->func_cnt;
}

static const struct func_info *mass_attacher__func(const struct mass_attacher *att, int id)
{
	if (id < 0 || id >= att->func_cnt)
		return NULL;
	return &att->func_infos[id];
}

static bool is_kprobe_ok(const struct mass_attacher *att, const char *name)
{
	void *r;

	/*
	if (strcmp(name, "__x64_sys_getpgid") == 0) 
		r = NULL;
	*/
	r = bsearch(&name, att->kprobes, att->kprobe_cnt, sizeof(void *), str_cmp);

	return r != NULL;
}

static int func_arg_cnt(const struct btf *btf, int id)
{
	const struct btf_type *t;

	t = btf__type_by_id(btf, id);
	t = btf__type_by_id(btf, t->type);
	return btf_vlen(t);
}

static bool is_arg_type_ok(const struct btf *btf, const struct btf_type *t)
{
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);
	if (!btf_is_int(t) && !btf_is_ptr(t) && !btf_is_enum(t))
		return false;
	return true;
}

static bool is_ret_type_ok(const struct btf *btf, const struct btf_type *t)
{
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);

	if (btf_is_int(t) || btf_is_enum(t))
		return true;

	/* non-pointer types are rejected */
	if (!btf_is_ptr(t))
		return false;

	/* pointer to void is fine */
	if (t->type == 0) 
		return true;

	/* only pointer to struct/union is allowed */
	t = btf__type_by_id(btf, t->type);
	if (!btf_is_composite(t))
		return false;

	return true;
}

static bool is_func_type_ok(const struct btf *btf, const struct btf_type *t)
{
	const struct btf_param *p;
	int i;

	t = btf__type_by_id(btf, t->type);
	if (btf_vlen(t) > MAX_FUNC_ARG_CNT)
		return false;

	/* IGNORE VOID FUNCTIONS, THIS SHOULDN'T BE DONE IN GENERAL!!! */
	if (!t->type)
		return false;

	if (t->type && !is_ret_type_ok(btf, btf__type_by_id(btf, t->type)))
		return false;

	for (i = 0; i < btf_vlen(t); i++) {
		p = btf_params(t) + i;

		/* vararg not supported */
		if (!p->type)
			return false;

		if (!is_arg_type_ok(btf, btf__type_by_id(btf, p->type)))
			return false;
	}

	return true;
}

static const char *bpf_entry_globs[] = {
	"*_sys_bpf",
	NULL,
};

static const char *bpf_allow_globs[] = {
	"*bpf_*",
	"do_check*",
	"reg_*",
	"check_*",
	"btf_*",
	"_btf_*",
	"__btf_*",
	"find_*",
	"resolve_*",
	"convert_*",
	"release_*",
	"adjust_*",
	"verifier_*",
	"verbose_*",
	"type_*",
	"arg_*",
	"sanitize_*",
	"print_*",
	//"map_*",
	"ringbuf_*",
	"array_*",
	"__vmalloc_*",
	"__alloc*",
	"pcpu_*",
	"memdup_*",

	"copy_*",
	"_copy_*",
	"raw_copy_*",

	NULL,
};

static const char *bpf_deny_globs[] = {
	"bpf_get_smp_processor_id",
	"mm_init",
	"migrate_enable",
	"migrate_disable",
	"rcu_read_lock_strict",
	"rcu_read_unlock_strict",
	"__bpf_prog_enter",
	"__bpf_prog_exit",
	"__bpf_prog_enter_sleepable",
	"__bpf_prog_exit_sleepable",
	"__cant_migrate",
	"bpf_get_current_pid_tgid",
	"__bpf_prog_run_args",

	"__x64_sys_select",
	"__x64_sys_epoll_wait",
	"__x64_sys_ppoll",
	
	/* too noisy */
	"bpf_lsm_*",
	"check_cfs_rq_runtime",
	"find_busiest_group",
	"find_vma*",

	NULL,
};

static const char *perf_entry_globs[] = {
	"*_sys_perf_event_open",
	NULL,
};

static const char *perf_allow_globs[] = {
	"perf_*",
	NULL,
};

static const char *perf_deny_globs[] = {
	"bla",
	NULL,
};

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

struct dwime_ctx {
	struct mass_attacher *att;
	struct minimal_bpf *skel;
	struct ksyms *ksyms;
	struct addr2line *a2l;
};

/* fexit logical stack trace item */
struct fstack_item {
	const char *name;
	long res;
	long lat;
	bool finished;
	bool stitched;
};

static int filter_fstack(struct dwime_ctx *ctx, struct fstack_item *r, const struct call_stack *s)
{
	struct mass_attacher *att = ctx->att;
	struct minimal_bpf *skel = ctx->skel;
	const struct func_info *finfo;
	struct fstack_item *fitem;
	const char *fname;
	int i, id, flags, cnt;

	for (i = 0, cnt = 0; i < s->max_depth; i++, cnt++) {
		id = s->func_ids[i];
		flags = skel->bss->func_flags[id];
		finfo = mass_attacher__func(att, id);
		fname = finfo->name;

		fitem = &r[cnt];
		fitem->name = fname;
		fitem->stitched = false;
		if (i >= s->depth) {
			fitem->finished = true;
			fitem->lat = s->func_lat[i];
		} else {
			fitem->lat = 0;
		}
		if (flags & FUNC_NEEDS_SIGN_EXT)
			fitem->res = (long)(int)s->func_res[i];
		else
			fitem->res = s->func_res[i];
		fitem->lat = s->func_lat[i];
	}

	/* no stitched together stack */
	if (s->max_depth + 1 != s->saved_depth)
		return cnt;

	for (i = s->saved_depth - 1; i < s->saved_max_depth; i++, cnt++) {
		id = s->saved_ids[i];
		flags = skel->bss->func_flags[id];
		finfo = mass_attacher__func(att, id);
		fname = finfo->name;

		fitem = &r[cnt];
		fitem->name = fname;
		fitem->stitched = true;
		fitem->finished = true;
		fitem->lat = s->saved_lat[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			fitem->res = (long)(int)s->saved_res[i];
		else
			fitem->res = s->saved_res[i];
	}

	return cnt;
}

/* actual kernel stack trace item */
struct kstack_item {
	const struct ksym *ksym;
	long addr;
	bool filtered;
};

static bool is_bpf_tramp(const struct kstack_item *item)
{
	static char bpf_tramp_pfx[] = "bpf_trampoline_";

	if (!item->ksym)
		return false;

	return strncmp(item->ksym->name, bpf_tramp_pfx, sizeof(bpf_tramp_pfx) - 1) == 0
	       && isdigit(item->ksym->name[sizeof(bpf_tramp_pfx)]);
}

static bool is_bpf_prog(const struct kstack_item *item)
{
	static char bpf_prog_pfx[] = "bpf_prog_";

	if (!item->ksym)
		return false;

	return strncmp(item->ksym->name, bpf_prog_pfx, sizeof(bpf_prog_pfx) - 1) == 0
	       && isxdigit(item->ksym->name[sizeof(bpf_prog_pfx)]);
}

#define FTRACE_OFFSET 0x5

static int filter_kstack(struct dwime_ctx *ctx, struct kstack_item *r, const struct call_stack *s)
{
	struct ksyms *ksyms = ctx->ksyms;
	int i, n, p;

	/* lookup ksyms and reverse stack trace to match natural call order */
	n = s->kstack_sz / 8;
	for (i = 0; i < n; i++) {
		struct kstack_item *item = &r[n - i - 1];

		item->addr = s->kstack[i];
		item->filtered = false;
		item->ksym = ksyms__map_addr(ksyms, item->addr);
		if (!item->ksym)
			continue;
	}

	/* perform addiitonal post-processing to filter out bpf_trampoline and
	 * bpf_prog symbols, fixup fexit patterns, etc
	 */
	for (i = 0, p = 0; i < n; i++) {
		struct kstack_item *item = &r[p];

		*item = r[i];

		if (!item->ksym) {
			p++;
			continue;
		}

		/* Ignore bpf_trampoline frames and fix up stack traces.
		 * When fexit program happens to be inside the stack trace,
		 * a following stack trace pattern will be apparent (taking into account inverted order of frames
		 * which we did few lines above):
		 *     ffffffff8116a3d5 bpf_map_alloc_percpu+0x5
		 *     ffffffffa16db06d bpf_trampoline_6442494949_0+0x6d
		 *     ffffffff8116a40f bpf_map_alloc_percpu+0x3f
		 * 
		 * bpf_map_alloc_percpu+0x5 is real, by it just calls into the
		 * trampoline, which them calls into original call
		 * (bpf_map_alloc_percpu+0x3f). So the last item is what
		 * really matters, everything else is just a distraction, so
		 * try to detect this and filter it out. Unless we are in
		 * verbose mode, of course, in which case we live a hint
		 * that this would be filtered out (helps with debugging
		 * overall), but otherwise is preserved.
		 */
		if (i + 2 < n && is_bpf_tramp(&r[i + 1])
		    && r[i].ksym == r[i + 2].ksym
		    && r[i].addr - r[i].ksym->addr == FTRACE_OFFSET) {
			if (env.verbose) {
				item->filtered = true;
				p++;
				continue;
			}

			/* skip two elements and process useful item */
			*item = r[i + 2];
			continue;
		}

		/* Iignore bpf_trampoline and bpf_prog in stack trace, those
		 * are most probably part of our own instrumentation, but if
		 * not, you can still see them in verbose mode.
		 * Similarly, remove bpf_get_stack_raw_tp, which seems to be
		 * always there due to call to bpf_get_stack() from BPF
		 * program.
		 */
		if (is_bpf_tramp(&r[i]) || is_bpf_prog(&r[i])
		    || strcmp(r[i].ksym->name, "bpf_get_stack_raw_tp") == 0) {
			if (env.verbose) {
				item->filtered = true;
				p++;
				continue;
			}

			if (i + 1 < n)
				*item = r[i + 1];
			continue;
		}

		p++;
	}

	return p;
}

static const char *err_to_str(long err) {
	static const char *err_names[] = {
		[1] = "EPERM", [2] = "ENOENT", [3] = "ESRCH",
		[4] = "EINTR", [5] = "EIO", [6] = "ENXIO", [7] = "E2BIG",
		[8] = "ENOEXEC", [9] = "EBADF", [10] = "ECHILD", [11] = "EAGAIN",
		[12] = "ENOMEM", [13] = "EACCES", [14] = "EFAULT", [15] = "ENOTBLK",
		[16] = "EBUSY", [17] = "EEXIST", [18] = "EXDEV", [19] = "ENODEV",
		[20] = "ENOTDIR", [21] = "EISDIR", [22] = "EINVAL", [23] = "ENFILE",
		[24] = "EMFILE", [25] = "ENOTTY", [26] = "ETXTBSY", [27] = "EFBIG",
		[28] = "ENOSPC", [29] = "ESPIPE", [30] = "EROFS", [31] = "EMLINK",
		[32] = "EPIPE", [33] = "EDOM", [34] = "ERANGE", [35] = "EDEADLK",
		[36] = "ENAMETOOLONG", [37] = "ENOLCK", [38] = "ENOSYS", [39] = "ENOTEMPTY",
		[40] = "ELOOP", [42] = "ENOMSG", [43] = "EIDRM", [44] = "ECHRNG",
		[45] = "EL2NSYNC", [46] = "EL3HLT", [47] = "EL3RST", [48] = "ELNRNG",
		[49] = "EUNATCH", [50] = "ENOCSI", [51] = "EL2HLT", [52] = "EBADE",
		[53] = "EBADR", [54] = "EXFULL", [55] = "ENOANO", [56] = "EBADRQC",
		[57] = "EBADSLT", [59] = "EBFONT", [60] = "ENOSTR", [61] = "ENODATA",
		[62] = "ETIME", [63] = "ENOSR", [64] = "ENONET", [65] = "ENOPKG",
		[66] = "EREMOTE", [67] = "ENOLINK", [68] = "EADV", [69] = "ESRMNT",
		[70] = "ECOMM", [71] = "EPROTO", [72] = "EMULTIHOP", [73] = "EDOTDOT",
		[74] = "EBADMSG", [75] = "EOVERFLOW", [76] = "ENOTUNIQ", [77] = "EBADFD",
		[78] = "EREMCHG", [79] = "ELIBACC", [80] = "ELIBBAD", [81] = "ELIBSCN",
		[82] = "ELIBMAX", [83] = "ELIBEXEC", [84] = "EILSEQ", [85] = "ERESTART",
		[86] = "ESTRPIPE", [87] = "EUSERS", [88] = "ENOTSOCK", [89] = "EDESTADDRREQ",
		[90] = "EMSGSIZE", [91] = "EPROTOTYPE", [92] = "ENOPROTOOPT", [93] = "EPROTONOSUPPORT",
		[94] = "ESOCKTNOSUPPORT", [95] = "EOPNOTSUPP", [96] = "EPFNOSUPPORT", [97] = "EAFNOSUPPORT",
		[98] = "EADDRINUSE", [99] = "EADDRNOTAVAIL", [100] = "ENETDOWN", [101] = "ENETUNREACH",
		[102] = "ENETRESET", [103] = "ECONNABORTED", [104] = "ECONNRESET", [105] = "ENOBUFS",
		[106] = "EISCONN", [107] = "ENOTCONN", [108] = "ESHUTDOWN", [109] = "ETOOMANYREFS",
		[110] = "ETIMEDOUT", [111] = "ECONNREFUSED", [112] = "EHOSTDOWN", [113] = "EHOSTUNREACH",
		[114] = "EALREADY", [115] = "EINPROGRESS", [116] = "ESTALE", [117] = "EUCLEAN",
		[118] = "ENOTNAM", [119] = "ENAVAIL", [120] = "EISNAM", [121] = "EREMOTEIO",
		[122] = "EDQUOT", [123] = "ENOMEDIUM", [124] = "EMEDIUMTYPE", [125] = "ECANCELED",
		[126] = "ENOKEY", [127] = "EKEYEXPIRED", [128] = "EKEYREVOKED", [129] = "EKEYREJECTED",
		[130] = "EOWNERDEAD", [131] = "ENOTRECOVERABLE", [132] = "ERFKILL", [133] = "EHWPOISON",
		[512] = "ERESTARTSYS", [513] = "ERESTARTNOINTR", [514] = "ERESTARTNOHAND", [515] = "ENOIOCTLCMD",
		[516] = "ERESTART_RESTARTBLOCK", [517] = "EPROBE_DEFER", [518] = "EOPENSTALE", [519] = "ENOPARAM",
		[521] = "EBADHANDLE", [522] = "ENOTSYNC", [523] = "EBADCOOKIE", [524] = "ENOTSUPP",
		[525] = "ETOOSMALL", [526] = "ESERVERFAULT", [527] = "EBADTYPE", [528] = "EJUKEBOX",
		[529] = "EIOCBQUEUED", [530] = "ERECALLCONFLICT",
	};

	if (err < 0)
		err = -err;
	if (err < ARRAY_SIZE(err_names))
		return err_names[err];
	return NULL;
}

static int detect_linux_src_loc(const char *path)
{
	static const char *linux_dirs[] = {
		"arch/", "kernel/", "include/", "block/", "fs/", "net/",
		"drivers/", "mm/", "ipc/", "security/", "lib/", "crypto/",
		"certs/", "init/", "lib/", "scripts/", "sound/", "tools/",
		"usr/", "virt/", 
	};
	int i;
	char *p;

	for (i = 0; i < ARRAY_SIZE(linux_dirs); i++) {
		p = strstr(path, linux_dirs[i]);
		if (p)
			return p - path;
	}

	return 0;
}

static void print_item(struct dwime_ctx *ctx, const struct fstack_item *fitem, const struct kstack_item *kitem)
{
	const int err_width = 12;
	const int lat_width = 12;
	static struct symb_resp resps[64];
	struct symb_resp *resp = NULL;
	int symb_cnt = 0, i, line_off, p = 0;
	const char *fname;
	int src_print_off = 70, func_print_off;

	if (kitem && !kitem->filtered) {
		symb_cnt = addr2line__symbolize(ctx->a2l, kitem->addr, resps);
		if (symb_cnt < 0)
			symb_cnt = 0;
		if (symb_cnt > 0)
			resp = &resps[symb_cnt - 1];
	}

	/* this should be rare, either a bug or we couldn't get valid kernel
	 * stack trace
	 */
	if (!kitem)
		p += printf("!");
	else
		p += printf(" ");

	p += printf("%c ", (fitem && fitem->stitched) ? '*' : ' ');

	if (fitem && !fitem->finished) {
		p += printf("%*s %-*s ", lat_width, "...", err_width, "[...]");
	} else if (fitem) {
		p += printf("%*ldus ", lat_width - 2 /* for "us" */, fitem->lat / 1000);
		if (fitem->res == 0) {
			p += printf("%-*s ", err_width, "[NULL]");
		} else {
			const char *errstr;
			int print_cnt;

			errstr = err_to_str(fitem->res);
			if (errstr)
				print_cnt = printf("[-%s]", errstr);
			else
				print_cnt = printf("[%ld]", fitem->res);
			p += print_cnt;
			p += printf("%*s ", err_width - print_cnt, "");
		}
	} else {
		p += printf("%*s ", lat_width + 1 + err_width, "");
	}

	if (env.verbose) {
		if (kitem && kitem->filtered) 
			p += printf("~%016lx ", kitem->addr);
		else if (kitem)
			p += printf(" %016lx ", kitem->addr);
		else
			p += printf(" %*s ", 16, "");
	}

	if (kitem && kitem->ksym)
		fname = kitem->ksym->name;
	else if (fitem)
		fname = fitem->name;
	else
		fname = "";

	func_print_off = p;
	p += printf("%s", fname);
	if (kitem && kitem->ksym)
		p += printf("+0x%lx", kitem->addr - kitem->ksym->addr);
	if (symb_cnt) {
		if (env.verbose)
			src_print_off += 18; /* for extra " %16lx " */
		p += printf(" %*s(", p < src_print_off ? src_print_off - p : 0, "");

		if (strcmp(fname, resp->fname) != 0)
			p += printf("%s @ ", resp->fname);

		line_off = detect_linux_src_loc(resp->line);
		p += printf("%s)", resp->line + line_off);
	}

	p += printf("\n");

	for (i = 1, resp--; i < symb_cnt; i++, resp--) {
		p = printf("%*s. %s", func_print_off, "", resp->fname);
		line_off = detect_linux_src_loc(resp->line);
		printf(" %*s(%s)\n",
		       p < src_print_off ? src_print_off - p : 0, "",
		       resp->line + line_off);
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	static struct fstack_item fstack[MAX_FSTACK_DEPTH];
	static struct kstack_item kstack[MAX_KSTACK_DEPTH];
	const struct fstack_item *fitem;
	const struct kstack_item *kitem;
	struct dwime_ctx *dctx = ctx;
	const struct call_stack *s = data;
	int i, j, fstack_n, kstack_n;

	if (!s->is_err)
		return 0;

	if (env.debug) {
		printf("GOT %s STACK (depth %u):\n", s->is_err ? "ERROR" : "SUCCESS", s->max_depth);
		printf("DEPTH %d MAX DEPTH %d SAVED DEPTH %d MAX SAVED DEPTH %d\n",
				s->depth, s->max_depth, s->saved_depth, s->saved_max_depth);
	}

	fstack_n = filter_fstack(dctx, fstack, s);
	if (fstack_n < 0) {
		fprintf(stderr, "FAILURE DURING FILTERING FUNCTION STACK!!! %d\n", fstack_n);
		return -1;
	}
	kstack_n = filter_kstack(dctx, kstack, s);
	if (kstack_n < 0) {
		fprintf(stderr, "FAILURE DURING FILTERING KERNEL STACK!!! %d\n", kstack_n);
		return -1;
	}
	if (env.debug) {
		printf("FSTACK (%d items):\n", fstack_n);
		printf("KSTACK (%d items out of original %ld):\n", kstack_n, s->kstack_sz / 8);
	}

	i = 0;
	j = 0;
	while (i < fstack_n) {
		fitem = &fstack[i];
		kitem = j < kstack_n ? &kstack[j] : NULL;

		if (!kitem) {
			/* this shouldn't happen unless we got no kernel stack
			 * or there is some bug
			 */
			print_item(dctx, fitem, NULL);
			i++;
			continue;
		}

		/* exhaust unknown kernel stack items, assuming we should find
		 * kstack_item matching current fstack_item eventually, which
		 * should be the case when kernel stack trace is correct
		 */
		if (!kitem->ksym || kitem->filtered
		    || strcmp(kitem->ksym->name, fitem->name) != 0) {
			print_item(dctx, NULL, kitem);
			j++;
			continue;
		}

		/* happy case, lots of info, yay */
		print_item(dctx, fitem, kitem);
		i++;
		j++;
		continue;
	}

	for (; j < kstack_n; j++) {
		print_item(dctx, NULL, &kstack[j]);
	}

	printf("\n\n");

	return 0;
}

struct addr2line {
	FILE *read_pipe;
	FILE *write_pipe;
	bool inlines;
};

static void addr2line__free(struct addr2line *a2l)
{
	if (!a2l)
		return;

	if (a2l->read_pipe)
		fclose(a2l->read_pipe);
	if (a2l->write_pipe)
		fclose(a2l->write_pipe);

	free(a2l);
}

static void sig_pipe(int signo)
{
	/*
	printf("SIGPIPE caught, exiting!\n");
	*/
	exit(1);
}

static struct addr2line *addr2line__init(const char *filename, const char *vmlinux, bool inlines)
{
	struct addr2line *a2l;
	int fd1[2], fd2[2];
	int pid;
	//int fd;

	a2l = calloc(1, sizeof(*a2l));
	if (!a2l)
		return NULL;

	if (signal(SIGPIPE, sig_pipe) == SIG_ERR) {
		fprintf(stderr, "Failed to install SIGPIPE handler: %d\n", -errno);
		goto err_out;
	}

	if (pipe(fd1) < 0 || pipe(fd2) < 0) {
		fprintf(stderr, "Failed to create pipes for addr2line: %d\n", -errno);
		goto err_out;
	}

//	pid = pty_fork(&fd);
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork() addr2line: %d\n", -errno);
		goto err_out;
	}

	if (pid == 0) {
		/* CHILD PROCESS */
		//set_noecho(STDIN_FILENO);

		close(fd1[1]);
		close(fd2[0]);

		if (fd1[0] != STDIN_FILENO) {
			if (dup2(fd1[0], STDIN_FILENO) != STDIN_FILENO) {
				fprintf(stderr, "CHILD: failed to dup2() stdin: %d\n", -errno);
				exit(1);
			}
			close(fd1[0]);
		}
		if (fd2[1] != STDOUT_FILENO) {
			if (dup2(fd2[1], STDOUT_FILENO) != STDOUT_FILENO) {
				fprintf(stderr, "CHILD: failed to dup2() stdout: %d\n", -errno);
				exit(1);
			}
			close(fd2[1]);
		}
		if (execlp("stdbuf", "-oL", "-eL", filename, "-f", "--llvm", "-e", vmlinux, inlines ? "-i" : NULL, NULL) < 0) {
			fprintf(stderr, "CHILD: failed to exec() addr2line: %d\n", -errno);
			exit(1);
		}
		exit(2); /* should never reach this */
	}

	close(fd1[0]);
	close(fd2[1]);

	/*
	a2l->pipe = fdopen(fd, "w");
	if (!a2l->pipe) {
		fprintf(stderr, "Failed to fdopen() pty pipe: %d\n", -errno);
		goto err_out;
	}
	*/
	a2l->write_pipe = fdopen(fd1[1], "w");
	if (!a2l->write_pipe) {
		fprintf(stderr, "Failed to fdopen() write pipe: %d\n", -errno);
		goto err_out;
	}
	a2l->read_pipe = fdopen(fd2[0], "r");
	if (!a2l->read_pipe) {
		fprintf(stderr, "Failed to fdopen() write pipe: %d\n", -errno);
		goto err_out;
	}
	//loop(fd 0);

	return a2l;

err_out:
	addr2line__free(a2l);
	return NULL;
}

static int addr2line__symbolize(const struct addr2line *a2l, long addr,
				struct symb_resp *resp)
{
	int err, cnt = 0;

	err = fprintf(a2l->write_pipe, "%lx\n", addr);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to symbolize %lx: %d\n", addr, err);
		return err;
	}
	fflush(a2l->write_pipe);

	while (true) {
		if (fgets(resp->fname, sizeof(resp->fname), a2l->read_pipe) == NULL) {
			err = -errno;
			fprintf(stderr, "Failed to get symbolized function name: %d\n", err);
			return err;
		}
		resp->fname[strlen(resp->fname) - 1] = '\0';

		/* empty line denotes end of response */
		if (resp->fname[0] == '\0')
			break;

		if (fgets(resp->line, sizeof(resp->line), a2l->read_pipe) == NULL) {
			err = -errno;
			fprintf(stderr, "Failed to get file/line info: %d\n", err);
			return err;
		}

		resp->line[strlen(resp->line) - 1] = '\0';

		if (strcmp(resp->line, "??:0:0") == 0)
			continue;

		resp++;
		cnt++;
	}

	return cnt;
}

static int func_flags(const char *func_name, const struct btf *btf, const struct btf_type *t)
{
	t = btf__type_by_id(btf, t->type);
	if (!t->type)
		return FUNC_CANT_FAIL;

	t = btf__type_by_id(btf, t->type);
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);

	if (btf_is_ptr(t))
		return FUNC_RET_PTR; /* can fail, no sign extension */

	/* unsigned is treated as non-failing */
	if (btf_is_int(t) && !(btf_int_encoding(t) & BTF_INT_SIGNED))
		return FUNC_CANT_FAIL;

	/* byte and word are treated as non-failing */
	if (t->size < 4)
		return FUNC_CANT_FAIL;

	/* integers need sign extension */
	if (t->size == 4)
		return FUNC_NEEDS_SIGN_EXT;

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct mass_attacher_opts att_opts = {};
	struct mass_attacher *att = NULL;
	struct minimal_bpf *skel = NULL;
	struct dwime_ctx dwime_ctx = {};
	const struct btf *vmlinux_btf = NULL;
	int err, i, j, k, n;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return -1;

	if (env.entry_glob_cnt + env.preset_cnt == 0) {
		fprintf(stderr, "No entry point globs specified. "
				"Please provide entry glob(s) ('-e GLOB') and/or any preset ('-p PRESET').\n");
		return -1;
	}

	if (env.symb_lines) {
		const char *addr2line_path = "/home/vmuser/local/libbpf-bootstrap/src/addr2line";
		const char *vmlinux_path = "/home/vmuser/local/linux-build/default/vmlinux";

		dwime_ctx.a2l = addr2line__init(addr2line_path, vmlinux_path,
						env.symb_inlines);
		if (!dwime_ctx.a2l) {
			fprintf(stderr, "Failed to start %s against vmlinux image at %s!\n",
				addr2line_path, vmlinux_path);
			return -1;
		}
	}

	att_opts.verbose = env.verbose;
	att_opts.debug = env.debug;
	att = mass_attacher__new(&att_opts);
	if (!att)
		goto cleanup;

	for (i = 0; i < env.preset_cnt; i++) {
		const struct preset *p = env.presets[i];

		/* entry globs are also allow globs */
		for (j = 0; p->entry_globs[j]; j++) {
			err = mass_attacher__allow_glob(att, p->entry_globs[j]);
			if (err)
				goto cleanup;
		}
		for (j = 0; p->allow_globs[j]; j++) {
			err = mass_attacher__allow_glob(att, p->allow_globs[j]);
			if (err)
				goto cleanup;
		}
		for (j = 0; p->deny_globs[j]; j++) {
			err = mass_attacher__deny_glob(att, p->deny_globs[j]);
			if (err)
				goto cleanup;
		}
	}
	/* entry globs are allow globs as well */
	for (i = 0; i < env.entry_glob_cnt; i++) {
		err = mass_attacher__allow_glob(att, env.entry_globs[i]);
		if (err)
			goto cleanup;
	}
	for (i = 0; i < env.allow_glob_cnt; i++) {
		err = mass_attacher__allow_glob(att, env.allow_globs[i]);
		if (err)
			goto cleanup;
	}
	for (i = 0; i < env.deny_glob_cnt; i++) {
		err = mass_attacher__deny_glob(att, env.deny_globs[i]);
		if (err)
			goto cleanup;
	}

	err = mass_attacher__prepare(att);
	if (err)
		goto cleanup;

	skel = mass_attacher__skeleton(att);
	if (env.verbose)
		skel->rodata->verbose = true;
	
	vmlinux_btf = mass_attacher__btf(att);
	for (i = 0, n = mass_attacher__func_cnt(att); i < n; i++) {
		const struct func_info *finfo;
		const struct btf_type *t;
		const char *glob;
		__u32 flags;

		finfo = mass_attacher__func(att, i);
		t = btf__type_by_id(vmlinux_btf, finfo->btf_id);
		flags = func_flags(finfo->name, vmlinux_btf, t);

		for (j = 0; j < env.entry_glob_cnt; j++) {
			glob = env.entry_globs[j];
			if (!glob_matches(glob, finfo->name))
				continue;

			flags |= FUNC_IS_ENTRY;

			if (env.verbose)
				printf("Function '%s' is marked as an entry point.\n", finfo->name);
			goto done;
		}
		for (j = 0; j < env.preset_cnt; j++) {
			for (k = 0; env.presets[j]->entry_globs[k]; k++) {
				glob = env.presets[j]->entry_globs[k];
				if (!glob_matches(glob, finfo->name))
					continue;

				flags |= FUNC_IS_ENTRY;

				if (env.verbose)
					printf("Function '%s' is marked as an entry point.\n", finfo->name);
				goto done;
			}
		}
done:
		strcpy(skel->bss->func_names[i], finfo->name);
		skel->bss->func_ips[i] = finfo->addr;
		skel->bss->func_flags[i] = flags;
	}

	err = mass_attacher__load(att);
	if (err)
		goto cleanup;

	err = mass_attacher__attach(att);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);

	dwime_ctx.att = att;
	dwime_ctx.skel = mass_attacher__skeleton(att);
	dwime_ctx.ksyms = ksyms__load();
	if (!dwime_ctx.ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms for symbolization.\n");
		goto cleanup;
	}


	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(att->skel->maps.rb), handle_event, &dwime_ctx, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Allow mass tracing */
	mass_attacher__activate(att);

	/* Process events */
	printf("Receiving data...\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			goto cleanup;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	printf("Detaching, be patient...\n");
	mass_attacher__free(att);

	addr2line__free(dwime_ctx.a2l);
	ksyms__free(dwime_ctx.ksyms);

	for (i = 0; i < env.allow_glob_cnt; i++)
		free(env.allow_globs[i]);
	free(env.allow_globs);
	for (i = 0; i < env.deny_glob_cnt; i++)
		free(env.deny_globs[i]);
	free(env.deny_globs);
	for (i = 0; i < env.entry_glob_cnt; i++)
		free(env.entry_globs[i]);
	free(env.entry_globs);
	free(env.presets);

	return -err;
}
