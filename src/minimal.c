// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "minimal.h"
#include "minimal.skel.h"
#include "trace_helpers.h"

struct bpf_program1 {
	char bla[164]; /* XXX: THIS NEEDS TO BE ADJUSTED IF LIBBPF CHANGES SOMETHING */
	__u32 attach_btf_id;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_open_file_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= 200000,
		.rlim_max	= 200000,
	};

	if (setrlimit(RLIMIT_NOFILE, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_NOFILE limit!\n");
		exit(1);
	}
}

/*
static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}
*/

static struct ksyms *ksyms;
static struct btf *vmlinux_btf;
static struct minimal_bpf *skel;

struct func_info {
	long addr;
	const char *name;
	int btf_id;
	int fentry_prog_fd;
	int fexit_prog_fd;
	long last_call_cnt;
	int func_flags;
};

#define MAX_FUNC_ARG_CNT 11

static int func_cnt;
static int func_info_cnts[MAX_FUNC_ARG_CNT + 1];
static struct bpf_program *fentries[MAX_FUNC_ARG_CNT + 1];
static struct bpf_program *fexits[MAX_FUNC_ARG_CNT + 1];
static struct func_info func_infos[50000];
static struct func_info *func_infos_by_arg_cnt[MAX_FUNC_ARG_CNT + 1][30000];

static int kprobe_cnt;
static char *kprobes[50000];
static char buf[512];
static char buf2[512];

static int str_cmp(const void *a, const void *b)
{
	const char * const *s1 = a, * const *s2 = b;

	return strcmp(*s1, *s2);
}

static void load_available_kprobes(void)
{
	const char *fname = "/sys/kernel/tracing/available_filter_functions";
	FILE *f;
	int cnt;

	f = fopen(fname, "r");
	if (!f) {
		fprintf(stderr, "Failed to open %s: %d\n", fname, -errno);
		exit(1);
	}

	while ((cnt = fscanf(f, "%s%[^\n]\n", buf, buf2)) == 1) {
		kprobes[kprobe_cnt++] = strdup(buf);
	}

	qsort(kprobes, kprobe_cnt, sizeof(char *), str_cmp);
	printf("READ %d AVAILABLE KPROBES!\n", kprobe_cnt);
}

static bool is_kprobe_ok(const char *name)
{
	void *r;

	if (strcmp(name, "__x64_sys_getpgid") == 0) 
		r = NULL;
	r = bsearch(&name, kprobes, kprobe_cnt, sizeof(void *), str_cmp);

	return r != NULL;
}

static int func_arg_cnt(const struct btf *btf, int id)
{
	const struct btf_type *t;

	t = btf__type_by_id(btf, id);
	t = btf__type_by_id(btf, t->type);
	return btf_vlen(t);
}

static int prog_arg_cnt(const struct bpf_program *p)
{
	int i;

	for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
		if (fentries[i] == p || fexits[i] == p)
			return i;
	}

	return -1;
}

static int prepped_cnt;

static int prep_prog(struct bpf_program *prog, int n,
		     struct bpf_insn *insns, int insns_cnt,
		     struct bpf_prog_prep_result *res)
{
	struct bpf_program1 *p = (void *)prog;
	struct func_info *finfo;
	int arg_cnt;

	arg_cnt = prog_arg_cnt(prog);
	finfo = func_infos_by_arg_cnt[arg_cnt][n];
	p->attach_btf_id = finfo->btf_id;

	prepped_cnt++;
	if (prepped_cnt % 1000 == 0) {
		printf("prepping prog %s (total %d): func %s, arg cnt %d, instance #%d, btf set to %d\n",
			bpf_program__name(prog), prepped_cnt, finfo->name, arg_cnt, n, finfo->btf_id);
	}

	res->new_insn_ptr = insns;
	res->new_insn_cnt = insns_cnt;
	if (strncmp(bpf_program__name(prog), "fexit", sizeof("fexit") - 1) == 0)
		res->pfd = &finfo->fexit_prog_fd;
	else
		res->pfd = &finfo->fentry_prog_fd;

	return 0;
}

static bool is_ok_type(const struct btf *btf, const struct btf_type *t)
{
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);
	if (!btf_is_int(t) && !btf_is_ptr(t) && !btf_is_enum(t))
		return false;
	return true;
}

static bool is_ok_ret_type(const struct btf *btf, const struct btf_type *t)
{
	const struct btf_type *tt;

	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);
	if (btf_is_int(t) || btf_is_enum(t))
		return true;
	if (!btf_is_ptr(t))
		return false;

	if (t->type == 0) 
		return true;

	tt = btf__type_by_id(btf, t->type);
	if (!btf_is_composite(tt))
		return false;

	return true;
}

static bool is_ok_func(const struct btf *btf, const struct btf_type *t)
{
	const struct btf_param *p;
	int i;

	t = btf__type_by_id(btf, t->type);
	if (btf_vlen(t) > MAX_FUNC_ARG_CNT)
		return false;

	/* IGNORE VOID FUNCTIONS, THIS SHOULDN'T BE DONE IN GENERAL!!! */
	if (!t->type)
		return false;

	if (t->type && !is_ok_ret_type(btf, btf__type_by_id(btf, t->type)))
		return false;

	for (i = 0; i < btf_vlen(t); i++) {
		p = btf_params(t) + i;
		if (!p->type)
			return false;
		if (!is_ok_type(btf, btf__type_by_id(btf, p->type)))
			return false;
	}

	return true;
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

	if (btf_is_int(t) && !(btf_int_encoding(t) & BTF_INT_SIGNED))
		return FUNC_CANT_FAIL;

	if (t->size < 4)
		return FUNC_CANT_FAIL;

	if (t->size == 4)
		return FUNC_NEEDS_SIGN_EXT;

	return 0;
}

/*
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name);
*/

static const char *entry_whitelist[] = {
	"__x64_sys_bpf",
	"__x64_sys_perf_event_open",
	NULL,
};

static const char *whitelist[] = {
	//"__x64_sys_",
	"bpf_",
	"_bpf_",
	"__bpf_",
	"__x64_sys_bpf",
	"do_check",
	"reg_",
	"check_",
	"btf_",
	"_btf_",
	"__btf_",
	"find_",
	"resolve_",
	"convert_",
	"release_",
	"adjust_",
	"verifier_",
	"verbose_",
	"type_",
	"arg_",
	"sanitize_",
	"print_",
	"map_",
	"ringbuf_",
	"array_",
	"__vmalloc_",
	"__alloc",
	"pcpu_",
	"memdup_",

	"copy_",
	"_copy_",
	"raw_copy_",

	"__x64_sys_perf_event_open",
	"perf",

	/*
	"__x64_sys_execve",
	"__x64_sys_fork",
	"__x64_sys_clone",
	*/

	NULL,
};

static const char *blacklist[] = {
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
	"bpf_lsm_",
	"check_cfs_rq_runtime",
	"find_busiest_group",
	"find_vma",

	NULL,
};

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_errno(long err)
{
	switch (err) {
	case 0: printf("NULL"); break;
	case -EPERM: printf("-EPERM"); break;
	case -ENOENT: printf("-ENOENT"); break;
	case -ENOMEM: printf("-ENOMEM"); break;
	case -EACCES: printf("-EACCES"); break;
	case -EFAULT: printf("-EFAULT"); break;
	case -EINVAL: printf("-EINVAL"); break;
	default: printf("%ld", err); break;
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct call_stack *s = data;
	int i;

	if (!s->is_err)
		return 0;

	printf("GOT %s STACK (depth %u):\n", s->is_err ? "ERROR" : "SUCCESS", s->max_depth);
	printf("DEPTH %d MAX DEPTH %d SAVED DEPTH %d MAX SAVED DEPTH %d\n",
			s->depth, s->max_depth, s->saved_depth, s->saved_max_depth);
	for (i = 0; i < s->max_depth; i++) {
		int id = s->func_ids[i];
		const char *fname = func_infos[id].name;

		printf("\t%s", fname);
		if (i + 1 > s->depth) {
			printf(" (returned ");
			print_errno(s->func_res[i]);
			printf(")\n");
		} else {
			printf(" (...)\n");
		}
	}
	if (s->max_depth + 1 == s->saved_depth) {
		for (i = s->saved_depth - 1; i < s->saved_max_depth; i++) {
			int saved_id = s->saved_ids[i];
			const char *fname = func_infos[saved_id].name;

			printf("\t\t*%s [returned %ld]\n", fname, s->saved_res[i]);
		}
	}
	printf("\n");

	return 0;
}

int main(int argc, char **argv)
{
	int err, i, func_skip = 0, j;
	long last_total_call_cnt = 0;
	struct ring_buffer *rb = NULL;

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms\n");
		return 1;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Allow opening lots of BPF programs */
	bump_open_file_rlimit();

	/* Load names of possible kprobes */
	load_available_kprobes();

	/* Open BPF application */
	skel = minimal_bpf__open();
	if (!skel) {
		err = -1;
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto cleanup;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	//skel->bss->my_pid = getpid();

	fentries[0] = skel->progs.fentry0;
	fentries[1] = skel->progs.fentry1;
	fentries[2] = skel->progs.fentry2;
	fentries[3] = skel->progs.fentry3;
	fentries[4] = skel->progs.fentry4;
	fentries[5] = skel->progs.fentry5;
	fentries[6] = skel->progs.fentry6;
	fentries[7] = skel->progs.fentry7;
	fentries[8] = skel->progs.fentry8;
	fentries[9] = skel->progs.fentry9;
	fentries[10] = skel->progs.fentry10;
	fentries[11] = skel->progs.fentry11;
	fexits[0] = skel->progs.fexit0;
	fexits[1] = skel->progs.fexit1;
	fexits[2] = skel->progs.fexit2;
	fexits[3] = skel->progs.fexit3;
	fexits[4] = skel->progs.fexit4;
	fexits[5] = skel->progs.fexit5;
	fexits[6] = skel->progs.fexit6;
	fexits[7] = skel->progs.fexit7;
	fexits[8] = skel->progs.fexit8;
	fexits[9] = skel->progs.fexit9;
	fexits[10] = skel->progs.fexit10;
	fexits[11] = skel->progs.fexit11;

	vmlinux_btf = libbpf_find_kernel_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err) {
		fprintf(stderr, "Failed to load vmlinux BTF: %d\n", err);
		goto cleanup;
	}

	for (i = 1; i <= btf__get_nr_types(vmlinux_btf); i++) {
		const struct btf_type *t = btf__type_by_id(vmlinux_btf, i);
		const char *func_name;
		const struct ksym *ksym;
		struct func_info *finfo;
		int arg_cnt;
		bool skip = false;

		if (!btf_is_func(t))
			continue;

		func_name = btf__str_by_offset(vmlinux_btf, t->name_off);
		ksym = ksyms__get_symbol(ksyms, func_name);
		if (!ksym) {
			printf("FUNC '%s' not found in /proc/kallsyms!\n", func_name);
			func_skip++;
			continue;
		}
		if (whitelist[0]) {
			for (j = 0; whitelist[j]; j++) {
				if (strncmp(func_name, whitelist[j], strlen(whitelist[j])) == 0) {
					//printf("FUNC '%s' is whitelisted!\n", func_name);
					goto proceed;
				}
			}
			func_skip++;
			skip = true;
			continue;
		}
proceed:
		for (j = 0; blacklist[j]; j++) {
			if (strncmp(func_name, blacklist[j], strlen(blacklist[j])) == 0) {
				//printf("FUNC '%s' is skipped due to blacklisting!\n", func_name);
				func_skip++;
				skip = true;
				break;
			}
		}
		if (skip)
			continue;
		if (!is_kprobe_ok(func_name)) {
			//printf("FUNC '%s' is not attachable kprobe, skipping!\n", func_name);
			func_skip++;
			continue;
		}
		if (!is_ok_func(vmlinux_btf, t)) {
			//printf("FUNC '%s' has incompatible prototype, skipping!\n", func_name);
			func_skip++;
			continue;
		}

		/*
		if (func_cnt > 10000)
			break;
		*/

		finfo = &func_infos[func_cnt++];
		finfo->btf_id = i;
		finfo->addr = ksym->addr;
		finfo->name = ksym->name;
		finfo->func_flags = func_flags(finfo->name, vmlinux_btf, t);

		arg_cnt = func_arg_cnt(vmlinux_btf, i);
		func_infos_by_arg_cnt[arg_cnt][func_info_cnts[arg_cnt]++] = finfo;

		//printf("FOUND %s, ADDR 0x%lx\n", func_name, ksym->addr);
	}

	for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
		if (func_info_cnts[i]) {
			bpf_program__set_prep(fentries[i], func_info_cnts[i], prep_prog);
			bpf_program__set_prep(fexits[i], func_info_cnts[i], prep_prog);
			printf("FOUND %d FUNCS WITH ARG CNT %d\n", func_info_cnts[i], i);
		} else {
			bpf_program__set_autoload(fentries[i], false);
			bpf_program__set_autoload(fexits[i], false);
		}
	}
	printf("FOUND %d FUNCS, SKIPPED %d!\n", func_cnt, func_skip);

	bpf_map__set_max_entries(skel->maps.ip_to_idx, func_cnt);

	/* Load & verify BPF programs */
	err = minimal_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	for (i = 0; i < func_cnt; i++) {
		const char *func_name = func_infos[i].name;
		long func_addr = func_infos[i].addr;

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.ip_to_idx), &func_addr, &i, 0);
		if (err) {
			fprintf(stderr, "Failed to add 0x%lx -> '%s' lookup entry!\n", func_addr, buf);
			exit(1);
		}

		strcpy(skel->bss->func_names[i], func_name);
		skel->bss->func_ips[i] = func_addr;

		skel->bss->func_flags[i] = func_infos[i].func_flags;

		for (j = 0; entry_whitelist[j]; j++) {
			const char *name = entry_whitelist[j];

			if (strncmp(func_name, name, strlen(name)) == 0) {
				printf("FUNC '%s' is marked as an entry point!\n", name);
				skel->bss->func_flags[i] |= FUNC_IS_ENTRY;
				break;
			}
		}

	}

	/* Attach tracepoint handler */
	/*
	err = minimal_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	*/
	for (i = 0; i < func_cnt; i++) {
		int prog_fd;

		printf("ATTACHING #%d to '%s' (IP %lx)\n", i, func_infos[i].name, func_infos[i].addr);

		prog_fd = func_infos[i].fentry_prog_fd;
		err = bpf_raw_tracepoint_open(NULL, prog_fd);
		if (err < 0) {
			fprintf(stderr, "Failed to attach FENTRY prog (fd %d) for func #%d (%s), skipping: %d\n",
				prog_fd, i, func_infos[i].name, -errno);
		}
		prog_fd = func_infos[i].fexit_prog_fd;
		err = bpf_raw_tracepoint_open(NULL, prog_fd);
		if (err < 0) {
			fprintf(stderr, "Failed to attach FEXIT prog (fd %d) for func #%d (%s), skipping: %d\n",
				prog_fd, i, func_infos[i].name, -errno);
		}

		/*
		if ((i + 1) % 100 == 0)
			printf("ATTACHED %d FUNCS (%ld calls traced)!\n", i + 1, skel->bss->calls_traced);
		*/
	}

	printf("Total %d funcs attached successfully!\n", func_cnt);

	signal(SIGINT, sig_handler);

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	skel->bss->ready = true;

	/* Process events */
	printf("RECEIVING DATA...\n");
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

	while (!exiting) {
		long total_call_cnt;

		sleep(2);
		for (i = 0; i < func_cnt; i++) {
			struct func_info *info = &func_infos[i];
			long cnt = skel->bss->func_call_cnts[i];
			
			if (cnt != info->last_call_cnt) {
				printf("%s called %ld times.\n", info->name, cnt - info->last_call_cnt);
				info->last_call_cnt = cnt;
			}
		}

		total_call_cnt = skel->bss->calls_traced;
		printf("%ld new calls traced!\n", total_call_cnt - last_total_call_cnt);
		last_total_call_cnt = total_call_cnt;
	}

cleanup:
	skel->bss->ready = false;

	btf__free(vmlinux_btf);
	ksyms__free(ksyms);
	minimal_bpf__destroy(skel);
	return -err;
}
