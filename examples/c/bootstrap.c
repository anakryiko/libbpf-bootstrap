// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#define __unused __attribute__((unused))

static struct bootstrap_bpf *skel;

static struct env {
	bool verbose;
	int port;
	bool transparent;
	int conn_cnt;
} env = {
	.conn_cnt = 4096,
};

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF bootstrap demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{ "port", 'p', "port", 0, "Server port filter" },
	{ "coalesce", 'c', "BYTES", 0, "Coalesce len in bytes" },
	{ "transparent", 't', NULL, 0, "Verbose debug output" },
	{ "conn-cnt", 'n', "CNT", 0, "Number of connection" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.transparent = true;
		break;
	case 'p':
		errno = 0;
		env.port = strtol(arg, NULL, 10);
		if (errno || env.port <= 0) {
			fprintf(stderr, "Invalid port: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'n':
		errno = 0;
		env.conn_cnt = strtol(arg, NULL, 10);
		if (errno || env.conn_cnt <= 0) {
			fprintf(stderr, "Invalid conn_cnt: %s\n", arg);
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG /*&& !env.verbose*/)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exit(1);
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->exit_event) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid, e->ppid,
		       e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, e->ppid,
		       e->filename);
	}

	return 0;
}

static void setup(struct bootstrap_bpf *skel)
{
	int cg_fd;
	int err;

	cg_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "Failed to get root CG FD: %d\n", -errno);
		exit(1);
	}

	err = bpf_prog_attach(bpf_program__fd(skel->progs.skb_parser),
			      bpf_map__fd(skel->maps.sockhash), 
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		fprintf(stderr, "Failed to attach STREAM_PARSER program: %d\n", err);
		exit(1);
	}

	err = bpf_prog_attach(bpf_program__fd(skel->progs.skb_verdict),
			      bpf_map__fd(skel->maps.sockhash), 
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		fprintf(stderr, "Failed to attach STREAM_VERDICT program: %d\n", err);
		exit(1);
	}

	skel->links.sock_ops = bpf_program__attach_cgroup(
			skel->progs.sock_ops, cg_fd);
	if (!skel->links.sock_ops) {
		fprintf(stderr, "Failed to attach sockops: %d\n", -errno);
		exit(1);
	}
	scanf("%d", &err);
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("TRACING PORT %d\n", env.port);
	printf("MAX CONN CNT %d\n", env.conn_cnt);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->bss->port = env.port;
	skel->bss->verbose = env.verbose;
	skel->bss->transparent = env.transparent;

	bpf_map__set_max_entries(skel->maps.sockhash, env.conn_cnt);
	bpf_map__set_max_entries(skel->maps.posmap, env.conn_cnt);

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	setup(skel);

	return 0;

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID",
	       "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
