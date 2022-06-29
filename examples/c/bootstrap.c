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

static struct bootstrap_bpf *skel;

struct msg {
	int total_len;
	int payload_len;
	int offload_len;
	int offload_id;
	int offload_start_off;
	int offload_end_off;
	char payload[];
};

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
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
	if (level == LIBBPF_DEBUG && !env.verbose)
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
		printf("%-8s %-5s %-16s %-7d %-7d [%u]",
		       ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n",
		       ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
	}

	return 0;
}

static bool server_started = false;

static void offload_fetch(int offload_id, int start_off, int end_off, char *buf)
{
	int err;

	skel->bss->off_req_id = offload_id;
	skel->bss->off_req_start_off = start_off;
	skel->bss->off_req_end_off = end_off;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.skb_get_offload), NULL);
	if (err) {
		fprintf(stderr, "Failed to fetch offload: %d\n", err);
		exit(1);
	}

	memcpy(buf, skel->bss->off_res_data, skel->bss->off_res_len);
	buf[skel->bss->off_res_len] = '\0';
}

static void *handle_server(void *arg)
{
	int port = *(int *)arg;
	socklen_t client_addr_len;
	struct sockaddr_in server_addr, client_addr;
	int server_fd, client_fd, err, zero = 0;
	char buf[512];
	int buf_off = 0;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		fprintf(stderr, "Failed to create server socket: %d\n", -errno);
		exit(1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);

	err = bind(server_fd, (void *)&server_addr, sizeof(server_addr));
	if (err) {
		fprintf(stderr, "Failed to bind server socket fd %d: %d\n", server_fd, -errno);
		exit(1);
	}

	err = listen(server_fd, 1);
	if (err) {
		fprintf(stderr, "Failed to listen socket fd %d: %d\n", server_fd, -errno);
		exit(1);
	}

	printf("SERVER started at port %d\n", port);
	server_started = true;

	client_fd = accept(server_fd, (void *)&client_addr, &client_addr_len);
	if (client_fd < 0) {
		fprintf(stderr, "Failed to accept client socket on server fd %d: %d\n", server_fd, -errno);
		exit(1);
	}

	err = bpf_prog_attach(bpf_program__fd(skel->progs.skb_parser),
			      bpf_map__fd(skel->maps.sockmap), 
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		fprintf(stderr, "Failed to attach STREAM_PARSER program: %d\n", err);
		exit(1);
	}

	err = bpf_prog_attach(bpf_program__fd(skel->progs.skb_verdict),
			      bpf_map__fd(skel->maps.sockmap), 
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		fprintf(stderr, "Failed to attach STREAM_VERDICT program: %d\n", err);
		exit(1);
	}

	err = bpf_map__update_elem(skel->maps.sockmap, &zero, sizeof(zero),
				   &client_fd, sizeof(client_fd), BPF_NOEXIST);
	if (err) {
		fprintf(stderr, "Failed to add client socket fd %d to sockmap: %d\n", client_fd, err);
		exit(1);
	}

	while ((err = read(client_fd, buf + buf_off, sizeof(buf) - buf_off)) >= 0 || errno == EAGAIN) {
		const struct msg *msg = (void *)buf;
		int buf_len, msg_len, need_len;

		buf_len = buf_off + err;

		while (buf_len > 0) {
			char tmp[512], tmp_payload[256];

			need_len = buf_len < sizeof(*msg)
				   ? sizeof(*msg)
				   : msg->total_len - (msg->offload_id ? msg->offload_len : 0);

			if (buf_len < need_len) {
				fprintf(stdout, "Got %d bytes in buffer (%d + %d), need at least %d, waiting for more data...\n",
					buf_len, buf_off, err, need_len);
				break;
			}

			if (msg->offload_id) {
				usleep(200);
				offload_fetch(msg->offload_id, msg->offload_start_off, msg->offload_end_off, tmp_payload);

				snprintf(tmp, sizeof(tmp), "<OFFLOADED id %d [%d, %d) '%s'>",
					 msg->offload_id, msg->offload_start_off, msg->offload_end_off,
					 tmp_payload);
			}

			fprintf(stdout, "RECV MSG total %d actual %d pay_len %d off_len %d payload %s off_payload %s\n",
				msg->total_len,
				need_len,
				msg->payload_len - 1,
				msg->offload_len - 1,
				msg->payload,
				msg->offload_id ? tmp : msg->payload + msg->payload_len);

			/* shift the remainder so it's always at the beginning of the buf */
			msg_len = need_len;
			memmove(buf, buf + msg_len, buf_len - msg_len);

			buf_len -= msg_len;
			buf_off = buf_len;
			err = 0;
		}

		buf_off = buf_len;
	}

	printf("SERVER shutting down, last read got error %d %d...\n", err, -errno);

	return NULL;
}

static void *handle_client(void *arg)
{
	int port = *(int *)arg;
	int sock_fd, err;
	struct sockaddr_in server_addr;
	int msg_len = 0;
	char buf[512];
	struct msg *msg = (void *)&buf;

	fprintf(stdout, "CLIENT starting...\n");

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		fprintf(stderr, "Failed to create client socket: %d\n", -errno);
		exit(1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(port);

	err = connect(sock_fd, (void *)&server_addr, sizeof(server_addr));
	if (err) {
		fprintf(stderr, "Failed to connect client socket fd %d: %d\n", sock_fd, -errno);
		exit(1);
	}

	fprintf(stdout, "CLIENT started for port %d\n", port);

	while (true) {
		char msg_char, off_char;
		int off_len;

		msg_char = getchar();
		if (!isalpha(msg_char))
			continue;

		off_char = msg_char - 'a' + 'A';

		msg_len++;
		off_len = msg_len * 2;

		msg->total_len = sizeof(struct msg) + msg_len + 1 + off_len + 1;
		msg->payload_len = msg_len + 1;
		msg->offload_len = off_len + 1;
		msg->offload_id = 0;
		msg->offload_start_off = 0;
		msg->offload_end_off = 0;

		memset(msg->payload, msg_char, msg_len);
		msg->payload[msg_len] = '\0';
		memset(msg->payload + msg_len + 1, off_char, off_len);
		msg->payload[msg_len + 1 + off_len] = '\0';

		fprintf(stdout, "SEND MSG total %d bytes (%d * '%c' + %d * '%c')...\n",
			msg->total_len, msg_len, msg_char, off_len, off_char);

		err = write(sock_fd, buf, msg->total_len);
		if (err < 0 || err != msg->total_len) {
			fprintf(stderr, "Failed to send message (len %d, sent %d %d)\n",
				msg->total_len, err, -errno);
			exit(1);
		}

		if (msg_len >= 10)
			msg_len = 0;
	}

	return NULL;
}

static void setup_client_server(void)
{
	pthread_t client_thread, server_thread;
	int port = 7777;
	int err;

	err = pthread_create(&server_thread, NULL, handle_server, &port);
	if (err) {
		fprintf(stderr, "Failed to create server thread: %d\n", err);
		exit(1);
	}

	fprintf(stdout, "Waiting for server to start up...\n");
	while (!server_started) {
		usleep(100);
	}

	err = pthread_create(&client_thread, NULL, handle_client, &port);
	if (err) {
		fprintf(stderr, "Failed to create client thread: %d\n", err);
		exit(1);
	}

	fprintf(stdout, "Joining client and server threads...\n");
	pthread_join(client_thread, NULL);
	fprintf(stdout, "Client thread finished!\n");
	pthread_join(server_thread, NULL);
	fprintf(stdout, "Server thread finished!\n");

	fprintf(stdout, "Exiting...\n");
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	setup_client_server();
	return 0;

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
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
