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
#include <sys/epoll.h>

#define __unused __attribute__((unused))

static struct bootstrap_bpf *skel;

static struct env {
	bool verbose;
	int pid;
	int port;
	bool transparent;
	bool lowat_mode;
	int conn_cnt;
	bool manual;
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
	{ "manual", 'm', NULL, 0, "Manual client/server mode" },
	{ "lowat", 'l', NULL, 0, "RCVLOWAT mode" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{ "port", 'p', "PORT", 0, "Server port filter" },
	{ "pid", 'P', "PID", 0, "Server PID filter" },
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
	case 'm':
		env.manual = true;
		break;
	case 't':
		env.transparent = true;
		break;
	case 'l':
		env.lowat_mode = true;
		break;
	case 'P':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
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

struct msg {
	unsigned char len1, len2, len3;
	char payload[];
};

static volatile bool server_started = false;

static void *handle_server(void *arg)
{
	int port = env.port;
	socklen_t client_addr_len;
	struct sockaddr_in server_addr, client_addr;
	int server_fd, client_fd, err;
	char buf[512 * 1024];
	struct epoll_event ev;
	int epoll_fd;

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

	/*
	if (fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "Failed to make server socket non-blocking: %d\n", -errno);
		exit(1);
	}
	*/

	err = listen(server_fd, 1);
	if (err) {
		fprintf(stderr, "Failed to listen socket fd %d: %d\n", server_fd, -errno);
		exit(1);
	}

	printf("SERVER started at port %d\n", port);
	server_started = true;

again:
	client_fd = accept(server_fd, (void *)&client_addr, &client_addr_len);
	if (client_fd < 0 && errno == EAGAIN)
		goto again;
	if (client_fd < 0) {
		fprintf(stderr, "Failed to accept client socket on server fd %d: %d\n", server_fd, -errno);
		exit(1);
	} 
	if (fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "Failed to make client socket non-blocking: %d\n", -errno);
		exit(1);
	}

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		fprintf(stderr, "Failed to create epoll_fd: %d\n", -errno);
		exit(1);
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = 0;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
		fprintf(stderr, "Failed to EPOLL_CTL_ADD client_fd: %d\n", -errno);
		exit(1);
	}

	int buf_len = 0;
	while (true) {
		const struct msg *msg = (void *)buf;
		int msg_len, need_len;

		err = epoll_wait(epoll_fd, &ev, 1, 100000);
		if (err < 0 && errno == EAGAIN) {
			fprintf(stdout, "EPOLL EAGAIN!\n");
			continue;
		}
		if (err < 0) {
			fprintf(stderr, "EPOLL ERROR: %d\n", -errno);
			exit(1);
		}
		fprintf(stdout, "EPOLL RETURNED %d\n", err);

		err = recvfrom(client_fd, buf + buf_len, sizeof(buf) - buf_len, MSG_DONTWAIT, NULL, NULL);
		if (err < 0 && errno == EAGAIN) {
			fprintf(stdout, "READ EAGAIN!\n");
			continue;
		}
		if (err < 0) {
			fprintf(stderr, "READ ERROR: %d, %d\n", err, -errno);
			exit(1);
		}
		if (err == 0) {
			fprintf(stdout, "READ ZERO!!!\n");
			continue;
		}
		fprintf(stdout, "READ GOT %d\n", err);

		buf_len += err;
		while (buf_len > 0) {
			if (buf_len < sizeof(*msg))
				need_len = sizeof(*msg);
			else
				need_len = ((unsigned)msg->len1 << 16) +
					((unsigned)msg->len2 << 8) +
					(unsigned)msg->len3 +
					sizeof(*msg);

			if (buf_len < need_len) {
				fprintf(stdout, "Got new %d bytes in buffer, need at least %d, waiting for more data...\n",
					buf_len, need_len);
				break;
			}
			msg_len = need_len;

			fprintf(stdout, "RECV MSG len %d payload %s\n", need_len - 3, msg->payload);

			/* shift the remainder so it's always at the beginning of the buf */
			memmove(buf, buf + msg_len, buf_len - msg_len);
			msg = (void *)&buf;
			buf_len -= msg_len;
		}
	}

	printf("SERVER shutting down, last read got error %d %d...\n", err, -errno);

	return NULL;
}

static void *handle_client(void *arg)
{
	int port = env.port;
	int sock_fd, err;
	struct sockaddr_in server_addr;
	char buf[512 * 1024];
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
		int msg_lens[16];
		char msg_chars[16];
		char msg_char;
		int msg_len, rem, sent, chunk;
		int msg_cnt = 0, i, buf_len;

		fprintf(stdout, "MSGs (len1 len2 ... char1 char2 ...): \n");
		while (scanf("%d", &msg_lens[msg_cnt]) == 1) {
			msg_cnt++;
			if (msg_cnt > 16) {
				fprintf(stderr, "TOO MANY SIMULTANEOUS MSGS...\n");
				exit(1);
			}
		}
		for (i = 0; i < msg_cnt; i++) {
			scanf(" %c", &msg_chars[i]);
		}
		
		buf_len = 0;
		for (i = 0; i < msg_cnt; i++) {
			msg_len = msg_lens[i];
			msg_char = msg_chars[i];

			fprintf(stdout, "BUF_LEN %d MSG_LEN %d\n", buf_len, msg_len);
			msg = (void *)&buf[buf_len];

			msg->len1 = (msg_len >> 16) & 0xFF;
			msg->len2 = (msg_len >> 8) & 0xFF;
			msg->len3 = msg_len & 0xFF;

			fprintf(stdout, "L1 %u L2 %u L3 %u\n",
				(unsigned)msg->len1,
				(unsigned)msg->len2,
				(unsigned)msg->len3);

			memset(msg->payload, msg_char, msg_len);
			msg->payload[msg_len - 1] = '\0';

			fprintf(stdout, "PREPARING MSG total %d+3(=%d) bytes (%d * '%c')...\n",
				msg_len, msg_len + 3, msg_len, msg_char);

			msg_len += 3;
			buf_len += msg_len;
		}

		fprintf(stdout, "SENDING PAYLOAD total %d bytes...\n", buf_len);

		rem = buf_len;
		sent = 0;
		while (rem && scanf("%d", &chunk) == 1) {
			if (chunk > rem)
				chunk = rem;
			err = write(sock_fd, buf + sent, chunk);
			if (err < 0 || err != chunk) {
				fprintf(stderr, "Failed to send message (msg_len %d, sent %d, rem %d, chunk %d, ret %d): %d\n",
					msg_len, sent, rem, chunk, err, -errno);
				exit(1);
			}
			rem -= chunk;
			sent += chunk;
		}

		fprintf(stdout, "DONE SENDING.\n");
	}

	return NULL;
}

static void setup_client_server(void)
{
	pthread_t client_thread, server_thread;
	int err;

	err = pthread_create(&server_thread, NULL, handle_server, NULL);
	if (err) {
		fprintf(stderr, "Failed to create server thread: %d\n", err);
		exit(1);
	}

	fprintf(stdout, "Waiting for server to start up...\n");
	while (!server_started) {
		usleep(100);
	}

	err = pthread_create(&client_thread, NULL, handle_client, NULL);
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

static void setup(struct bootstrap_bpf *skel)
{
	int cg_fd;
	int err;

	cg_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "Failed to get root CG FD: %d\n", -errno);
		exit(1);
	}

	/*
	if (env.lowat_mode) {
		skel->links.handle_skb = bpf_program__attach_cgroup(skel->progs.handle_skb, cg_fd);
		if (!skel->links.handle_skb) {
			fprintf(stderr, "Failed to attach handle_skb: %d\n", -errno);
			exit(1);
		}
		return;
	}
	*/

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
	printf("TRACING PID %d\n", env.pid);
	printf("MAX CONN CNT %d\n", env.conn_cnt);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->bss->port = env.port;
	skel->bss->pid = env.pid;
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

	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	setup(skel);
	if (env.manual)
		setup_client_server();

	scanf("%d", &err);
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
