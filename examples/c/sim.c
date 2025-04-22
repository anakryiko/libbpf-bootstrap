// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

static struct env {
	bool verbose;
	long on_dur_ms;
	long off_dur_ms;
} env;

const char *argp_program_version = "sim 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "On/off CPU workload simulator.\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "on-duration", 'd', "DURATION-MS", 0, "Time spent burning CPU" },
	{ "off-duration", 'D', "DURATION-MS", 0, "Time spent sleeping" },
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
		env.on_dur_ms = strtol(arg, NULL, 10);
		if (errno || env.on_dur_ms < 0) {
			fprintf(stderr, "Invalid --on-duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'D':
		errno = 0;
		env.off_dur_ms = strtol(arg, NULL, 10);
		if (errno || env.off_dur_ms < 0) {
			fprintf(stderr, "Invalid --off-duration: %s\n", arg);
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

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static inline uint64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static uint64_t now_ns()
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}

int main(int argc, char **argv)
{
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		uint64_t start_ts;
		volatile double sink = 1.0;
		const int iter_num = 100000;
		int i;

		if (env.on_dur_ms) {
			start_ts = now_ns();
			do {
				for (i = 0; i < iter_num; i++) {
					sink = sqrt(sink * sink);
					(void)read(-1, NULL, 0);
				}
			} while (now_ns() - start_ts < env.on_dur_ms * 1000000ULL);
		}
		if (env.off_dur_ms) {
			start_ts = now_ns();
			do {
				usleep(1000);
			} while (now_ns() - start_ts < env.off_dur_ms * 1000000ULL);
		}
	}

	return err < 0 ? -err : 0;
}
