// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int cnt = 0;

	for (;;) {
		int min_pages = 4096 / 8;
		int key_sz = 8;
		int val_sz = 1024 - 8;
		int min_elems = min_pages * 4096 / (key_sz + val_sz);

		int num_elems = min_elems + 100 * min_elems * ((rand() + 0.0) / RAND_MAX);
		int fd = bpf_map_create(BPF_MAP_TYPE_HASH, "boom_map", key_sz, val_sz, num_elems, NULL);
		if (fd >= 0)
			close(fd);
		printf("MIN_ELEMS %d NUM_ELEMS %d APPROX_SZ %d FD %d\n",
		       min_elems, num_elems, num_elems * (key_sz + val_sz), fd);

		if (cnt++ % 100 == 0)
			fprintf(stderr, ".");
		usleep(1);
	}

	return 0;
}
