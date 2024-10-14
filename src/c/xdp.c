// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
/* XDP_FLAGS_SKB_MODE */

#include "xdp.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <iface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("failed to resolve iface to ifindex");
        return EXIT_FAILURE;
    }

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("failed to increase RLIMIT_MEMLOCK");
        return EXIT_FAILURE;
    }

    libbpf_set_print(libbpf_print);

    int err;
    struct xdp_bpf *obj;

    obj = xdp_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return EXIT_FAILURE;
    }
    err = xdp_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /*
     * Use "xdpgeneric" mode; less performance but supported by all drivers
     */
    int flags = XDP_FLAGS_SKB_MODE;
    int fd = bpf_program__fd(obj->progs.xdp_pass);

    /* Attach BPF to network interface */

    err = bpf_xdp_attach(ifindex, fd, flags, NULL);
    if (err) {
        fprintf(stderr, "failed to attach BPF to iface %s (%d): %d\n",
            iface, ifindex, err);
        goto cleanup;
    }

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

    // XXX: replace with actual code, e.g. loop to get data from BPF
    while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

    /* Remove BPF from network interface */

    err = bpf_xdp_detach(ifindex, flags, NULL);
    if (err) {
        fprintf(stderr, "failed to detach BPF from iface %s (%d): %d\n",
            iface, ifindex, err);
        goto cleanup;
    }

cleanup:
    xdp_bpf__destroy(obj);

    if (err) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
