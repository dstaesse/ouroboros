/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Ouroboros VPN
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _POSIX_C_SOURCE 200109L

#include <ouroboros/dev.h>

#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>

#define BUF_SIZE 65536

int t_fd;
int o_fd;

static void usage(void)
{
        printf("Usage: ovpn [OPTION]...\n"
               "Sends TCP/IP traffic over Ouroboros\n\n"
               "  -n, --name                Run as client, name of ovpn "
               "server to connect to\n"
               "  -i, --ip                  IP address to give to TUN device\n"
               "  -m, --mask                Subnet mask to give to TUN device\n"
               "  -C, --crypt               AES encryption (default: off)\n"
               "\n"
               "      --help                Display this help text and exit\n");
}

static int tun_open(char *   dev,
                    uint32_t ip,
                    uint32_t mask)
{
        struct ifreq         ifr;
        int                  fd;
        int                  s;
        int                  ret;
        char *               clonedev = "/dev/net/tun";
        struct sockaddr_in * addr;

        fd = open(clonedev, O_RDWR);
        if (fd < 0)
                return -1;

        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
        if (ret < 0)
                goto fail;

        strcpy(dev, ifr.ifr_name);

        /* Now get the i/f up and running. */
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0)
                goto fail;

        /* Set IP address. */
        ifr.ifr_addr.sa_family = AF_INET;
        addr = (struct sockaddr_in *) &ifr.ifr_addr;
        addr->sin_addr.s_addr = ip;

        if (ioctl(s, SIOCSIFADDR, &ifr))
                goto fail_ioctl;

        /* Set subnet mask. */
        addr->sin_addr.s_addr = mask;
        if (ioctl(s, SIOCSIFNETMASK, &ifr))
                goto fail_ioctl;

        /* Bring interface up. */
        if (ioctl(s, SIOCGIFFLAGS, &ifr))
                goto fail_ioctl;
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
        if (ioctl(s, SIOCSIFFLAGS, &ifr))
                goto fail_ioctl;

        close(s);

        return fd;

 fail_ioctl:
        close(s);
 fail:
        close(fd);
        return -1;
}

void * o_reader(void * o)
{
        char buf[BUF_SIZE];
        int  len = 0;

        (void) o;

        while (true) {
                len = flow_read(o_fd, buf, BUF_SIZE);
                if (len <= 0)
                        continue;

                if (write(t_fd, buf, len))
                        continue;
        }
}

void * t_reader(void * o)
{
        char buf[BUF_SIZE];
        int  len = 0;

        (void) o;

        while (true) {
                len = read(t_fd, buf, BUF_SIZE);
                if (len <= 0)
                        continue;

                if (flow_write(o_fd, buf, len) < 0)
                        continue;
        }
}

static int check_mask(uint32_t mask)
{
        if (mask == 0)
                return 0;

        return ((~mask & (~mask + 1)) != 0);
}

int main(int     argc,
         char ** argv)
{
        char *    name = NULL;
        uint32_t  ip   = 0;
        int32_t   mask = -1;
        char      dev[IFNAMSIZ];
        pthread_t t_thr;
        pthread_t o_thr;
        sigset_t  sigset;
        int       sig;
        int       c;
        qosspec_t qs;

        static struct option long_options[] =
                {{"ip",    required_argument, NULL, 'i'},
                 {"mask",  required_argument, NULL, 'm'},
                 {"name",  required_argument, NULL, 'n'},
                 {"crypt", no_argument,       NULL, 'C'},
                 {"help",  no_argument,       NULL, 'h'},
                 {NULL,    0,                 NULL, 0}
                };

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGTERM);

        if (geteuid() != 0) {
                printf("ovpn must be run as root.\n");
                exit(EXIT_FAILURE);
        }

        qs = qos_raw;

        while ((c = getopt_long(argc, argv, "i:m:n:Ch",
                                long_options, NULL)) != -1) {
                switch (c) {
                case 'i':
                        if (inet_pton(AF_INET, optarg, &ip) != 1) {
                                printf("Invalid IP address: %s.\n\n", optarg);
                                goto fail_usage;
                        }
                        break;
                case 'm':
                        if (inet_pton(AF_INET, optarg, &mask) != 1 ||
                            check_mask(htonl(mask))) {
                                printf("Invalid subnet mask: %s.\n\n", optarg);
                                goto fail_usage;
                        }
                        break;
                case 'n':
                        name = optarg;
                        break;
                case 'C':
                        qs = qos_raw_crypt;
                        break;
                case 'h':
                        usage();
                        exit(EXIT_SUCCESS);
                default:
                        exit(EXIT_FAILURE);
                }
        }

        if (optind < argc) {
                printf("Unknown arguments specified: ");
                while (optind < argc)
                        printf("%s ", argv[optind++]);
                printf("\n\n");
                goto fail_usage;
        }

        if (ip == 0) {
                printf("Please specify an IP address.\n\n");
                goto fail_usage;
        }

        if (mask == -1) {
                printf("Please specify a subnetmask.\n\n");
                goto fail_usage;
        }

        if (name != NULL) {
                printf("Allocating a flow to %s.\n", name);

                o_fd = flow_alloc(name, &qs, NULL);
                if (o_fd < 0) {
                        printf("Failed to allocate flow.\n");
                        goto fail_alloc;
                }
        } else {
                printf("Waiting for a new flow...\n");

                o_fd = flow_accept(NULL, NULL);
                if (o_fd < 0) {
                        printf("Failed to accept flow.\n");
                        goto fail_alloc;
                }
        }

        printf("Flow allocated.\n");

        t_fd = tun_open(dev, ip, mask);
        if (t_fd < 0) {
                printf("Failed to open tunnel device.\n");
                goto fail_tun;
        }

        printf("Tunnel device name is %s.\n", dev);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        printf("Starting read/write threads.\n");

        if (pthread_create(&o_thr, NULL, o_reader, NULL))
                goto fail_thread;

        if (pthread_create(&t_thr, NULL, t_reader, NULL))
                goto fail_thread2;

        while (true) {
                if (sigwait(&sigset, &sig) != 0) {
                        printf("Bad signal.\n");
                        continue;
                }

                printf("Shutting down...\n");
                break;
        }

        pthread_cancel(o_thr);
        pthread_cancel(t_thr);

        pthread_join(o_thr, NULL);
        pthread_join(t_thr, NULL);

        close(t_fd);
        flow_dealloc(o_fd);

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        exit(EXIT_SUCCESS);
 fail_usage:
        usage();
        exit(EXIT_FAILURE);
 fail_thread2:
        pthread_cancel(o_thr);
        pthread_join(o_thr, NULL);
 fail_thread:
        close(t_fd);
 fail_tun:
        flow_dealloc(o_fd);
 fail_alloc:
        exit(EXIT_FAILURE);
}
