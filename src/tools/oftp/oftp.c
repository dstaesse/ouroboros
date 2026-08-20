/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * A minimal file-transfer tool over an FRCT stream flow
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
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

#if defined(__APPLE__)
/* macOS hides O_NOFOLLOW behind the BSD feature set. */
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <ouroboros/crc64.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/qos.h>

#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BUF_SIZE 16384

static volatile sig_atomic_t stop = 0;

static void apply_rto_min_env(int fd)
{
        const char * env;
        long         v;

        env = getenv("OFTP_FRCT_RTO_MIN");
        if (env == NULL)
                return;

        v = strtol(env, NULL, 10);
        if (v <= 0)
                return;

        if (fccntl(fd, FRCTSRTOMIN, (time_t) v) < 0)
                fprintf(stderr,
                        "oftp: failed to set RTO_MIN=%ld ns\n", v);
}

static void apply_stream_ring_sz_env(int fd)
{
        const char * env;
        long         v;

        env = getenv("OFTP_FRCT_STREAM_RING_SZ");
        if (env == NULL)
                return;

        v = strtol(env, NULL, 10);
        if (v <= 0)
                return;

        if (fccntl(fd, FRCTSRRINGSZ, (size_t) v) < 0)
                fprintf(stderr,
                        "oftp: failed to set STREAM_RING_SZ=%ld\n", v);
}

static void on_signal(int signo)
{
        (void) signo;
        stop = 1;
}

static void usage(void)
{
        printf("Usage: oftp [OPTION]...\n"
               "Stream-mode file transfer over an Ouroboros flow.\n\n"
               "  -l, --listen        Run as the receiver (server)\n"
               "  -n, --name NAME     Destination service name (client)\n"
               "  -i, --in   FILE     Read input from FILE (default stdin)\n"
               "  -o, --out  FILE     Write output to FILE (default stdout)\n"
               "  -N, --bytes SIZE    Stop after SIZE bytes "
                                     "(K/M/G suffix; client only)\n"
               "      --help          Display this help text and exit\n");
}

static int parse_size(const char * s, size_t * out)
{
        char *        end;
        unsigned long v;
        size_t        mul;

        v = strtoul(s, &end, 0);
        if (end == s)
                return -1;

        mul = 1;
        if (*end == 'k' || *end == 'K')
                mul = 1024UL;
        else if (*end == 'm' || *end == 'M')
                mul = 1024UL * 1024UL;
        else if (*end == 'g' || *end == 'G')
                mul = 1024UL * 1024UL * 1024UL;
        else if (*end != '\0')
                return -1;

        *out = (size_t) v * mul;
        return 0;
}

static void report_xfer(const char *            tag,
                        size_t                  total,
                        uint64_t                crc,
                        const struct timespec * t0,
                        const struct timespec * t1)
{
        double elapsed_s;
        double mib_per_s;

        elapsed_s = (t1->tv_sec  - t0->tv_sec)
                  + (t1->tv_nsec - t0->tv_nsec) / 1e9;
        if (elapsed_s <= 0.0)
                elapsed_s = 1e-9;

        mib_per_s = ((double) total / (1024.0 * 1024.0)) / elapsed_s;

        fprintf(stderr,
                "oftp: %s %zu bytes in %.3f s (%.2f MiB/s) "
                "crc64=%016" PRIx64 "\n",
                tag, total, elapsed_s, mib_per_s, crc);
}

static int xfer_to_flow(int fd, FILE * in, size_t max_bytes)
{
        char            buf[BUF_SIZE];
        size_t          n;
        size_t          total;
        size_t          want;
        size_t          off;
        ssize_t         w;
        uint64_t        crc;
        struct timespec t0;
        struct timespec t1;

        total = 0;
        crc   = 0;

        clock_gettime(CLOCK_MONOTONIC, &t0);

        while (!stop) {
                want = sizeof(buf);
                if (max_bytes > 0 && max_bytes - total < want)
                        want = max_bytes - total;
                if (want == 0)
                        break;

                n = fread(buf, 1, want, in);
                if (n == 0)
                        break;

                crc64_nvme(&crc, buf, n);

                off = 0;
                while (off < n) {
                        w = flow_write(fd, buf + off, n - off);
                        if (w < 0) {
                                fprintf(stderr,
                                        "flow_write failed: %zd\n", w);
                                return 1;
                        }
                        off   += (size_t) w;
                        total += (size_t) w;
                }
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (ferror(in)) {
                fprintf(stderr, "Input read error.\n");
                return 1;
        }

        report_xfer("sent", total, crc, &t0, &t1);
        return 0;
}

static int xfer_from_flow(int fd, FILE * out)
{
        char            buf[BUF_SIZE];
        size_t          total;
        ssize_t         n;
        uint64_t        crc;
        struct timespec timeout;
        struct timespec t0;
        struct timespec t1;
        bool            started;

        total           = 0;
        crc             = 0;
        started         = false;
        timeout.tv_sec  = 1;
        timeout.tv_nsec = 0;

        /* Short timeout so SIGTERM/SIGINT 'stop' is observed promptly. */
        fccntl(fd, FLOWSRCVTIMEO, &timeout);

        while (!stop) {
                n = flow_read(fd, buf, sizeof(buf));
                if (n == 0) {
                        /* Clean EOF: peer sent EOS and we drained it. */
                        clock_gettime(CLOCK_MONOTONIC, &t1);
                        fflush(out);
                        if (!started)
                                t0 = t1;
                        report_xfer("received", total, crc, &t0, &t1);
                        return 0;
                }
                if (n == -ETIMEDOUT)
                        continue;
                if (n < 0) {
                        /* Peer aborted before EOS: partial transfer. */
                        if (n == -EFLOWDOWN || n == -EFLOWPEER) {
                                fprintf(stderr,
                                        "oftp: peer aborted at %zu B\n",
                                        total);
                                return 2;
                        }
                        fprintf(stderr,
                                "flow_read failed: %zd\n", n);
                        return 1;
                }
                if (!started) {
                        clock_gettime(CLOCK_MONOTONIC, &t0);
                        started = true;
                }
                crc64_nvme(&crc, buf, (size_t) n);
                if (fwrite(buf, 1, (size_t) n, out) != (size_t) n) {
                        fprintf(stderr, "Output write error.\n");
                        return 1;
                }
                total += (size_t) n;
        }

        /* Receiver was signalled (SIGINT/SIGTERM) before EOF. */
        fflush(out);
        fprintf(stderr, "oftp: interrupted at %zu B\n", total);
        return 2;
}

static int server_main(const char * outpath)
{
        FILE *     out = stdout;
        int        fd;
        int        ofd;
        int        rc;
        qosspec_t  qs;

        if (outpath != NULL) {
                ofd = open(outpath,
                           O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                           0600);
                if (ofd < 0) {
                        perror("open");
                        return 1;
                }
                out = fdopen(ofd, "wb");
                if (out == NULL) {
                        perror("fdopen");
                        close(ofd);
                        unlink(outpath);
                        return 1;
                }
        }

        fprintf(stderr, "oftp: listening...\n");

        fd = flow_accept(&qs, NULL);
        if (fd < 0) {
                fprintf(stderr, "flow_accept failed: %d\n", fd);
                if (outpath != NULL)
                        fclose(out);
                return 1;
        }

        if (qs.service != SVC_STREAM) {
                fprintf(stderr,
                        "oftp: rejecting non-stream flow (service=%u)\n",
                        qs.service);
                flow_dealloc(fd);
                if (outpath != NULL) {
                        fclose(out);
                        unlink(outpath);
                }
                return 1;
        }

        apply_rto_min_env(fd);
        apply_stream_ring_sz_env(fd);

        rc = xfer_from_flow(fd, out);

        flow_dealloc(fd);

        if (outpath != NULL) {
                fclose(out);
                /* Drop the half-written file on abort/interrupt. */
                if (rc != 0)
                        unlink(outpath);
        }

        return rc;
}

static int client_main(const char * name,
                       const char * inpath,
                       size_t       max_bytes)
{
        FILE *    in;
        int       fd;
        int       rc;
        qosspec_t qs;

        in = stdin;
        qs = qos_stream;

        if (inpath != NULL) {
                in = fopen(inpath, "rb");
                if (in == NULL) {
                        perror("fopen");
                        return 1;
                }
        }

        fd = flow_alloc(name, &qs, NULL);
        if (fd < 0) {
                fprintf(stderr, "flow_alloc failed: %d\n", fd);
                if (inpath != NULL)
                        fclose(in);
                return 2;
        }

        apply_rto_min_env(fd);
        apply_stream_ring_sz_env(fd);

        rc = xfer_to_flow(fd, in, max_bytes);

        flow_dealloc(fd);

        if (inpath != NULL)
                fclose(in);

        return rc;
}

int main(int argc, char ** argv)
{
        bool             server;
        const char *     name;
        const char *     inpath;
        const char *     outpath;
        size_t           max_bytes;
        struct sigaction sa;

        server    = false;
        name      = NULL;
        inpath    = NULL;
        outpath   = NULL;
        max_bytes = 0;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        signal(SIGPIPE, SIG_IGN);

        argc--; argv++;
        while (argc > 0) {
                if (strcmp(*argv, "-l") == 0 ||
                    strcmp(*argv, "--listen") == 0) {
                        server = true;
                } else if ((strcmp(*argv, "-n") == 0 ||
                            strcmp(*argv, "--name") == 0) && argc > 1) {
                        name = *(++argv); argc--;
                } else if ((strcmp(*argv, "-i") == 0 ||
                            strcmp(*argv, "--in") == 0) && argc > 1) {
                        inpath = *(++argv); argc--;
                } else if ((strcmp(*argv, "-o") == 0 ||
                            strcmp(*argv, "--out") == 0) && argc > 1) {
                        outpath = *(++argv); argc--;
                } else if ((strcmp(*argv, "-N") == 0 ||
                            strcmp(*argv, "--bytes") == 0) && argc > 1) {
                        if (parse_size(*(++argv), &max_bytes) < 0) {
                                fprintf(stderr,
                                        "oftp: bad size '%s'\n", *argv);
                                return 1;
                        }
                        argc--;
                } else if (strcmp(*argv, "--help") == 0) {
                        usage();
                        return 0;
                } else {
                        usage();
                        return 1;
                }
                argc--; argv++;
        }

        if (server)
                return server_main(outpath);

        if (name == NULL) {
                usage();
                return 1;
        }

        return client_main(name, inpath, max_bytes);
}
