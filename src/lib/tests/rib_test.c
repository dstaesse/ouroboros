/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Test of the RIB
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/config.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/rib.h>
#include <ouroboros/rqueue.h>
#include <ouroboros/errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RIB_MAX_PATH_LEN 256

int rib_test(int     argc,
             char ** argv)
{
        uint64_t * address;

        size_t addr_size = 8;
        size_t addr_chk;

        char * addr_name;

        ro_set_t * set;
        rqueue_t * rq;

        int ret;

        char tmp[RIB_MAX_PATH_LEN];

        char ** kids;
        ssize_t ch;

        uint8_t * buf;
        ssize_t   buf_len;

        struct timespec t = {0, 100 * MILLION};

        (void) argc;
        (void) argv;

        address = malloc(sizeof(*address));
        if (address == NULL)
                return -ENOMEM;

        if (rib_init()) {
                printf("Failed to initialize rib.\n");
                return -1;
        }

        rib_fini();

        if (rib_init()) {
                printf("Failed to re-initialize rib.\n");
                return -1;
        }

        if (rib_add(RIB_ROOT, "static_info")) {
                printf("Failed to add element to rib.\n");
                rib_fini();
                return -1;
        }

        ch = rib_children("/static_info", &kids);
        if (ch != 0) {
                printf("Wrong number of children returned.\n");
                rib_fini();
                while (ch > 0)
                        free(kids[--ch]);
                free(kids);
                return -1;
        }

        if (!rib_has("/static_info")) {
                printf("Failed to find added element.\n");
                rib_fini();
                return -1;
        }

        if (rib_add(RIB_ROOT, "dynamic_info")) {
                printf("Failed to add element to rib.\n");
                rib_fini();
                return -1;
        }

        if (rib_add("/static_info", "addr_size")) {
                printf("Failed to add sub-element to rib.\n");
                rib_fini();
                return -1;
        }

        if (rib_write("/static_info/addr_size",
                    &addr_size, sizeof(addr_size))) {
                printf("Failed to add sub-element to rib.\n");
                rib_fini();
                return -1;
        }

        if (rib_add("/static_info", "addresses")) {
                printf("Failed to add sub-element to rib.\n");
                rib_fini();
                return -1;
        }

        if (!rib_has("/static_info/addr_size")) {
                printf("Failed to find added subelement.\n");
                rib_fini();
                return -1;
        }

        if (rib_read("/static_info/addr_size",
                     &addr_chk, sizeof(addr_chk))
            != sizeof(addr_chk)) {
                printf("Failed to read added element.\n");
                rib_fini();
                return -1;
        }

        ch = rib_children("/static_info", &kids);
        if (ch != 2) {
                printf("Wrong number of children returned.\n");
                rib_fini();
                return -1;
        }

        while (ch > 0)
                free(kids[--ch]);
        free(kids);

        if (addr_chk != addr_size) {
                printf("Failed to verify added element contents.\n");
                rib_fini();
                return -1;
        }

        addr_size = 16;

        if (rib_write("/static_info/addr_size",
                      &addr_size, sizeof(addr_size))) {
                printf("Failed to write into added element.\n");
                rib_fini();
                return -1;
        }

        if (rib_read("/static_info/addr_size",
                     &addr_chk, sizeof(addr_chk))
            != sizeof(addr_chk)) {
                printf("Failed to verify added element update size.\n");
                rib_fini();
                return -1;
        }

        if (addr_chk != addr_size) {
                printf("Failed to verify added element update size.\n");
                rib_fini();
                return -1;
        }

        addr_name = rib_name_gen(address, sizeof(*address));
        if (addr_name == NULL) {
                printf("Failed to create a name.\n");
                rib_fini();
                return -1;
        }

        strcpy(tmp, "/dynamic_info");

        if (rib_add(tmp, addr_name)) {
                free(addr_name);
                printf("Failed to add address.\n");
                rib_fini();
                return -1;
        }

        rib_path_append(tmp, addr_name);

        if (rib_put(tmp, address, sizeof(*address))) {
                free(addr_name);
                printf("Failed to add address.\n");
                rib_fini();
                return -1;
        }

        free(addr_name);

        buf_len = rib_pack("/static_info", &buf, PACK_HASH_ALL);
        if (buf_len < 0) {
                printf("Failed pack.\n");
                rib_fini();
                return -1;
        }

        if (rib_del("/static_info")) {
                printf("Failed to delete.\n");
                rib_fini();
                return -1;
        }

        if (rib_unpack(buf, buf_len, UNPACK_CREATE)) {
                printf("Failed to unpack.\n");
                rib_fini();
                return -1;
        }

        if (!rib_has("/static_info")) {
                printf("Failed to find unpacked element.\n");
                rib_fini();
                return -1;
        }

        ch = rib_children("/static_info", &kids);
        if (ch != 2) {
                printf("Wrong number of children returned.\n");
                rib_fini();
                return -1;
        }

        while (ch > 0)
                free(kids[--ch]);
        free(kids);

        set = ro_set_create();
        if (set == NULL) {
                printf("Failed to create ro_set.\n");
                rib_fini();
                return -1;
        }

        rq = rqueue_create();
        if (rq == NULL) {
                printf("Failed to create rqueue.\n");
                ro_set_destroy(set);
                rib_fini();
                return -1;
        }

        if (ro_set_add(set, "/static_info", RO_ALL_OPS)) {
                printf("Failed to add to rqueue.\n");
                ro_set_destroy(set);
                rqueue_destroy(rq);
                rib_fini();
                return -1;
        }

        ret = rib_event_wait(set, rq, &t);
        if (ret != -ETIMEDOUT) {
                printf("Wait failed to timeout: %d.\n", ret);
                ro_set_destroy(set);
                rqueue_destroy(rq);
                rib_fini();
                return -1;
        }

        if (rib_del("/static_info")) {
                printf("Failed to delete rib subtree.\n");
                rib_fini();
                return -1;
        }

        ro_set_destroy(set);

        rqueue_destroy(rq);

        rib_fini();

        return 0;
}
