/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Lockfile for Ouroboros
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/lockfile.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LF_SIZE (sizeof(pid_t))

struct lockfile {
        pid_t * api;
};

struct lockfile * lockfile_create() {
        int fd;
        mode_t mask;
        struct lockfile * lf = malloc(sizeof(*lf));
        if (lf == NULL)
                return NULL;

        mask = umask(0);

        fd = shm_open(LOCKFILE_NAME, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (fd == -1) {
                free(lf);
                return NULL;
        }

        umask(mask);

        if (ftruncate(fd, LF_SIZE - 1) < 0) {
                free(lf);
                return NULL;
        }

        lf->api = mmap(NULL,
                       LF_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       fd,
                       0);

        close (fd);

        if (lf->api == MAP_FAILED) {
                shm_unlink(LOCKFILE_NAME);
                free(lf);
                return NULL;
        }

        *lf->api = getpid();

        return lf;
}

struct lockfile * lockfile_open() {
        int fd;
        struct lockfile * lf = malloc(sizeof(*lf));
        if (lf == NULL)
                return NULL;

        fd = shm_open(LOCKFILE_NAME, O_RDWR, 0666);
        if (fd < 0) {
                free(lf);
                return NULL;
        }

        lf->api = mmap(NULL,
                       LF_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       fd,
                       0);

        close(fd);

        if (lf->api == MAP_FAILED) {
                shm_unlink(LOCKFILE_NAME);
                free(lf);
                return NULL;
        }

        return lf;
}

void lockfile_close(struct lockfile * lf)
{
        assert(lf);

        munmap(lf->api, LF_SIZE);

        free(lf);
}

void lockfile_destroy(struct lockfile * lf)
{
        assert(lf);

        if (getpid() != *lf->api && kill(*lf->api, 0) == 0)
                return;

        munmap(lf->api, LF_SIZE);

        shm_unlink(LOCKFILE_NAME);

        free(lf);
}

pid_t lockfile_owner(struct lockfile * lf)
{
        assert(lf);

        return *lf->api;
}
