/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Lockfile for Ouroboros
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200112L

#include "config.h"

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
#define LF_PROT (PROT_READ | PROT_WRITE)

struct lockfile {
        pid_t * pid;
};

static struct lockfile * __lockfile_open(int oflag)
{
        int    fd;
        struct lockfile * lf;

        lf = malloc(sizeof(*lf));
        if (lf == NULL)
                goto fail_lockfile;

        fd = shm_open(SHM_LOCKFILE_NAME, oflag, 0666);
        if (fd == -1)
                goto fail_shm_open;

        if ((oflag & O_CREAT) && ftruncate(fd, LF_SIZE) < 0)
                goto fail_truncate;

        lf->pid = mmap(NULL, LF_SIZE, LF_PROT, MAP_SHARED, fd, 0);
        if (lf->pid == MAP_FAILED)
                goto fail_mmap;

        close (fd);

        return lf;

 fail_mmap:
        shm_unlink(SHM_LOCKFILE_NAME);
 fail_truncate:
        close(fd);
 fail_shm_open:
        free(lf);
 fail_lockfile:
        return NULL;
}

struct lockfile * lockfile_create(void)
{
        struct lockfile * lf;
        mode_t            mask;

        mask = umask(0);

        lf = __lockfile_open(O_CREAT | O_EXCL | O_RDWR);
        if (lf == NULL)
                return NULL;

        umask(mask);

        *lf->pid = getpid();

        return lf;
}

struct lockfile * lockfile_open(void)
{
        return __lockfile_open(O_RDWR);
}

void lockfile_close(struct lockfile * lf)
{
        assert(lf);

        munmap(lf->pid, LF_SIZE);

        free(lf);
}

void lockfile_destroy(struct lockfile * lf)
{
        assert(lf);

        if (getpid() != *lf->pid && kill(*lf->pid, 0) == 0)
                return;

        lockfile_close(lf);

        shm_unlink(SHM_LOCKFILE_NAME);
}

pid_t lockfile_owner(struct lockfile * lf)
{
        assert(lf);

        return *lf->pid;
}
