/*
 * Ouroboros - Copyright (C) 2016
 *
 * Lockfile for ouroboros system
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <ouroboros/lockfile.h>

#define OUROBOROS_PREFIX "lockfile"

#include <ouroboros/logs.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LF_SIZE (sizeof(pid_t))

struct lockfile {
        pid_t * api;
        int fd;
};

struct lockfile * lockfile_create() {
        struct lockfile * lf = malloc(sizeof(*lf));
        if (lf == NULL)
                return NULL;

        lf->fd = shm_open(LOCKFILE_NAME, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (lf->fd == -1) {
                LOG_DBGF("Could not create lock file.");
                free(lf);
                return NULL;
        }

        if (fchmod(lf->fd, 0666)) {
                LOG_DBGF("Failed to chmod lockfile.");
                free(lf);
                return NULL;
        }

        if (ftruncate(lf->fd, LF_SIZE - 1) < 0) {
                LOG_DBGF("Failed to extend lockfile.");
                free(lf);
                return NULL;
        }

        if (write(lf->fd, "", 1) != 1) {
                LOG_DBGF("Failed to finalise lockfile.");
                free(lf);
                return NULL;
        }

        lf->api = mmap(NULL,
                       LF_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       lf->fd,
                       0);

        if (lf->api == MAP_FAILED) {
                LOG_DBGF("Failed to map lockfile.");

                if (shm_unlink(LOCKFILE_NAME) == -1)
                        LOG_DBGF("Failed to remove invalid lockfile.");

                free(lf);
                return NULL;
        }

        *lf->api = getpid();

        return lf;
}

struct lockfile * lockfile_open() {
        struct lockfile * lf = malloc(sizeof(*lf));
        if (lf == NULL)
                return NULL;

        lf->fd = shm_open(LOCKFILE_NAME, O_RDWR, 0666);
        if (lf->fd < 0) {
                LOG_DBGF("Could not open lock file.");
                free(lf);
                return NULL;
        }

        lf->api = mmap(NULL,
                       LF_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       lf->fd,
                       0);

        if (lf->api == MAP_FAILED) {
                LOG_DBGF("Failed to map lockfile.");

                if (shm_unlink(LOCKFILE_NAME) == -1)
                        LOG_DBGF("Failed to remove invalid lockfile.");

                free(lf);
                return NULL;
        }

        return lf;
}

void lockfile_close(struct lockfile * lf)
{
        if (lf == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        if (close(lf->fd) < 0)
                LOG_DBGF("Couldn't close lockfile.");

        if (munmap(lf->api, LF_SIZE) == -1)
                LOG_DBGF("Couldn't unmap lockfile.");

        free(lf);
}

void lockfile_destroy(struct lockfile * lf)
{
        if (lf == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        if (getpid() != *lf->api && kill(*lf->api, 0) == 0) {
                LOG_DBGF("Only IRMd can destroy %s.", LOCKFILE_NAME);
                return;
        }

        if (close(lf->fd) < 0)
                LOG_DBGF("Couldn't close lockfile.");

        if (munmap(lf->api, LF_SIZE) == -1)
                LOG_DBGF("Couldn't unmap lockfile.");

        if (shm_unlink(LOCKFILE_NAME) == -1)
                LOG_DBGF("Failed to remove lockfile.");

        free(lf);
}

pid_t lockfile_owner(struct lockfile * lf)
{
        return *lf->api;
}
