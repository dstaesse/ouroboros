/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * RIB export using FUSE
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

#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/rib.h>
#include <ouroboros/utils.h>


#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_FUSE
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION  26
#if defined (__linux__)
#define __USE_XOPEN
#elif defined (__FreeBSD__)
#define __XSI_VISIBLE 500
#endif /* __linux__ */
#include <sys/stat.h>
#include <fuse.h>

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

#define RT "/"

struct reg_comp {
        struct list_head next;

        char             path[RIB_PATH_LEN + 1];
        struct rib_ops * ops;
};

struct {
        struct list_head   reg_comps;

        char               mnt[RIB_PATH_LEN + 1];

        struct fuse *      fuse;
        struct fuse_chan * ch;

        pthread_rwlock_t   lock;

        pthread_t          fuse_thr;
} rib;

static int rib_open(const char *            path,
                    struct fuse_file_info * info)
{
        (void) path;

        info->nonseekable = 1;

        return 0;
}

static int rib_opendir(const char *         path,
                    struct fuse_file_info * info)
{
        (void) path;
        (void) info;

        return 0;
}

static int rib_read(const char *            path,
                    char *                  buf,
                    size_t                  size,
                    off_t                   offset,
                    struct fuse_file_info * info)
{
        struct list_head * p;
        char               comp[RIB_PATH_LEN + 1];
        char *             c;

        if (strlen(path) > RIB_PATH_LEN)
                return -1;

        strcpy(comp, path + 1);

        c = strstr(comp, "/");

        if (c != NULL)
                *c = '\0';

        (void) info;
        (void) offset;

        pthread_rwlock_wrlock(&rib.lock);

        list_for_each(p, &rib.reg_comps) {
                struct reg_comp * r = list_entry(p, struct reg_comp, next);
                if (strcmp(comp, r->path) == 0) {
                        int ret = r->ops->read(c + 1, buf, size);
                        pthread_rwlock_unlock(&rib.lock);
                        return ret;
                }
        }

        pthread_rwlock_unlock(&rib.lock);

        return -1;
}

static int rib_readdir(const char *            path,
                       void *                  buf,
                       fuse_fill_dir_t         filler,
                       off_t                   offset,
                       struct fuse_file_info * info)
{
        struct list_head * p;

        (void) offset;
        (void) info;

        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);

        pthread_rwlock_rdlock(&rib.lock);

        if (strcmp(path, RT) == 0) {
                list_for_each(p, &rib.reg_comps) {
                        struct reg_comp * c;
                        c = list_entry(p, struct reg_comp, next);
                        filler(buf, c->path, NULL, 0);
                }
        } else {
                list_for_each(p, &rib.reg_comps) {
                        char **           dir_entries;
                        ssize_t           len;
                        ssize_t           i;
                        struct reg_comp * c;
                        c = list_entry(p, struct reg_comp, next);

                        if (strcmp(path + 1, c->path) != 0)
                                continue;

                        assert(c->ops->readdir != NULL);

                        len = c->ops->readdir(&dir_entries);
                        if (len < 0)
                                break;
                        for (i = 0; i < len; ++i)
                                filler(buf, dir_entries[i], NULL, 0);
                        freepp(char, dir_entries, len);
                }
        }

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

static size_t __getattr(const char *  path,
                        struct stat * st)
{
        struct list_head * p;
        char               comp[RIB_PATH_LEN + 1];
        char *             c;
        struct rib_attr    attr;

        if (strlen(path) > RIB_PATH_LEN)
                return -1;

        strcpy(comp, path + 1);

        c = strstr(comp, "/");

        if (c != NULL)
                *c = '\0';

        memset(&attr, 0, sizeof(attr));

        pthread_rwlock_rdlock(&rib.lock);

        list_for_each(p, &rib.reg_comps) {
                struct reg_comp * r = list_entry(p, struct reg_comp, next);
                if (strcmp(comp, r->path) == 0) {
                        size_t ret = r->ops->getattr(c + 1, &attr);
                        pthread_rwlock_unlock(&rib.lock);
                        st->st_mode  = S_IFREG | 0755;
                        st->st_nlink = 1;
                        st->st_uid   = getuid();
                        st->st_gid   = getgid();
                        st->st_size  = attr.size;
                        st->st_mtime = attr.mtime;
                        return ret;
                }
        }

        pthread_rwlock_unlock(&rib.lock);

        return -1;
}

static int rib_getattr(const char *  path,
                       struct stat * st)
{
        struct list_head * p;
        struct timespec    now;

        memset(st, 0, sizeof(*st));

        if (strcmp(path, RT) == 0)
                goto finish_dir;

        pthread_rwlock_rdlock(&rib.lock);

        list_for_each(p, &rib.reg_comps) {
                struct reg_comp * rc = list_entry(p, struct reg_comp, next);
                if (strcmp(path + 1, rc->path) == 0) {
                        pthread_rwlock_unlock(&rib.lock);
                        goto finish_dir;
                }
        }

        pthread_rwlock_unlock(&rib.lock);

        assert(st->st_mode == 0);

        return __getattr(path, st);

 finish_dir:
        clock_gettime(CLOCK_REALTIME_COARSE, &now);
        st->st_mode  = S_IFDIR | 0755;
        st->st_nlink = 2;
        st->st_uid   = getuid();
        st->st_gid   = getgid();
        st->st_mtime = now.tv_sec;
        return 0;
}

static struct fuse_operations r_ops = {
        .getattr = rib_getattr,
        .open    = rib_open,
        .opendir = rib_opendir,
        .read    = rib_read,
        .readdir = rib_readdir
};

static void * fuse_thr(void * o)
{
        if (fuse_loop((struct fuse *) o) < 0)
                return (void *) -1;

        return (void *) 0;
}
#endif /* HAVE_FUSE */

int rib_init(const char * mountpt)
{
#ifdef HAVE_FUSE
        struct stat      st;
        char *           argv[] = {"-f",
                                   "-o",
                                   "ro,"
                                   "default_permissions,"
                                   "allow_other,"
                                   "fsname=rib",
                                   NULL};
        struct fuse_args args = FUSE_ARGS_INIT(3, argv);

        if (stat(FUSE_PREFIX, &st) == -1)
                return -1;

        sprintf(rib.mnt, FUSE_PREFIX "/%s", mountpt);

        if (stat(rib.mnt, &st) == -1)
                switch(errno) {
                case ENOENT:
                        if (mkdir(rib.mnt, 0777))
                                return -1;
                        break;
                case ENOTCONN:
                        fuse_unmount(rib.mnt, rib.ch);
                        break;
                default:
                        return -1;
                }

        fuse_opt_parse(&args, NULL, NULL, NULL);

        list_head_init(&rib.reg_comps);

        rib.ch = fuse_mount(rib.mnt,  &args);
        if (rib.ch == NULL)
                goto fail_mount;

        rib.fuse = fuse_new(rib.ch, &args, &r_ops, sizeof(r_ops), NULL);
        if (rib.fuse == NULL)
                goto fail_fuse;

        if (pthread_rwlock_init(&rib.lock, NULL))
                goto fail_rwlock_init;

        if (pthread_create(&rib.fuse_thr, NULL, fuse_thr, rib.fuse))
                goto fail_fuse_thr;

        fuse_opt_free_args(&args);

        return 0;

 fail_fuse_thr:
        pthread_rwlock_destroy(&rib.lock);
 fail_rwlock_init:
        fuse_destroy(rib.fuse);
 fail_fuse:
        fuse_unmount(rib.mnt, rib.ch);
 fail_mount:
        fuse_opt_free_args(&args);
        rmdir(rib.mnt);
        return -1;
#else
        (void) mountpt;
        return 0;
#endif
}

void rib_fini(void)
{
#ifdef HAVE_FUSE
        struct list_head * p;
        struct list_head * h;

        fuse_exit(rib.fuse);

        fuse_unmount(rib.mnt, rib.ch);

        pthread_join(rib.fuse_thr, NULL);

        fuse_destroy(rib.fuse);

        rmdir(rib.mnt);

        pthread_rwlock_wrlock(&rib.lock);

        list_for_each_safe(p, h, &rib.reg_comps) {
                struct reg_comp * c = list_entry(p, struct reg_comp, next);
                list_del(&c->next);
                free(c);
        }

        pthread_rwlock_unlock(&rib.lock);

        pthread_rwlock_destroy(&rib.lock);
#endif
}

int rib_reg(const char *     path,
            struct rib_ops * ops)
{
#ifdef HAVE_FUSE
        struct reg_comp *  rc;
        struct list_head * p;

        if (strlen(rib.mnt) == 0)
                return 0;

        pthread_rwlock_wrlock(&rib.lock);

        list_for_each(p, &rib.reg_comps) {
                struct reg_comp * r = list_entry(p, struct reg_comp, next);
                if (strcmp(r->path, path) == 0) {
                        pthread_rwlock_unlock(&rib.lock);
                        return -EPERM;
                }

                if (strcmp(r->path, path) > 0)
                        break;
        }

        rc = malloc(sizeof(*rc));
        if (rc == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -ENOMEM;
        }

        if (strlen(path) > RIB_PATH_LEN) {
                pthread_rwlock_unlock(&rib.lock);
                free(rc);
                return -1;
        }

        strcpy(rc->path, path);
        rc->ops = ops;

        list_add_tail(&rc->next, p);

        pthread_rwlock_unlock(&rib.lock);
#else
        (void) path;
        (void) ops;
#endif
        return 0;
}

void rib_unreg(const char * path)
{
#ifdef HAVE_FUSE
        struct list_head * p;
        struct list_head * h;

        if (strlen(rib.mnt) == 0)
                return;

        pthread_rwlock_wrlock(&rib.lock);

        list_for_each_safe(p, h, &rib.reg_comps) {
                struct reg_comp * r = list_entry(p, struct reg_comp, next);
                if (strcmp(r->path, path) == 0) {
                        list_del(&r->next);
                        free(r);
                        break;
                }
        }

        pthread_rwlock_unlock(&rib.lock);
#else
        (void) path;
#endif
}
