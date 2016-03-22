/*
 * Ouroboros - Copyright (C) 2016
 *
 * API for applications
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "libouroboros-dev"

#include <ouroboros/logs.h>
#include <ouroboros/dev.h>

int ap_reg(char * ap_name, char * ae_name,
           char ** difs, size_t difs_size)
{
        LOG_MISSING;

        return -1;
}

int ap_unreg(char * ap_name, char * ae_name,
             char ** difs, size_t difs_size)
{
        LOG_MISSING;

        return -1;
}

int flow_accept(int fd, char * ap_name, char * ae_name)
{
        LOG_MISSING;

        return -1;
}

int flow_alloc_resp(int fd, int result)
{
        LOG_MISSING;

        return -1;
}

int flow_alloc(char * dst_ap_name, char * dst_ae_name,
               char * src_ap_name, char * src_ae_name,
               struct qos_spec * qos, int oflags)
{
        LOG_MISSING;

        return -1;
}

int flow_alloc_res(int fd)
{
        LOG_MISSING;

        return -1;
}

int flow_dealloc(int fd)
{
        LOG_MISSING;

        return -1;
}

int flow_cntl(int fd, int oflags)
{
        LOG_MISSING;

        return -1;
}

ssize_t flow_write(int fd,
                   void * buf,
                   size_t count)
{
        LOG_MISSING;

        return -1;
}

ssize_t flow_read(int fd,
                  void * buf,
                  size_t count)
{
        LOG_MISSING;

        return -1;
}
