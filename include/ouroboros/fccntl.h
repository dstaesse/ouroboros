/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Flow and FRCT connection control
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_FCCNTL_H
#define OUROBOROS_FCCNTL_H

#include <ouroboros/cdefs.h>

#include <sys/time.h>

/* Flow flags, same values as fcntl.h */
#define FLOWFRDONLY   00000000 /* Read-only flow         */
#define FLOWFWRONLY   00000001 /* Write-only flow        */
#define FLOWFRDWR     00000002 /* Read-write flow        */
#define FLOWFACCMODE  00000003 /* Access mask            */

#define FLOWFDOWN     00000004 /* Flow is down           */

#define FLOWFRNOBLOCK 00001000 /* Non-blocking read      */
#define FLOWFWNOBLOCK 00002000 /* Non-blocking write     */
#define FLOWFNONBLOCK (FLOWFRNOBLOCK | FLOWFWNOBLOCK)
#define FLOWFRNOPART  00010000 /* Disable partial reads  */
#define FLOWFWNOPART  00020000 /* Disable partial writes */

#define FLOWFDEFAULT  (FLOWFRDWR | FLOWFWNOPART)

#define FLOWFINVALID  (FLOWFWRONLY | FLOWFRDWR)

/* FRCT flags */
#define FRCTFRESCNTRL 00000001 /* Feedback from receiver */
#define FRCTFRTX      00000002 /* Reliable flow          */
#define FRCTFLINGER   00000004 /* Sent unsent data       */

/* Flow operations */
#define FLOWSRCVTIMEO 00000001 /* Set read timeout       */
#define FLOWGRCVTIMEO 00000002 /* Get read timeout       */
#define FLOWSSNDTIMEO 00000003 /* Set send timeout       */
#define FLOWGSNDTIMEO 00000004 /* Get send timeout       */
#define FLOWGQOSSPEC  00000005 /* Get qosspec_t          */
#define FLOWSFLAGS    00000006 /* Set flags for flow     */
#define FLOWGFLAGS    00000007 /* Get flags for flow     */
#define FLOWGRXQLEN   00000010 /* Get queue length on rx */
#define FLOWGTXQLEN   00000011 /* Get queue length on tx */

/* FRCT operations */
#define FRCTSFLAGS    00001000 /* Set flags for FRCT     */
#define FRCTGFLAGS    00002000 /* Get flags for FRCT     */

__BEGIN_DECLS

int fccntl(int fd,
           int cmd,
           ...);

__END_DECLS

#endif /* OUROBOROS_FCCNTL_H */
