/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * SWIG wrapper file
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

%module ouroboros
%{
#include "ouroboros/cdefs.h"
#include "ouroboros/cacep.h"
#include "ouroboros/dev.h"
#include "ouroboros/errno.h"
#include "ouroboros/fccntl.h"
#include "ouroboros/fqueue.h"
#include "ouroboros/irm.h"
#include "ouroboros/ipcp.h"
#include "ouroboros/qos.h"
#include "ouroboros/version.h"
%}

typedef int pid_t;

%include "ouroboros/cdefs.h"
%include "ouroboros/cacep.h"
%include "ouroboros/dev.h"
%include "ouroboros/errno.h"
%include "ouroboros/fccntl.h"
%include "ouroboros/fqueue.h"
%include "ouroboros/irm.h"
%include "ouroboros/ipcp.h"
%include "ouroboros/qos.h"
%include "ouroboros/version.h"
