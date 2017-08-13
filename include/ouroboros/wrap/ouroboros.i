/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * SWIG wrapper file
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
#include "ouroboros/cdap.h"
#include "ouroboros/dev.h"
#include "ouroboros/errno.h"
#include "ouroboros/fcntl.h"
#include "ouroboros/fqueue.h"
#include "ouroboros/irm.h"
#include "ouroboros/ipcp.h"
#include "ouroboros/nsm.h"
#include "ouroboros/qos.h"
%}

typedef int pid_t;

%include "ouroboros/cdefs.h"
%include "ouroboros/cacep.h"
%include "ouroboros/cdap.h"
%include "ouroboros/dev.h"
%include "ouroboros/errno.h"
%include "ouroboros/fcntl.h"
%include "ouroboros/fqueue.h"
%include "ouroboros/irm.h"
%include "ouroboros/ipcp.h"
%include "ouroboros/nsm.h"
%include "ouroboros/qos.h"
