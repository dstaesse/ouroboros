/*
 * Ouroboros - Copyright (C) 2016
 *
 * SWIG wrapper file
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

%module ouroboros
%{
#include "ouroboros/cdap.h"
#include "ouroboros/dev.h"
#include "ouroboros/errno.h"
#include "ouroboros/flow.h"
#include "ouroboros/irm.h"
#include "ouroboros/irm_config.h"
#include "ouroboros/nsm.h"
#include "ouroboros/qos.h"
%}

typedef int pid_t;

%include "ouroboros/cdap.h"
%include "ouroboros/dev.h"
%include "ouroboros/errno.h"
%include "ouroboros/flow.h"
%include "ouroboros/irm.h"
%include "ouroboros/irm_config.h"
%include "ouroboros/nsm.h"
%include "ouroboros/qos.h"
