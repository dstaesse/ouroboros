/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Functions of the IRM tool that are one level deep
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

int ipcp_cmd(int     argc,
             char ** argv);

int do_create_ipcp(int     argc,
                   char ** argv);

int do_destroy_ipcp(int     argc,
                    char ** argv);

int do_bootstrap_ipcp(int     argc,
                      char ** argv);

int do_enroll_ipcp(int     argc,
                   char ** argv);

int bind_cmd(int     argc,
             char ** argv);

int do_bind_ap(int     argc,
               char ** argv);

int do_bind_api(int     argc,
                char ** argv);

int do_bind_ipcp(int     argc,
                 char ** argv);

int unbind_cmd(int     argc,
               char ** argv);

int do_unbind_ap(int     argc,
                 char ** argv);

int do_unbind_api(int     argc,
                  char ** argv);

int do_unbind_ipcp(int     argc,
                   char ** argv);

int do_register(int     argc,
                char ** argv);

int do_unregister(int     argc,
                  char ** argv);
