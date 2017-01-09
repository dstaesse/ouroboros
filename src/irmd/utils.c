/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The IPC Resource Manager - Utilities
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/config.h>
#include <stdlib.h>
#include <string.h>

void argvfree(char ** argv)
{
        char ** argv_dup = argv;
        if (argv == NULL)
                return;

        while (*argv_dup != NULL)
                free(*(argv_dup++));

        free(argv);
}

char ** argvdup(char ** argv)
{
        int argc = 0;
        char ** argv_dup = argv;
        int i;

        if (argv == NULL)
                return NULL;

        while (*(argv_dup++) != NULL)
                argc++;

        if (argc != 0) {
                argv_dup = malloc((argc + 1) * sizeof(*argv_dup));
                for (i = 0; i < argc; ++i) {
                        argv_dup[i] = strdup(argv[i]);
                        if (argv_dup[i] == NULL) {
                                argvfree(argv_dup);
                                return NULL;
                        }
                }
        }
        argv_dup[argc] = NULL;
        return argv_dup;
}

/*
 * Copyright (c) 1989, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Wildcard Match code below is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 * All rights reserved.
 * Portions of this software were developed by David Chisnall
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * wildcard_match is based on the fnmatch function from POSIX.2.
 * Implementation based on that one from FreeBSD.
 */

int wildcard_match(const char * pattern, const char * string)
{
        char c;

        /* For loop? Why not Zoidberg? */
        for (;;) {
                switch (c = *pattern++) {
                case '\0':
                        return (*string == '\0' ? 0 : -1);
                case '*':
                        c = *pattern;

                        if (c == '\0')
                                return 0;

                        /* General case, use recursion. */
                        while ((c = *string) != '\0') {
                                if (!wildcard_match(pattern, string))
                                        return 0;
                                ++string;
                        }
                        return -1;
                default:
                        if (c != *string)
                                return -1;
                        string++;
                        break;
                }
        }
}
