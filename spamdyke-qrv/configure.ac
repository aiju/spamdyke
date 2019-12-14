# Process this file with autoconf to produce a configure script.
################################################################################
# spamdyke -- a filter for stopping spam at connection time.
# Copyright (C) 2015 Sam Clippinger (samc (at) silence (dot) org)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_PREREQ(2.59)
AC_INIT([[spamdyke-qrv]], [[5.0.1]], [[samc (at) silence (dot) org]])
AC_CONFIG_SRCDIR([spamdyke-qrv.c])
AC_CONFIG_HEADER([config-qrv.h])

AC_LANG_WERROR
CFLAGS=-Wall

# Checks for programs.
AC_PROG_CC([[gcc]])

AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([sys/inttypes.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([stdint.h sys/inttypes.h],
                 [],
                 [],
                 [[ #ifdef HAVE_NUMBER_H
                    #include <number.h>
                    #endif
                 ]])

AC_HEADER_TIME

AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_MSG_CHECKING([whether to include debugging symbols (for gdb)])
AC_ARG_WITH([debug-symbols],
            [ AS_HELP_STRING([--with-debug-symbols], [include debugging symbols (for gdb) @<:@default=no@:>@]) ],
            [ AS_IF([ test "x$with_debug_symbols" != "xno" ],
                    [ AC_MSG_RESULT([yes])
                      CFLAGS="${CFLAGS} -g" ],
                    [ AC_MSG_RESULT([no])
                      AC_CHECK_PROG([STRIP_CMD], [strip], [strip spamdyke-qrv], [])
                      CFLAGS="${CFLAGS} -O2"
                    ])
            ],
            [ AC_MSG_RESULT([no])
              AC_CHECK_PROG([STRIP_CMD], [strip], [strip spamdyke-qrv], [])
              CFLAGS="${CFLAGS} -O2"
            ])

AC_MSG_CHECKING([whether to include excessive debugging output])
AC_ARG_WITH([excessive-output],
            [ AS_HELP_STRING([--with-excessive-output], [include excessive debugging output @<:@default=no@:>@]) ],
            [ AS_IF([ test "x$with_excessive_output" != "xno" ],
                    [ AC_MSG_RESULT([yes])
                      AC_DEFINE([WITH_EXCESSIVE_OUTPUT], [1])
                      with_debug_output="yes" ],
                    [ AC_MSG_RESULT([no]) ])
            ],
            [ AC_MSG_RESULT([no]) ])

AC_ARG_VAR([VALIAS_PATH], [full path to vpopmail's valias binary (required for vpopmail support)])
AC_ARG_VAR([VUSERINFO_PATH], [full path to vpopmail's vuserinfo binary (required for vpopmail support)])

AC_MSG_CHECKING([whether to include extra support for vpopmail servers])
AC_ARG_WITH([vpopmail-support],
            [ AS_HELP_STRING([--with-vpopmail-support], [include extra support for vpopmail servers, requires VALIAS_PATH and VUSERINFO_PATH variables @<:@default=no@:>@]) ],
            [ AS_IF([ test "x$with_vpopmail_support" != "xno" ],
                    [ AC_MSG_RESULT([yes])
                      AC_DEFINE([WITH_VPOPMAIL_SUPPORT], [1])
                      VPOPMAIL_SUPPORT="yes"
                      with_vpopmail_support="yes" ],
                    [ AC_MSG_RESULT([no]) ])
            ],
            [ AC_MSG_RESULT([no])
              VPOPMAIL_SUPPORT="no" ])

AS_IF([ test "x$VPOPMAIL_SUPPORT" = "xyes" ],
      [ AC_MSG_CHECKING([whether valias binary exists])
        AS_IF([ test "x$VALIAS_PATH" != "x" ],
              [ AC_CHECK_PROG([VPOPMAIL_VALIAS_PATH], [$VALIAS_PATH], [$VALIAS_PATH], [], [/])
                AS_IF([ test "x$VPOPMAIL_VALIAS_PATH" != "x" ],
                      [ AC_DEFINE_UNQUOTED([VPOPMAIL_VALIAS_PATH], ["$VPOPMAIL_VALIAS_PATH"]) ],
                      [ AC_MSG_ERROR([unable to compile spamdyke-qrv with vpopmail support and without a valid value for VALIAS_PATH]) ]) ],
              [ AC_MSG_RESULT([no])
                AC_MSG_ERROR([unable to compile spamdyke-qrv with vpopmail support and without a valid value for VALIAS_PATH]) ])
        AC_MSG_CHECKING([whether vuserinfo binary exists])
        AS_IF([ test "x$VUSERINFO_PATH" != "x" ],
              [ AC_CHECK_PROG([VPOPMAIL_VUSERINFO_PATH], [$VUSERINFO_PATH], [$VUSERINFO_PATH], [], [/])
                AS_IF([ test "x$VPOPMAIL_VUSERINFO_PATH" != "x" ],
                      [ AC_DEFINE_UNQUOTED([VPOPMAIL_VUSERINFO_PATH], ["$VPOPMAIL_VUSERINFO_PATH"]) ],
                      [ AC_MSG_ERROR([unable to compile spamdyke-qrv with vpopmail support and without a valid value for VUSERINFO_PATH]) ]) ],
              [ AC_MSG_RESULT([no])
                AC_MSG_ERROR([unable to compile spamdyke-qrv with vpopmail support and without a valid value for VUSERINFO_PATH]) ]) ])

AC_MSG_CHECKING([whether to compile with address sanitizer])
AC_ARG_WITH([address-sanitizer],
            [ AS_HELP_STRING([--with-address-sanitizer], [compile with ASan (for developers only) https://code.google.com/p/address-sanitizer/wiki/AddressSanitizer @<:@default=no@:>@]) ],
            [ AS_IF([ test "x$with_address_sanitizer" != "xno" ],
                    [ AC_MSG_CHECKING([if address sanitizer is available])
                      OLD_CFLAGS=$CFLAGS
                      CFLAGS="$OLD_CFLAGS -fsanitize=address"
                      AC_TRY_COMPILE([ #include <stdio.h> ],
                                     [],
                                     [ AC_MSG_RESULT([yes])
                                       AC_DEFINE([WITH_ADDRESS_SANITIZER], [1]) ],
                                     [ AC_MSG_RESULT([no])
                                       CFLAGS=$OLD_CFLAGS
                                     ])
                    ],
                    [ AC_MSG_RESULT([not supported here]) ])
            ],
            [ AC_MSG_RESULT([no]) ])

AC_MSG_CHECKING([whether __func__ is available])
AC_TRY_COMPILE([],
               [ char *foo;
                 if ((foo = (char *)__func__)) return(0); ],
               [ AC_MSG_RESULT([yes]) ],
               [ AC_MSG_RESULT([no])
                 AC_MSG_CHECKING([whether __FUNCTION__ is available])
                 AC_TRY_COMPILE([],
                                [ char *foo;
                                  if ((foo = (char *)__FUNCTION__)) return(0); ],
                                [ AC_MSG_RESULT([yes])
                                  AC_DEFINE([__func__], [__FUNCTION__]) ],
                                [ AC_MSG_RESULT([no])
                                  AC_DEFINE([__func__], ["(unknown)"]) ])
               ])

AC_MSG_CHECKING([whether uid_t is an unsigned int or an unsigned long])
AC_TRY_COMPILE([ #include <stdio.h>
                 #include <sys/types.h>
                 #include <unistd.h>
                 #ifdef USE_PRAGMA
                 #pragma GCC diagnostic error "-Wformat"
                 #endif ],
               [ printf("%u", getuid()); ],
               [ AC_MSG_RESULT([unsigned int])
                 AC_DEFINE([FORMAT_UID_T], ["%u"]) ],
               [ AC_MSG_RESULT([unsigned long])
                 AC_DEFINE([FORMAT_UID_T], ["%lu"]) ])

AC_MSG_CHECKING([whether gid_t is an unsigned int or an unsigned long])
AC_TRY_COMPILE([ #include <stdio.h>
                 #include <sys/types.h>
                 #include <unistd.h>
                 #ifdef USE_PRAGMA
                 #pragma GCC diagnostic error "-Wformat"
                 #endif ],
               [ printf("%u", getgid()); ],
               [ AC_MSG_RESULT([unsigned int])
                 AC_DEFINE([FORMAT_GID_T], ["%u"]) ],
               [ AC_MSG_RESULT([unsigned long])
                 AC_DEFINE([FORMAT_GID_T], ["%lu"]) ])

AC_MSG_CHECKING([whether int64_ts are supported in a test program])
AC_TRY_COMPILE([ #ifdef HAVE_INTTYPES_H
                 #include <inttypes.h>
                 #endif
                 #ifdef HAVE_STDINT_H
                 #include <stdint.h>
                 #endif
                 #ifdef HAVE_SYS_TYPES_H
                 #include <sys/types.h>
                 #endif ],
               [ int64_t foo;
                 int64_t bar;
                 foo = 0x7777777777777777ULL;
                 bar = 0x7777777777777777ULL;
                 if (foo == bar) return(0); ],
               [ AC_MSG_RESULT([yes])
                 AC_MSG_CHECKING([whether printf()/scanf() uses %ld for 64-bit integers])
                 AC_RUN_IFELSE([ AC_LANG_PROGRAM([ #ifdef HAVE_INTTYPES_H
                                                   #include <inttypes.h>
                                                   #endif
                                                   #ifdef HAVE_STDINT_H
                                                   #include <stdint.h>
                                                   #endif
                                                   #ifdef HAVE_SYS_TYPES_H
                                                   #include <sys/types.h>
                                                   #endif
                                                   #include <stdio.h>
                                                   #ifdef USE_PRAGMA
                                                   #pragma GCC diagnostic error "-Wformat"
                                                   #endif ],
                                                 [ int64_t tmp;
                                                   tmp = 0x7777777777777777ULL;
                                                   if ((sscanf("1", "%ld", &tmp) != 1) ||
                                                       (tmp != 1))
                                                     return(1);
                                                   return(0);
                                                 ])
                               ],
                               [ AC_MSG_RESULT([yes])
                                 AC_DEFINE([FORMAT_INT64_T], ["%ld"])
                                 AC_DEFINE([FORMAT_UINT64_T], ["%lu"]) ],
                               [ AC_MSG_RESULT([no])
                                 AC_MSG_CHECKING([whether printf()/scanf() uses %lld for 64-bit integers])
                                 AC_RUN_IFELSE([ AC_LANG_PROGRAM([ #ifdef HAVE_INTTYPES_H
                                                                   #include <inttypes.h>
                                                                   #endif
                                                                   #ifdef HAVE_STDINT_H
                                                                   #include <stdint.h>
                                                                   #endif
                                                                   #ifdef HAVE_SYS_TYPES_H
                                                                   #include <sys/types.h>
                                                                   #endif
                                                                   #include <stdio.h>
                                                                   #ifdef USE_PRAGMA
                                                                   #pragma GCC diagnostic error "-Wformat"
                                                                   #endif ],
                                                                 [ int64_t tmp;
                                                                   tmp = 0x7777777777777777ULL;
                                                                   if ((sscanf("1", "%lld", &tmp) != 1) ||
                                                                       (tmp != 1))
                                                                     return(1);
                                                                   return(0);
                                                                 ])
                                               ],
                                               [ AC_MSG_RESULT([yes])
                                                 AC_DEFINE([FORMAT_INT64_T], ["%lld"])
                                                 AC_DEFINE([FORMAT_UINT64_T], ["%llu"]) ],
                                               [ AC_MSG_RESULT([no])
                                                 AC_MSG_CHECKING([whether printf()/scanf() uses %qd for 64-bit integers])
                                                 AC_RUN_IFELSE([ AC_LANG_PROGRAM([ #ifdef HAVE_INTTYPES_H
                                                                                   #include <inttypes.h>
                                                                                   #endif
                                                                                   #ifdef HAVE_STDINT_H
                                                                                   #include <stdint.h>
                                                                                   #endif
                                                                                   #ifdef HAVE_SYS_TYPES_H
                                                                                   #include <sys/types.h>
                                                                                   #endif
                                                                                   #include <stdio.h>
                                                                                   #ifdef USE_PRAGMA
                                                                                   #pragma GCC diagnostic error "-Wformat"
                                                                                   #endif ],
                                                                                 [ int64_t tmp;
                                                                                   tmp = 0x7777777777777777ULL;
                                                                                   if ((sscanf("1", "%qd", &tmp) != 1) ||
                                                                                       (tmp != 1))
                                                                                     return(1);
                                                                                   return(0);
                                                                                 ])
                                                               ],
                                                               [ AC_MSG_RESULT([yes])
                                                                 AC_DEFINE([FORMAT_INT64_T], ["%qd"])
                                                                 AC_DEFINE([FORMAT_UINT64_T], ["%qu"]) ],
                                                               [ AC_MSG_RESULT([no])
                                                                 AC_MSG_FAILURE([Unable to compile without a printf()/scanf() pattern for 64-bit integers.])
                                                               ])
                                               ])
                               ])
               ],
               [ AC_MSG_RESULT([no])
                 AC_MSG_FAILURE([Unable to test if/how 64-bit integers should be used]) ])

AC_SEARCH_LIBS([getopt_long],
               [gnugetopt],
               [],
               [
                 CFLAGS="$CFLAGS -I/usr/local/include"
                 LDFLAGS="$LDFLAGS -L/usr/local/lib"
                 ac_cv_search_getopt_long=""
                 AC_SEARCH_LIBS([getopt_long],
                                [gnugetopt],
                                [ LDFLAGS="$LDFLAGS -lgnugetopt" ],
                                [ AC_MSG_FAILURE([unable to compile without getopt_long(), you may need to install the libgnugetopt package/port]) ])
               ])

AC_MSG_CHECKING([whether struct option is defined in getopt.h])
AC_TRY_COMPILE([ #define _GNU_SOURCE
                 #include <stdio.h>
                 #include <getopt.h> ],
               [ struct option tmp_option;
                 if ((tmp_option.name = NULL)) return(0); ],
               [ AC_MSG_RESULT([yes])
                 AC_DEFINE([HAVE_GETOPT_H], [1]) ],
               [ AC_MSG_RESULT([no])
                 AC_MSG_CHECKING([whether struct option is defined in unistd.h])
                 AC_TRY_COMPILE([ #include <stdio.h>
                                  #include <unistd.h> ],
                                [ struct option tmp_option;
                                  if ((tmp_option.name = NULL)) return(0); ],
                                [ AC_MSG_RESULT([yes]) ],
                                [ AC_MSG_RESULT([no])
                                  AC_MSG_FAILURE([Unable to compile without struct option for getopt_long()])
                                ])
               ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
