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
AC_INIT([[spamdyke]], [[5.0.1]], [[samc (at) silence (dot) org]])
AC_CONFIG_SRCDIR([spamdyke.h])
AC_CONFIG_HEADER([config.h])

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
AC_STRUCT_DIRENT_D_TYPE

AC_CHECK_DECLS([DT_WHT],
               [ AC_CHECK_DECLS([S_IFWHT],
                                [ AC_DEFINE([HAVE_WHITEOUT], [1]) ],
                                [],
                                [ AC_INCLUDES_DEFAULT
                                  [ #include <sys/types.h>
                                    #include <sys/stat.h>
                                    #include <dirent.h> ]]) ],
               [],
               [ AC_INCLUDES_DEFAULT
                 [ #include <sys/types.h>
                   #include <sys/stat.h>
                   #include <dirent.h> ]])

AC_CHECK_DECLS([INADDR_LOOPBACK],
               [],
               [ AC_DEFINE([INADDR_LOOPBACK], [(uint32_t)0x7f000001]) ],
               [ AC_INCLUDES_DEFAULT
                 [ #include <netinet/in.h> ]])

AC_MSG_CHECKING([whether to include debugging symbols (for gdb)])
AC_ARG_WITH([debug-symbols],
            [ AS_HELP_STRING([--with-debug-symbols], [include debugging symbols (for gdb) @<:@default=no@:>@]) ],
            [ AS_IF([ test "x$with_debug_symbols" != "xno" ],
                    [ AC_MSG_RESULT([yes])
                      CFLAGS="${CFLAGS} -g" ],
                    [ AC_MSG_RESULT([no])
                      AC_CHECK_PROG([STRIP_CMD], [strip], [strip spamdyke], [])
                      CFLAGS="${CFLAGS} -O2"
                    ])
            ],
            [ AC_MSG_RESULT([no])
              AC_CHECK_PROG([STRIP_CMD], [strip], [strip spamdyke], [])
              CFLAGS="${CFLAGS} -O2"
            ])

AC_MSG_CHECKING([whether to include excessive debugging output])
AC_ARG_WITH([excessive-output],
            [ AS_HELP_STRING([--with-excessive-output], [include excessive debugging output (also includes debugging output) @<:@default=no@:>@]) ],
            [ AS_IF([ test "x$with_excessive_output" != "xno" ],
                    [ AC_MSG_RESULT([yes])
                      AC_DEFINE([WITH_EXCESSIVE_OUTPUT], [1])
                      with_debug_output="yes" ],
                    [ AC_MSG_RESULT([no]) ])
            ],
            [ AC_MSG_RESULT([no]) ])

AC_MSG_CHECKING([whether to include some debugging output])
AC_ARG_WITH([debug-output],
            [ AS_HELP_STRING([--with-debug-output], [include some debugging output @<:@default=yes@:>@]) ],
            [ AS_IF([ test "x$with_debug_output" != "xno" ],
                    [ AC_MSG_RESULT([yes]) ],
                    [ AC_MSG_RESULT([no])
                      AC_DEFINE([WITHOUT_DEBUG_OUTPUT], [1])
                    ])
            ],
            [ AC_MSG_RESULT([yes]) ])

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

AC_ARG_ENABLE([config-test], [AS_HELP_STRING([--enable-config-test], [enable configuration tests (increases code size) @<:@default=yes@:>@]) ], [], [ enable_config_test=yes ])
AC_MSG_CHECKING([whether to include configuration tests])
AS_IF([ test "x$enable_config_test" != "xno" ],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        AC_DEFINE([WITHOUT_CONFIG_TEST], [1]) ])

AC_ARG_ENABLE([tls], [AS_HELP_STRING([--enable-tls], [support TLS encryption @<:@default=check@:>@]) ], [], [ enable_tls=check ])
AS_IF([ test "x$enable_tls" != "xno" ],
      [
        AC_MSG_CHECKING([if openssl/ssl.h will include without additional include directories])
        AC_TRY_COMPILE([ #include <openssl/ssl.h> ],
                       [],
                       [],
                       [ AC_MSG_RESULT([no])                       
                         AC_MSG_NOTICE([Adding /usr/kerberos/include to the include file search path])
                         AC_MSG_CHECKING([if openssl/ssl.h will include correctly])
                         CFLAGS="${CFLAGS} -I/usr/kerberos/include"
                       ])
        AC_TRY_COMPILE([ #include <openssl/ssl.h> ],
                       [],
                       [
                         AC_MSG_RESULT([yes])
                         AC_SEARCH_LIBS([RSA_sign], [ssl crypto], [], [ AC_MSG_FAILURE([--enable-tls was given but OpenSSL was not found]) ])
                         AC_SEARCH_LIBS([SSL_library_init],
                                        [ssl crypto],
                                        [ LIBS="$LIBS -lssl"
                                          AC_DEFINE([HAVE_LIBSSL], [1])
                                          AC_MSG_CHECKING([for OpenSSL libraries (for TLS support)]) 
                                          AC_MSG_RESULT([yes])
                                        ],
                                        [ AS_IF([ test "x$enable_tls" = "xcheck" ],
                                                [ AC_MSG_CHECKING([for OpenSSL libraries (for TLS support)])
                                                  AC_MSG_RESULT([no, TLS disabled]) ],
                                                [ AC_MSG_FAILURE([--enable-tls was given but OpenSSL was not found])
                                                ])
                                        ])
                       ],
                       [
                         AC_MSG_RESULT([no])
                         AC_MSG_NOTICE([Unable to include openssl/ssl.h (required by OpenSSL), TLS support disabled])
                         enable_tls="no"
                       ])
      ],
      [ AC_MSG_NOTICE([OpenSSL check skipped, TLS support disabled]) ]
     )

AC_SEARCH_LIBS([inet_aton], [resolv], [], [ AC_MSG_FAILURE([unable to compile without inet_aton()]) ])
AC_SEARCH_LIBS([bind], [socket], [], [ AC_MSG_FAILURE([unable to compile without bind()]) ])
AC_SEARCH_LIBS([inet_ntoa], [nsl], [], [ AC_MSG_FAILURE([unable to compile without inet_ntoa()]) ])
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

# Checks for the flag to compile anonymous inner functions.
AC_MSG_CHECKING([whether anonymous inner functions are supported by default])
AC_TRY_COMPILE([],
               [ int (*bar)(int) = ({ int tmp_action(int foo) { foo++; return(0); } &tmp_action; }); (*bar)(0); ],
               [ AC_MSG_RESULT([yes]) ],
               [ AC_MSG_RESULT([no])
                 OLD_CFLAGS=$CFLAGS
                 CFLAGS="$OLD_CFLAGS -fnested-functions"
                 AC_MSG_CHECKING([whether anonymous inner functions are supported with -fnested-functions])
                 AC_TRY_COMPILE([],
                                [ int (*bar)(int) = ({ int tmp_action(int foo) { foo++; return(0); } &tmp_action; }); (*bar)(0); ],
                                [ AC_MSG_RESULT([yes]) ],
                                [ AC_MSG_RESULT([no])
                                  CFLAGS="$OLD_CFLAGS -ftrampolines"
                                  AC_MSG_CHECKING([whether anonymous inner functions are supported with -ftrampolines])
                                  AC_TRY_COMPILE([],
                                                 [ int (*bar)(int) = ({ int tmp_action(int foo) { foo++; return(0); } &tmp_action; }); (*bar)(0); ],
                                                 [ AC_MSG_RESULT([yes]) ],
                                                 [ AC_MSG_RESULT([no])
                                                   CFLAGS="$OLD_CFLAGS -Wp,-Wno-trampolines"
                                                   AC_MSG_CHECKING([whether anonymous inner functions are supported with -Wp,-Wno-trampolines])
                                                   AC_TRY_COMPILE([],
                                                                  [ int (*bar)(int) = ({ int tmp_action(int foo) { foo++; return(0); } &tmp_action; }); (*bar)(0); ],
                                                                  [ AC_MSG_RESULT([yes]) ],
                                                                  [ AC_MSG_RESULT([no])
                                                                    AC_MSG_FAILURE([Unable to compile without anonymous inner function support.])
                                                                  ])
                                                 ])
                                ])
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

AC_MSG_CHECKING([whether GCC diagnostic pragma directives are supported])
AC_TRY_COMPILE([ #pragma GCC diagnostic error "-Wformat" ],
               [ ],
               [ AC_MSG_RESULT([yes])
                 AC_DEFINE([USE_PRAGMA], [1]) ],
               [ AC_MSG_RESULT([no]) ])

AC_MSG_CHECKING([whether pid_t is an unsigned int or an unsigned long])
AC_TRY_COMPILE([ #include <stdio.h>
                 #include <unistd.h>
                 #ifdef USE_PRAGMA
                 #pragma GCC diagnostic error "-Wformat"
                 #endif ],
               [ printf("%u", getpid()); ],
               [ AC_MSG_RESULT([unsigned int])
                 AC_DEFINE([FORMAT_PID_T], ["%u"]) ],
               [ AC_MSG_RESULT([unsigned long])
                 AC_DEFINE([FORMAT_PID_T], ["%lu"]) ])

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

AC_MSG_CHECKING([whether time_t is an int or a long])
AC_TRY_COMPILE([ #include <stdio.h>
                 #include <time.h>
                 #ifdef USE_PRAGMA
                 #pragma GCC diagnostic error "-Wformat"
                 #endif ],
               [ printf("%d", time(NULL)); ],
               [ AC_MSG_RESULT([int])
                 AC_DEFINE([FORMAT_TIME_T], ["%d"]) ],
               [ AC_MSG_RESULT([long])
                 AC_DEFINE([FORMAT_TIME_T], ["%ld"]) ])

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

AC_MSG_CHECKING([whether socklen_t is available])
AC_TRY_COMPILE([ #include <sys/socket.h> ],
               [ socklen_t foo;
                 if ((foo = 0)) return(0); ],
               [ AC_MSG_RESULT([yes]) ],
               [ AC_MSG_RESULT([no])
                 AC_DEFINE([socklen_t], [uint32_t])
               ])

AC_MSG_CHECKING([whether RLIMIT_AS is available])
AC_TRY_COMPILE([ #include <sys/time.h>
                 #include <sys/resource.h> ],
               [ struct rlimit tmp;
                 getrlimit(RLIMIT_AS, &tmp);
                 return(0); ],
               [ AC_MSG_RESULT([yes])
                 AC_DEFINE([HAVE_RLIMIT_AS], [1]) ],
               [ AC_MSG_RESULT([no]) ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
