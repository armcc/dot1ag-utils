#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([dot1ag-utils], [1.0.1], [rvdp@sara.nl])
AM_INIT_AUTOMAKE([-Wall -Werror foreign no-dependencies subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# Checks for header files.
AC_CHECK_HEADERS([net/bpf.h net/if_ether.h net/ethernet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset select socket])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 src/Makefile])

AC_OUTPUT
