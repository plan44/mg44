AC_INIT([mg44], [0.1], [luz@plan44.ch], [mg44], [http://www.plan44.ch/])
AC_PREREQ([2.59])

AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CXX

AC_CONFIG_FILES([Makefile])

PKG_PROG_PKG_CONFIG

# PKG_CHECK_MODULES([JSONC], [json >= 0.10 ], [],
#     [
#         AC_MSG_ERROR([$JSON_PKG_ERRORS])
#     ])

# our own libs
#AC_CHECK_LIB(mongoose, mg_start, [], [AC_MSG_ERROR([Could not find libmongoose])])
#AC_CHECK_LIB(json-c, json_tokener_parse_ex, [], [AC_MSG_ERROR([Could not find libjson-c])])

# system libs
AC_CHECK_LIB(m, atan2, [], [AC_MSG_ERROR([Could not find math lib (m)])])
#AC_CHECK_LIB(crypto, SHA1_Init, [], [AC_MSG_ERROR([Could not find libcrypto])])
AC_CHECK_LIB(rt, clock_gettime, [], [AC_MSG_ERROR([Could not find rt lib for clock_gettime])])
AC_CHECK_LIB(dl, dlopen, [], [AC_MSG_ERROR([Could not find libdl])])
AC_CHECK_LIB(pthread, pthread_create, [], [AC_MSG_ERROR([Could not find libpthread])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h sys/resource.h], [], [AC_MSG_ERROR([required system header not found])])

AX_PTHREAD([], [ AC_MSG_ERROR([required pthread library not found]) ])

AC_OUTPUT
