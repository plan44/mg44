AC_INIT([mg44], [3.0], [luz@plan44.ch], [mg44], [http://www.plan44.ch/])
AC_PREREQ([2.59])

AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CXX

AC_CONFIG_FILES([Makefile])

##### OPTIONS

AC_ARG_ENABLE(
  [debug],
  [AC_HELP_STRING([--enable-debug], [Debug build with extra debugging code])]
)
AM_CONDITIONAL([DEBUG], [test "x$enable_debug" = xyes])


AC_ARG_ENABLE(
  [p44buildrpi],
  [AC_HELP_STRING([--enable-p44buildrpi], [legacy plan44 build for Raspian RPi])]
)
AM_CONDITIONAL([P44_BUILD_RPI], [test "x$enable_p44buildow" = xyes])

PKG_PROG_PKG_CONFIG


AM_COND_IF([P44_BUILD_RPI], [], [
  # can check modules only if not P44_BUILD_RPI
  PKG_CHECK_MODULES([JSONC], [json-c >= 0.10 ], [], [
        AC_MSG_ERROR([$JSON_PKG_ERRORS])
  ])
])


AC_CHECK_LIB(m, atan2, [], [AC_MSG_ERROR([Could not find math lib (m) with atan2])])
AC_CHECK_LIB(rt, clock_gettime, [], [AC_MSG_ERROR([Could not find rt lib with clock_gettime])])
AC_CHECK_LIB(dl, dlopen, [], [AC_MSG_ERROR([Could not find libdl with dlopen])])
AC_CHECK_LIB(pthread, pthread_create, [], [AC_MSG_ERROR([Could not find libpthread with pthread_create])])

AM_COND_IF([P44_BUILD_RPI], [], [
  # can check libs only if not P44_BUILD_RPI
  AC_CHECK_LIB(json-c, json_tokener_get_error, [], [AC_MSG_ERROR([Could not find JSON-C / libjson0 with json_tokener_get_error supported (>=0.10)])])
  AC_CHECK_LIB(ssl, TLSv1_client_method, [], [AC_MSG_ERROR([Could not find libssl with TLSv1_client_method])])
  AC_CHECK_LIB(crypto, SHA1_Init, [], [AC_MSG_ERROR([Could not find libcrypto with SHA1_Init])])
])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h sys/resource.h], [], [AC_MSG_ERROR([required system header not found])])

AX_PTHREAD([], [ AC_MSG_ERROR([required pthread library not found]) ])

AC_OUTPUT
