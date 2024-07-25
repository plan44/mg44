AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = mg44

if P44_BUILD_RPI

PLATFORM_FLAGS =
mg44_LDADD = ${PTHREAD_LIBS} -ljson-c -lcrypt

else

PLATFORM_FLAGS = -D NO_SSL_DL=1 -D USE_IPV6=1
mg44_LDADD = ${PTHREAD_LIBS} ${JSONC_LIBS} -lcrypt -lssl

endif

if DEBUG
mg44_DEBUG = -D DEBUG=1
else
mg44_DEBUG =
endif

if WITH_APPLICATION_VERSION
mg44_VERSION = -DP44_APPLICATION_VERSION=\"$(APPLICATION_VERSION)\"
endif


mg44_CFLAGS = \
  -D MG_LEGACY_INTERFACE=1 \
  -I ${srcdir}/civetweb \
  ${mg44_DEBUG} \
  ${mg44_VERSION} \
  ${PLATFORM_FLAGS} \
  ${JSONC_CFLAGS} \
  ${PTHREAD_CFLAGS}

mg44_SOURCES = \
  main.c \
  civetweb/civetweb.c \
  civetweb/civetweb.h \
  civetweb/handle_form.inl \
  civetweb/md5.inl \
  civetweb/sha1.inl



