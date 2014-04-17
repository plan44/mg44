AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = mg44

mg44_CXXFLAGS = $(JSONC_CFLAGS) $(PTHREAD_CFLAGS)

mg44_LDADD = $(PTHREAD_LIBS) -lmongoose -ljson-c -lcrypt

mg44_SOURCES = \
  main.c
