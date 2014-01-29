AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = mg44

mg44_CXXFLAGS = $(JSONC_CFLAGS) $(PTHREAD_CFLAGS)

mg44_LDADD = $(JSONC_LIBS) $(PTHREAD_LIBS)

mg44_SOURCES = \
  mongoose.c \
  mongoose.h \
  main.c
