AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = mg44

mg44_CXXFLAGS = $(JSONC_CFLAGS) $(PTHREAD_CFLAGS)

if P44_BUILD_RPI

mg44_LDADD = $(PTHREAD_LIBS) -lmongoose -ljson-c -lcrypt

mg44_SOURCES = \
  main.c

else

mg44_LDADD = $(PTHREAD_LIBS) $(JSONC_CFLAGS)

mg44_SOURCES = \
  main.c \
  mongoose.c \
  mongoose.h

endif


