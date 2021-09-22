#######################################################################
# TODO: assembly version of BLAKE3 depending on build target
BLAKE3=BLAKE3/c
BLAKE3_CFLAGS=-mavx512f -mavx512vl
BLAKE3_ASM=\
	$(BLAKE3)/blake3_sse2_x86-64_unix.S \
	$(BLAKE3)/blake3_sse41_x86-64_unix.S \
	$(BLAKE3)/blake3_avx2_x86-64_unix.S \
	$(BLAKE3)/blake3_avx512_x86-64_unix.S

#CFLAGS+=$(BLAKE3_CFLAGS)

LDFLAGS+=-Wl,-R -Wl,.

# For strdup on Linux
CFLAGS+=-D_XOPEN_SOURCE=500
# For getline on Linux
CFLAGS+=-D_POSIX_C_SOURCE=200809L

# Debugging
CFLAGS+=-g -ggdb3 -fstack-protector-all

#######################################################################

# Our very *bliep* set of options to make sure that these things can't cause any issues
CFLAGS += -ansi -pedantic -std=c99
CFLAGS += -W -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Waggregate-return
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls
CFLAGS += -Wnested-externs -Winline -Wbad-function-cast
CFLAGS += -fshort-enums -fstrict-aliasing -fno-common
CFLAGS += -Wno-packed -Wpadded -Wswitch-default -Wno-variadic-macros
CFLAGS += -Wformat=2 -Wformat-security -Wmissing-format-attribute
CFLAGS += -D_REENTRANT -D_THREAD_SAFE -fPIC
CFLAGS += -pipe
CFLAGS += -Wunused -Winit-self -Wextra -Wno-long-long -Wmissing-include-dirs
CFLAGS += -Wconversion

#######################################################################


# Default Target
all: libhashedrpz.so hasher hashedrpz_test

libblake3.so: $(BLAKE3)/blake3.c $(BLAKE3)/blake3_dispatch.c $(BLAKE3)/blake3_portable.c $(BLAKE3_ASM)
	@$(CC) -shared $(CFLAGS) $(EXTRAFLAGS) $^ -o $@ $(LDFLAGS)

libhashedrpz.so: hashedrpz.c base32hex_lc.c libblake3.so
	@$(CC) -shared $(CFLAGS) $(EXTRAFLAGS) $^ -o $@ $(LDFLAGS)

hasher: hasher.c libhashedrpz.so
	@$(CC) $(CFLAGS) $(EXTRAFLAGS) $^ -o $@ $(LDFLAGS)

hashedrpz_test: hashedrpz_test.c libhashedrpz.so
	@$(CC) $(CFLAGS) $(EXTRAFLAGS) $^ -o $@ $(LDFLAGS)

test: hashedrpz_test
	./hashedrpz_test -v

clean:
	@rm -rf libblake3.so libhashedrpz.so hasher hashedrpz_test *.dSYM || true 2>/dev/null

.PHONY: all clean test

