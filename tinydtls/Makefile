
LIB := libtinydtls.a

SOURCES := dtls.c crypto.c ccm.c hmac.c netq.c peer.c \
			dtls_time.c session.c dtls_debug.c \
			aes/rijndael.c ecc/ecc.c sha2/sha2.c
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))

DEFINES  := -DNDEBUG -DDTLSv12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE
CFLAGS   := -I. $(DEFINES) -Wall -pedantic -std=c99 -g -O2

RANLIB  := ranlib
ARFLAGS := cr

.PHONY: all clean

.SUFFIXES: .c .o

all:	$(LIB)

$(LIB):	$(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

clean:
	rm -f $(LIB) $(OBJECTS)
