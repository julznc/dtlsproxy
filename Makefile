
PROGRAM  := dtlsproxy

LIBDTLS_DIR := ./tinydtls
LIBDTLS     := $(LIBDTLS_DIR)/libtinydtls.a

SOURCES := main.c proxy.c keystore.c
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))

INCLUDES := -I. -I$(LIBDTLS_DIR)
DEFINES  :=
CFLAGS   := $(INCLUDES) $(DEFINES) -Wall -O2
LFLAGS   := -L$(LIBDTLS_DIR) -ltinydtls -lev

all: $(LIBDTLS) $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(CXX) -o $@ $^ $(LFLAGS)

$(LIBDTLS):
	$(MAKE) -C $(LIBDTLS_DIR)

clean:
	rm -f $(PROGRAM) $(OBJECTS)

clean-libs:
	$(MAKE) -C $(LIBDTLS_DIR) clean
