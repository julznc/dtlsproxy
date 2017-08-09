
PROGRAM  := dtlsproxy

SOURCES := main.c
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(CXX) -o $@ $^
