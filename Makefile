CC=gcc
CPP=g++
CFLAGS=-I.
CPPFLAGS=-I.
DEPS =
OBJ = pcapparser.o http2ng.o http2parser.o http2fileextractor.o nghttp2_hd_huffman_data.o
LIBS=-lpcap -lz

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS+=-DDEBUG
    CFLAGS+=-g
    CPPFLAGS+=-g
	CPPFLAGS+=-DDEBUG
endif

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.cc $(DEPS)
	$(CPP) -std=c++11 -c -o $@ $< $(CFLAGS)

http2fileextractor: $(OBJ)
	$(CPP) -o $@ $^ $(CFLAGS) $(LIBS)
	
.PHONY: clean

clean:
	rm -rf *.o http2fileextractor output/
