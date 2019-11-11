CC=g++
CPPFLAGS= -std=c++11

MAINFILE=main.cpp
OBJS1=main.o
TARGETS=main

CFLAGS=``
BUILDLIBS=``
BUILDAGENTLIBS=``

DLFLAGS=-fPIC -shared

all: $(TARGETS)

main: $(OBJS1)
	$(CC) -o $(TARGETS) $(MAINFILE) -lpcap

clean:
	rm -rf $(OBJS1) $(TARGETS)