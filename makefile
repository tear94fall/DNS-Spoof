CC=g++
CPPFLAGS=-std=c++11 -lstdc++

TARGET=dnsspoof
OBJS=main.o packet_handler.o
SRC=$(OBJS:.o=.c)

LIBS=-lnet -lpcap -lgtest
PTHREAD=-lpthread

UNITTEST=unittest

all: ${TARGET}

${TARGET}: ${OBJS}
	${CC} -o ${TARGET} ${OBJS} ${PTHREAD} ${LIBS} ${CPPFLAGS}

file:
	${CC} -o file_read file_read.cpp ${CPPFLAGS}
	echo "1.1.1.1 www.naver.com" > info.txt
	./file_read www.google.com

test:
	${CC} -o ${UNITTEST} unittest.cpp  ${PTHREAD} ${LIBS} ${CPPFLAGS}
	./${UNITTEST}

clean:
	rm -f *.o $(TARGET) ${UNITTEST}

main.o : main.cpp
packet_handler.o : packet_handler.cpp