CC=g++
CPPFLAGS=-std=c++11 -lstdc++

TARGET=dnsspoof
OBJS=main.o packet_handler.o set_attack_info.o
SRC=$(OBJS:.o=.c)

LIBS=-lnet -lpcap -lgtest
PTHREAD=-lpthread

test=test
UNITTEST=unittest
OBJS2=unittest.o packet_handler.o set_attack_info.o

${TARGET}: ${OBJS}
	${CC} -o ${TARGET} ${OBJS} ${PTHREAD} ${LIBS} ${CPPFLAGS}

${test}: ${OBJS2}
	${CC} -o ${UNITTEST} ${OBJS2} ${PTHREAD} ${LIBS} ${CPPFLAGS}
	./${UNITTEST}

clean:
	rm -f *.o $(TARGET) ${UNITTEST}