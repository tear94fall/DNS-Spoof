DIR=/usr/local
TEST_FILE=unittest
OBJS = main.o packet_handler.o
TARGET = main

main: packet_handler.o
	gcc main.cpp -o main packet_handler.o -lnet -lpcap -lpthread -std=c++11 -lstdc++

packet_handler.o: packet_handler.cpp
	gcc -c -o packet_handler.o packet_handler.cpp -std=c++11

file:
	g++ -o file_read file_read.cpp -std=c++11
	echo "1.1.1.1 www.naver.com" > info.txt
	./file_read www.google.com

test:
	g++ -o ${TEST_FILE} unittest.cpp -isystem -I${DIR}/include -L${DIR}/lib -pthread -lgtest -lpcap -std=c++11
	./${TEST_FILE}

clean:
	rm -f *.o $(TARGET) ${TEST_FILE}
