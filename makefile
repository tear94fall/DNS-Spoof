DIR=/usr/local
TEST_FILE=unittest

main:
	gcc main.cpp -o main -lnet -lpcap -lpthread -std=c++11 -lstdc++

test:
	g++ -o ${TEST_FILE} unittest.cpp -isystem -I${DIR}/include -L${DIR}/lib -pthread -lgtest -lpcap -std=c++11
	./${TEST_FILE}

clean:
	rm -rf ${TEST_FILE} main
