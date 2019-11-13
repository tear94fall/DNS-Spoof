dnspoof.o:
	gcc main.cpp -o main -lnet -lpcap -lpthread

clean:
	rm -rf ${TEST_FILE} main
