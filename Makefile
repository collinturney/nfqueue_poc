TARGET=nfqueue

all:
	g++ -g -c nfqueue.cpp -std=c++11
	g++ -g -lnetfilter_queue -ltins -std=c++11 -o ${TARGET} nfqueue.o

clean:
	rm -f ${TARGET} *.o
