TOPDIR=..

LIBS+= -L${TOPDIR}/lib -Wl,--whole-archive,-lnetstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -pthread

TARGET="helloworld"
all:
	@echo "build helloworld"
	$(CC) -g -I../lib -o ${TARGET} main.c ${LIBS}


clean:
	rm -f *.o ${TARGET}

.PHONY: clean
