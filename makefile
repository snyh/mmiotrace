all: mmiotrace.so

LDFLAGS=-lcapstone -ldl

mmiotrace.so: mmiotrace.o
	gcc -shared -fPIC -o $@ $< ${LDFLAGS}

mmiotrace.o: mmiotrace.c
	gcc -c -Og -funwind-tables -I/usr/include/capstone -fpic -D_GNU_SOURCE -fPIC -shared -o $@ $<

mmiotrace_t.o: mmiotrace.c
	gcc -c -DTRACE_ALL_MMAP -g -rdynamic -fasynchronous-unwind-tables -funwind-tables -I/usr/include/capstone -fpic -D_GNU_SOURCE -fPIC -shared -o $@ $<

test: test1.c mmiotrace_t.o
	gcc -g -funwind-tables -no-pie $^ ${LDFLAGS}

clean:
	rm *.o a.out mmiotrace.so
