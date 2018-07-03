# mmiotrace
trace memory access operations for helping debug.

It's usual used tracing device memory accessing, use this tool you can trace where, when and how the 
device memory is been acceed.

The original idea from libsegfault, the mmiotrace only make it work properly under *x86_64* and *arm64*.

# output
run with `LD_PRELOAD=$(pwd)/mmiotrace.so ./your_binary`
```
intercepting mmap(0x00000000, 0x00004000, 3, 34, -1, 0x00000000) =>0x7f3bc6016000
./a.out(mmap+0x112)[0x401441]
./a.out[0x400d71]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf1)[0x7f3bc53d42b1]
./a.out[0x400c7a]

  (access instruction address)  (acess opcode)  (access virtual address)
CATCH: 0x400d7f(442):	movb $0xf4, (%rax) #0x7f3bc6016000 
-----------------(backtrace)----------------------------------
/lib/x86_64-linux-gnu/libc.so.6(+0x33030)[0x7f3bc53e7030]
./a.out[0x400d7f]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf1)[0x7f3bc53d42b1]
./a.out[0x400c7a]
```
```
$addr2line -e ./a.out -f 0x400e1b -p
$main at /home/snyh/codes/mmiotrace/test1.c:29
```
# build
1. depdend libcapstone to decode opcde (`apt install libcapstone-dev`)
2. make
3. make test && ./a.out

## tips
1. use -no-pie to compile your code so the backtrace can be used with _addr2line_
2. arm64 need compile with -funwind-tables otherwise glibc's backtrace wouldn't work properly.
3. modify the `mmap` and `process_opcode` to adjust your owner tool.
