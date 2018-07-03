#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

char *addr = 0;

void myhandler(int no, siginfo_t* info, void*v) {
  return;
}

int main()
{
  addr = mmap(0, 4 * getpagesize(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = myhandler;
  sigaction(SIGUSR1, &sa, 0);
  addr[0] = 0xf4;
  printf("SHOULD BE  ?\n");
  printf("SHOULD BE  0xf4: 0x%x\n", addr[0]);

  printf("SHOULD BE  ?\n");
  addr[1] = 0x33;
  raise(SIGUSR1);
  printf("SHOULD BE  0x33: 0x%x\n", addr[1]);
  return 0;
}
