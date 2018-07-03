#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <strings.h>
#include <ucontext.h>
#include <capstone.h>
#include <execinfo.h>
#include <errno.h>

#define MAX_NUM_OF_MAPS 130
#define MAX_NUM_OF_BREAKS 130

#define TRACE_ALL_MMAP 1

// change to PROT_NONE if you want trace reading operations also.
#define TRACE_PROT PROT_READ

#if defined(__x86_64)
#define ADDR_TYPE uint64_t
uint8_t BREAKPOINT[1] = {0xcc};
#define MAX_INST_SIZE 16 /* FIXME: */
#define INST_PTR(context) (((ucontext_t*)context)->uc_mcontext.gregs[X86_REG_RIP])
#elif defined(__aarch64__)
#define ADDR_TYPE uint64_t
uint8_t BREAKPOINT[4] = {0, 0, 0x20, 0xd4};
#define MAX_INST_SIZE 4 /* FIXME: */
#define INST_PTR(context) (((ucontext_t*)context)->uc_mcontext.pc)
#else
#error unsupported architecture
#endif

#define page_align(address)  (char*)((unsigned long)(address) & -(getpagesize()))

int text_copy(void * target, void* source, size_t length);
static inline void clear_cache_line(void *beg);
static void dump_stack(void);


typedef struct {
  void *mmap_addr;
  void *addr;
  size_t size;
  unsigned long saddr;
  unsigned long eaddr;
  void *fault_addr;
} map_t;

typedef struct {
  bool is_used;
  uint8_t *inst_addr;
  uint8_t inst_part[sizeof(BREAKPOINT)];
  map_t *map;
} breakpoint_t;

typedef struct {
  csh disasm;
  FILE *log;

  map_t maps[MAX_NUM_OF_MAPS];
  size_t map_count;

  breakpoint_t breakpoints[MAX_NUM_OF_BREAKS];
} segfault_t;

typedef enum segfault_error_e {
  SEGFAULT_SUCCESS = 0,
  SEGFAULT_ADDR_NOT_FOUND,
  SEGFAULT_TOO_MANY_MAPS,
  SEGFAULT_TOO_MANY_BREAKS,
  SEGFAULT_MPROTECT_FAILD
} segfault_error_t;

typedef void (*sighandler_t)(int);

static sighandler_t (* o_signal)(int, sighandler_t);
static int(* o_sigaction)(int, const struct sigaction*, struct sigaction*);
static void* (* o_mmap)(void *addr,size_t len,	int prot, int flags,int fildes,	off_t off);
static int (* o_munmap)(void *addr, size_t len);
static void* libc_handle = NULL;


/*
 * static variables used for immediate value
 */
static segfault_t context;

/*
 * That's all folks in case of fatal error or unhandled instruction thus no
 * bad things happen.
 */
static void thats_all_folks(void)
{
  dump_stack();
  exit(-1);
}

static void dump_stack(void)
{
  void *array[10];
  size_t size;
  /* print traceback */
  size = backtrace(array, 10);
  backtrace_symbols_fd(array, size, 2);
}


/*
 * allocate a new map struct on the global pool (context)
 */
static 
segfault_error_t 
alloc_map(
          map_t **map
          )
{
  /* check if we have reach the end of the pool */
  if (MAX_NUM_OF_MAPS <= context.map_count) {
    return SEGFAULT_TOO_MANY_MAPS;
  }

  *map = &context.maps[context.map_count];
  context.map_count++;

  return SEGFAULT_SUCCESS;
}

/*
 * find if the addr is in one of the maps in the global pool 
 * if it is, the function return's the relevent map
 */
static 
segfault_error_t 
find_map(
         void *addr,
         map_t **map
         )
{
  unsigned long i = 0;
  segfault_error_t status = SEGFAULT_SUCCESS;

  /* we iterate over all the maps and see if the address is in one of them */
  for (; i < context.map_count; i++) {
    if ((context.maps[i].saddr <= (unsigned long)addr) &&
        (context.maps[i].eaddr >= (unsigned long)addr)) {
      /* we found the right map */
      *map = &context.maps[i];
      goto l_exit;
    }
  }
    
  /* the address is not in one of the maps */
  status = SEGFAULT_ADDR_NOT_FOUND;

 l_exit:
  return status;
}

/*
 * allocate a breakpoint struct on the global pool (context)
 */
static segfault_error_t alloc_breakpoint(breakpoint_t **breakpoint)
{
  unsigned long i = 0;
  segfault_error_t status = SEGFAULT_SUCCESS;

  for (i=0; i < MAX_NUM_OF_BREAKS; i++) {
    if (0 == context.breakpoints[i].is_used) {
      context.breakpoints[i].is_used = 1;
      *breakpoint = &context.breakpoints[i];
      goto l_exit;
    }
  }

  status =  SEGFAULT_TOO_MANY_BREAKS;

 l_exit:
  return status;
}

/*
 * delete a breakpoint struct from the global pool (context)
 */
static segfault_error_t del_breakpoint(breakpoint_t *breakpoint)
{
  breakpoint->is_used = 0;
  memset(breakpoint, 0, sizeof(*breakpoint));
    
  return SEGFAULT_SUCCESS;
}

static void del_map(void* addr)
{
  map_t maps[MAX_NUM_OF_MAPS];
  size_t map_count;

  for (int i=0; i < context.map_count; i++) {
    if (context.maps[i].addr == addr) {
      printf("unmap..... %p\n", addr);
      memset(context.maps+i, 0, sizeof(map_t));
    }
  }
}


/*
 * find if there is a breakpoint with a spsific addr
 */
static 
segfault_error_t find_breakpoint(void *addr, breakpoint_t **breakpoint)
{
  segfault_error_t status = SEGFAULT_SUCCESS;

  unsigned long i = 0;
  /* iterate over all the breakpoints */
  for (i=0; i < MAX_NUM_OF_BREAKS; i++) {
    if ((context.breakpoints[i].inst_addr == addr) &&
        (context.breakpoints[i].is_used == 1)) {
      /* we found the right breakpoint */
      *breakpoint = &context.breakpoints[i];
      goto l_exit;
    }
  }
  /* there is no breakpoint at that address */
  status = SEGFAULT_ADDR_NOT_FOUND;
 l_exit:
  return status;
}

static void protect(map_t *map)
{
  if (mprotect(map->addr, map->size, PROT_NONE) < 0) {
    fprintf(
			context.log,
			"protect mprotect(0x%08X|0x%08X) failed\n", 
            map->addr,
			map->size
            );
    //thats_all_folks();
  }
}

/*
 * Unprotect memory
 */
static void unprotect(map_t *map)
{
  if (mprotect(map->addr, map->size, PROT_READ | PROT_WRITE) < 0) {
    fprintf(
			context.log,
			"unprotect mprotect(0x%08X|0x%08X) failed\n", 
            map->addr,
			map->size
            );
    thats_all_folks();
  }
}


int munmap(void *addr, size_t len)
{
  del_map(addr);
  return o_munmap(addr, len);
}

void* mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
  map_t *map = NULL;
  segfault_error_t status = SEGFAULT_SUCCESS;

  /* add another map to the maping list */
  status = alloc_map(&map);
  if (SEGFAULT_SUCCESS != status) {
    thats_all_folks();
  }


  if (TRACE_ALL_MMAP||fildes != -1 && off > 0) {
    printf("intercepting mmap(0x%08X, 0x%08X, %d, %d, %d, 0x%08lX) ==\n",
           (uint64_t)addr, len, prot, flags, fildes, off);
    dump_stack();
  }
  map->size = len;
  map->addr = o_mmap(addr, len, TRACE_PROT,
                     flags, fildes, off);
  map->saddr = (unsigned long)map->addr;
  map->eaddr = (unsigned long)map->addr + map->size;

  if (fildes != -1 && off > 0) {
    printf(" ===> %p\n\n\n", map->saddr);
  }
  return map->addr;
}

/*
 * Replace the libc sigaction function
 */
int 
sigaction(
          int sn,
          const struct sigaction *act,
          struct sigaction *oldact
          )
{
  if (SIGSEGV == sn) {
    return 0;
  }
  if (SIGTRAP == sn) {
    return 0;
  }

  return o_sigaction(sn, act, oldact);
}

/*
 * Replace the libc signal function
 */
sighandler_t 
signal(
       int sn,
       sighandler_t sighandler
       )
{
  /* FIXME: check if we need to change this because of sigaction */
  if (sn == SIGSEGV) {
    /* return segfault_handler; */
    return NULL;
  }
  if (sn == SIGTRAP) {
    /* return segfault_handler; */
    return NULL;
  }

  /* in all other cases call the original libc signal() -function */
  return o_signal(sn, sighandler);
}



/* 
 * create a breakpoint at a wanted address and return the breakpoint struct
 */
static 
segfault_error_t 
set_breakpoint(
               void *addr,
               breakpoint_t **breakpoint
               )
{
  int result = 0;
  breakpoint_t *_breakpoint = NULL;
  segfault_error_t status = SEGFAULT_SUCCESS;

  /* check if there is already breakpoint there if there is something is wrong */
  if (find_breakpoint(addr, &_breakpoint) == SEGFAULT_SUCCESS) {
    /* something is defnitly worng */
    thats_all_folks();
  }

  /* get a new breakpoint struct */
  status = alloc_breakpoint(&_breakpoint);
  if (SEGFAULT_SUCCESS != status) {
    goto l_exit;
  }

  /* save the instraction address and content for later use (when removing the break) */
  _breakpoint->inst_addr = (uint8_t*)addr;
  memcpy(_breakpoint->inst_part, addr, sizeof(BREAKPOINT));

  /* FIXME: change the premisstions back to the orginal */
  result = mprotect(
                    (void*)(page_align(_breakpoint->inst_addr)),
                    getpagesize(),
                    PROT_READ | PROT_WRITE | PROT_EXEC
                    );
  if (result < 0) {
    status = SEGFAULT_MPROTECT_FAILD;
    fprintf(
			context.log,
			"set_breakpoint mprotect failed errno:%d\n",
            errno
            );
    goto l_exit;
  }


  /* set the breakpoint opcode */
  text_copy(_breakpoint->inst_addr, BREAKPOINT, sizeof(BREAKPOINT));
  *breakpoint = _breakpoint;

 l_exit:
  return status;
}

/* 
 * remove a breakpoint
 */
static 
segfault_error_t 
remove_breakpoint(
                  breakpoint_t *breakpoint
                  )
{
  text_copy(breakpoint->inst_addr, breakpoint->inst_part, sizeof(BREAKPOINT));
  return SEGFAULT_SUCCESS;
}


int text_copy( void * target,
               void * source,
               size_t      length)
{
  const long  page = sysconf(_SC_PAGESIZE);
  void       *start = (char *)target - ((long)target % page);
  size_t      bytes = length + (size_t)((long)target % page);

  /* Although length should not need to be a multiple of page size,
   * adjust it up if need be. */
  if (bytes % (size_t)page)
    bytes = bytes + (size_t)page - (bytes % (size_t)page);

  /* Disable write protect on target pages. */
  if (mprotect(start, bytes, PROT_READ | PROT_WRITE | PROT_EXEC))
    {
      printf("CAN't change mprotect\n");
      exit(-1);
      return errno;
    }

  memcpy((void *)target, (void *)source, length);
  clear_cache_line(target);

  /* Re-enable write protect on target pages. */
  if (mprotect(start, bytes, PROT_READ | PROT_EXEC))
    return errno;

  return 0;
}

/*
 * Process opcode which caused the segfault
 */
static int process_opcode(uint8_t* opcode, int64_t fault_address)
{
  unsigned int size = 0;
  static cs_insn* insn = 0;
  if (insn != 0) {
    if (insn->address == (uint64_t)opcode) {
      return 4;
    } else {
      cs_free(insn,  1);
    }
  }
  size = cs_disasm(context.disasm,
                   opcode, MAX_INST_SIZE,
                   (uint64_t)opcode,
                   1,
                   &insn);
  if (size != 1) {
    printf("CAN'T DISASM!!!!!!!:%d\n", size);
    return 0;
  }
 cached:
  size = insn->size;
  switch (insn->id) {
  case 324: //ARM64_INS_STP
  default:
    fprintf(context.log,"0x%0lx(%d):\t%s %s #0x%0lx\n",
            (int64_t)opcode,
            insn->id,
            insn->mnemonic, insn->op_str,
            fault_address
            );
    dump_stack();
    fprintf(context.log,"\n");
  }
  return size;
}


/* FIXME: can create starvetion? */
static 
void 
trap_handler(
             int sig,
             siginfo_t *info,
             void *signal_ucontext
             )
{
  breakpoint_t *breakpoint;
  uint8_t *addr = NULL;
  segfault_error_t status = SEGFAULT_SUCCESS;

  ucontext_t* uc = signal_ucontext;

  addr = (uint8_t*)(INST_PTR((ucontext_t*)(signal_ucontext)));

  /* find the correct breakpoint struct for the given address */
  status = find_breakpoint(addr, &breakpoint);
  if (SEGFAULT_SUCCESS != status) {
    printf("HHHH In trap_handler:%p\n", addr);
    exit(-1);
    goto l_exit;
  }

  /* remove the breakpoint */
  status = remove_breakpoint(breakpoint);
  if (SEGFAULT_SUCCESS != status) {
    thats_all_folks();
  }
    
  /* return the instruction pointer back to execute the instruction */
  INST_PTR(signal_ucontext) = (uint64_t)addr;
  protect(breakpoint->map);

  del_breakpoint(breakpoint);
 l_exit:
  return;
}

/*
 * All the segfault handling fun happen here
 */
static 
void 
segfault_handler(
                 int sig,
                 siginfo_t *info,
                 void *signal_ucontext
                 )
{
  int instruction_size = 0;
  uint8_t* opcode = NULL;
  int result = 0;
  void *fault_addr = NULL;
  ucontext_t *ucontext = NULL;
  map_t *map = NULL;
  breakpoint_t *breakpoint = NULL;
  segfault_error_t status = SEGFAULT_SUCCESS;

  if (NULL == signal_ucontext) {
    printf("There hasn't SIGNAL UCONTEXT");
    thats_all_folks();
  }

  /* get the signal frame from the ucontext */
  ucontext = (ucontext_t*)(signal_ucontext);
  fault_addr = info->si_addr;

  /* try to find the right map which cause the fault */
  status = find_map(fault_addr, &map);
  if (SEGFAULT_SUCCESS != status) {
    /* this means that the segfault wasn't our fault */
    printf("The address %p isn't mapped by we.\n", fault_addr);
    thats_all_folks();
  }

  /* opcode which caused the segfault is at eip */
  opcode = (uint8_t*)((uint64_t)(INST_PTR(ucontext)));

  /* process opcode */
  instruction_size = process_opcode(opcode, (int64_t)fault_addr);

  if (!instruction_size) {
    thats_all_folks();
  }

  /* set a breakpoint after the instruction */
  opcode += instruction_size;
  status = set_breakpoint(opcode, &breakpoint);
  if (SEGFAULT_SUCCESS != status) {
    thats_all_folks();
    goto l_exit;
  }

  /* set the current map and the fault_addr for later use */
  map->fault_addr = fault_addr;
  breakpoint->map = map;

  /* unprotect do the instruction
   * we will return the protection at SIGTAP hanlder */
  unprotect(map);

  /* return to the program context until SIGTRAP */
 l_exit:
  return;
}

/*
 * Initialize
 */
static
void 
segfault_init(void)
{
#define REPLACE(a, x, y)                            \
  if ( !(o_##x = dlsym(a , y)) ) {                  \
    fprintf(stderr, y"() not found in libc!\n");    \
    exit(-1);                                       \
  }

  struct sigaction fault_action;
  struct sigaction trap_action;

  /* initialize the action structs */
  memset(&fault_action, 0,sizeof(fault_action));
  memset(&trap_action, 0,sizeof(trap_action));

  if ( (libc_handle = dlopen("libc.so", RTLD_NOW)) == NULL)
    if ( (libc_handle = dlopen("libc.so.6", RTLD_NOW)) == NULL)
      fprintf(stderr, "error loading libc!");

  REPLACE(libc_handle, signal, "signal");
  REPLACE(libc_handle, sigaction, "sigaction");
  REPLACE(libc_handle, mmap, "mmap");
  REPLACE(libc_handle, munmap, "munmap");

  /* redirect action for these signals to our functions */
  fault_action.sa_flags = SA_SIGINFO;
  fault_action.sa_sigaction = segfault_handler;
  o_sigaction(SIGSEGV, &fault_action, NULL);

  trap_action.sa_flags = SA_SIGINFO;
  trap_action.sa_sigaction = trap_handler;
  o_sigaction(SIGTRAP, &trap_action, NULL);

  if (getenv("SF_LOGFILE")) {
    context.log = fopen(getenv("SF_LOGFILE"), "w");
    printf("open : %s\n", getenv("SF_LOGFILE"));
  } else {
    context.log = stderr;
  }

  /* init the disassmbler (udis86) */

#if defined(__x86_64)
  cs_open(CS_ARCH_X86, 0, &context.disasm);
  cs_option(context.disasm, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
#elif defined(__aarch64__)
  cs_open(CS_ARCH_ARM64, 0, &context.disasm);
  cs_option(context.disasm, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
#endif
#undef REPLACE
}

static void init(void) __attribute__((constructor));
static void init(void)
{
  context.log = stderr;
  segfault_init();
}

static void fini(void) __attribute__((destructor));
static void fini(void)
{
  if (context.log != stderr) {
    fclose(context.log);
  }
}


void
clear_cache_line(void *beg)
{
#if defined(__aarch64__)
  __asm__ __volatile__("dc cvau, %0" : : "r"(beg) : "memory");
  __asm__ __volatile__("ic ivau, %0" : : "r"(beg) : "memory");
#endif
}
