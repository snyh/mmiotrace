# 背景
移植某国产CPU架构(ISA为arm64)遇到一些问题，其中一个是user space
使用特定方式访问device memory时会导致当前CPU直接停止工作，整个kernel
都无法响应了。

具体反应在操作GPU显存时出现的问题。问题解决后，观察到的情况是
1. 使用stp访问显存(使用mmap)有一定概率导致挂掉kernel。(正常启动桌面的过程
会100%导致死机)
2. 使用str Xn会概率性导致signal bus。
3. 对显存的操作只有str Wn是安全的。

推测可能是pci host bridge与CPU之间传递64位数据时有问题。所以导致str Xn触发
signal bus，而stp(相当于一次执行两个64位的操作，但host bridge一次最多只支持
64位传输)就直接导致CPU无法工作了。

而生成stp指令的地方实在太多，排除prolog, epilog这类使用stp操作SP, LR的情况，
仅mesa，xorg等代码里都有五六十万条有风险的指令。
因此传统的print死磕很难有突破。我就是在print一周绝望后开始想办法进行精准定位的。

# 其他方式
在此之前也试过其他方式，首先是ftrace。但ftrace的问题是无法实时的获取内容，一般
如果只是用户太进程出现问题，那ftrace的ring buffer还是可以正常读取到，进而观察
到出现问题附近的代码。甚至kernel panic时也可以配置相关参数使ftrace ring buffer
全部dump出来，从而使用serial console的方式看到关键信息。
但这次的问题是直接CPU瞬间不工作了，因此只能在问题还未发生前的一刻打印出关键信息。

其次gdb里也有watch指令可以观察某个地址被读写的操作。但在实际使用中arm64下连drm
相关的内存都无法打印，且hardware breakpoint的数量也是有限的远远不够覆盖我们的需求。
另外找到有问题的地址就是目的，而无法方便的在gdb里跟踪所有的事件。


因此在尝试了各种其他方式后，决定试试mmiotrace这种方式。目前社区里能看到两个原理
类似的工具
1. x86的ftrace里有一个mmiotrace的tracer，这个是跟踪kernel态的io读写(但实际有遗漏)
2. libsegfault也是mmiotrace实现的原本，只是libsegfault实在太老了，在x86上都无法
正常工作了。因此为了在arm64下使用，基本得重写了。

# 原理
为了缩小讨论空间，这里的上下文仅以问题背景为主。
即
1. 设备内存指显存，通过PCIE的bus address space到CPU address space
2. user space使用mmap(2)将CPU address space转换到进程的virtual address space

内存访问并不像函数调用一样可以有多种方式进行跟踪，因为不论是kernel thread还是
user space thread在执行时都是一样的(特权指令等除外)，一条一条指令的执行下去。

不可能像跟踪函数一样对类似`mov x0, [x1]`这种下达跟踪指令，因为x1到底是物理内存
还是设备内存是不知道的，只有在执行到这里才能知晓。也不太可能对所有访问内存的
指令都下一个breakpoint然后去判断访问的地址是否是自己想观察的。这种方式理论上
可行，但速度完全无法接受。


[mmiotrace](https://github.com/snyh/mmiotrace/tree/master)的核心原理
为mprotect(2), sigaction(2), LD_PRELOAD

1. 首先使用LD_PRELOAD或其他方式替换进程的mmap(2), sigaction(2), signal(2)等函数。
   这步的目的是为了屏蔽进程代码的SIGSEGV和SIGTRAP信号，转由mmiotrace进行处理。
2. 在mmap时根据需要的条件选择是否截获，若截获则存储相关信息，并将prot参数修改
   为PROT\_NONE或PROT\_READ。mmiotrace的选择条件是fd > 1且offset > 0，主要是符合
   DRM的特征。drm-mm(7)
   因为去掉了PROT\_WRITE，因此当访问这块内存的时候就会触发SIGSEGV信号，从而让mmiotrace
   获得了执行权。这时候我们就已经能在目标io发生前进行信息打印等工作了。
3. 但我们必须处理SIGSEGV以便程序可以正常获取到数据。所以在SIGSEGV handler里必须再次
   使用mprotect(2)把这块内存恢复为PROT_WRITE。
4. 显存的访问一般是连续的，因此若直接调整为PROT_WRITE后放弃执行权，那么mmiotrace
   就无法再次捕获剩下的内存访问操作了。所以必须在离开SIGSEGV handler前在合适的
   地方设置breakpoint，以便能在进程代码正常获取到这1 byte的数据之后再次能够被监控。
   目前的实现是将访问这1 byte数据之后的一条指令设置为breakpoint，这样SIGSEGV handler
   立刻后立刻就会进入我们的SIGTRAP handler了。
5. 在SIGTRAP handler里清除掉breakpoint(避免无限breakpoint)
6. 在SIGTRAP handler里面使用mprotect(2)再次移除PROT_WRITE权限。

通过这6个步骤即可跟踪到任意内存操作的指令。

# 细节

## 如何获取异常时的指令地址和内容

必须使用sigaction配合SIGINFO来注册handler,
这样可以额外得到siginfo\_t info和sigcontext\_t uc这两个参数。
我们主要关注uc这个结构体。具体的文档请参考man手册以及源码。

1. 在SIGSEGV时候info->si\_addr能够得到对应被访问的内存地址。
   通过si\_addr可以去和之前mmap时的地址范围进行匹配从而知道是否是我们关系的地址区域。
   (一定只能是我们关心的区域，如果不是则只能让当前进程立刻退出。)
2. sigcontext\_t是不在man手册里记录的，因为属于kernel细节。可以参考getcontext(3)，但
   具体还是得看kernel和libc提供的头文件。
   里面有一个mcontext\_t结构，要完全理解这个结构体得先理解sigaction(2), sigreturn(2)以及
   kernel的context switch等了。
   简单来说mcontext\_t是kernel把user thread的context存储在了user thread的stack上，用来
   保存和恢复对应状态的。只要在signal handler里修改这个结构体的内容，当handler返回时
   kernel就会使用被“调整”的context来恢复进程的执行
3. 配合gdb的info types找到实际的头文件(直接翻/usr/include的话很容易迷失)确定mcontext
   的布局。从而获取指令地址，x86_64下是RIP，arm64下是PC。(后面统一用PC来指代)
4. 修改signal handler后期望执行的指令，也就是根据CPU spec调整PC从而隐藏
   breakpoint，mprotect等造成的影响。
   需要注意的是，每种架构下的行为都是不同的。x86_64在TRAP时PC指向的是下一条指令，而
   arm64在TRAP时PC指向的是当前指令。且具体情况要根据不同的异常类型参考CPU手册。
      

## 如何解析opcode

通过PC的地址我们可以得到
1. PC的值表明了指令的所在位置，通过这个位置是可以反过来推算出对应的函数以及其源码
   地址。
2. PC值的内存内容表明了具体的指令细节，通过这个指令我们可以进行有选择的进行输出不同
   信息。比如在遇到stp时则打印当前的backtrace。
   
mmiotrace里是通过capstone这个库来解析的，接口比较简单，主要是
1. cs\_open(CS\_ARCH\_X86, 0, &handler)来初始化一个handler。
2. cs\_disasm(handler, pc, MAX\_SIZE, 0, 1, &insn)来解析一条指令到insn。

使用capstone主要是为了解析出PC地址所在的指令长度s，从而在PC+s的地址设置breakpoint。
s在arm64等RSIC上都是固定长度的。因此是而已不依赖capstone的，但为了更好的输出指令
的汇编格式所以依旧使用了。

x86因为是边长指令所以必须借助capstone这类引擎进行解析。(libsegfault使用的是udis86)
另外因为变长指令的缘故在SIGTRAP时因为PC指向的是下一条指令，所以得想办法知道上一条
指令的长度s2，从而计算出PC-s2获取到被临时breakpoint的指令地址。(因为得有起始地址进行
指令还原）
大概有三种方式可以实现
1. 潜在的指令最大长度N是知道的，因此依次去尝试PC-[1,N]与之前记录下的breakpoints地址
   进行比对，若找到对应breakpoint则也得到了s2。(目前的实现)
2. 从PC开始向低地址搜索内容为BREAKPOINT的模式。
3. 传递PC-N给capstone进行解析。

## 如何设置breakpoint

设置breakpoint的方式很多文章都有介绍，x86_64下就是`0xcc(int 3)`这条指令。一般可以
使用_\_builtin_trap()。但mmiotrace是动态设置，所以稍微麻烦点，需要在替换对应地址的
内容为breakpoint的内容。而替换就是直接简单粗暴的使用memcpy。

但这里主要会遇到两个问题
1. 被下breakpoint的区域一般是.text区域，而这个区域是没有write权限的，因此是无法直接
   替换的。需要再次使用mprotect临时修改对应区域的权限。
2. 因为我们修改的地方往往就是在PC附近，这个地址内容大概率已经在CPU cache里面了，因此
   只是修改RAM还是不够的。在x86_64下是不需要处理的，但arm64下则必须显示的使用相关
   指令(`dc cvau; ic ivau`)使CPU cache进行更新。不过后来发现了有个
   \_\_builtin\_\_\_clear\_cache可以实现这个功能。


# 优化
目前的实现方式，每次命中一个byte都会触发
0. 一次SIGSEGV
1. 一次设置breakpoint，一次恢复breakpoint
2. 一次SIGTRAP
相当于两次switch，两次cacheline invalid

SIGSEGV属于核心原理不太可能优化掉，但breakpoint如果能替换为single step则能有
较多优化。目前有两个方向可以尝试
1. 改用ptrace的形式，使用PTRACE\_SINGLESTEP cmd
2. 使用mcontext的pstate(arm64下)，修改thread flags，并修改kernel不要做安全检查。
   (kernel里会在signal handler结束后检查对应stack上的内容是否合法)
