---
title: glibc版本对比
date: 2024-06-04 12:56:10
category: pwn
tags: heap
---

# glibc
> glibc源码下载地址：https://ftp.gnu.org/pub/gnu/glibc/
> 清华源git仓库 `git clone https://mirrors.tuna.tsinghua.edu.cn/git/glibc.git`

源码需要下载对应版本(从2.23到2.39)的glibc压缩文件，然后解压
git仓库可以使用 `git checkout glibc-2.xx` 切换到对应版本

# glibc版本对应关系
|glibc|Ubuntu|
|-----|------|
|2.39 |24.04 |
|2.35 |22.04 |
|2.31 |20.04 |
|2.27 |18.04 |
|2.23 |16.04 |

# glibc不同版本的malloc.c
介绍一下对做题影响比较大的malloc.c的修改（可能不太全，欢迎补充）
从glibc-2.23开始，更老的版本应该没多少人用了

## glibc-2.23
1. 没有tcache
2. fastbin没有fd指针保护(PROTECT_PTR)，没有指针对齐检测，所以可以错位(_malloc_hook-0x23)弄出0x7f的size，从而绕过fastbin分配对size的检测，将堆分配到malloc_hook附近

## glibc-2.26
1. 开始加入tcache，但没有tcache key检测double free，不会检测next指针指向堆块的大小，比起攻击fastbin还省了错位弄出0x7f这一步，可以直接指向_malloc_hook
2. 检测是否能够申请tcache堆块是根据next指针的值不为NULL来判断的，而不是通过对应tcache的count
3. unlink加了一个当前size和下一个chunk的prev_size是否相等的检测，之前只有fd与bk双向链表完整性检测(largebin还有fd_nextsize与bk_nextsize双向链表的完整性检测)

## glibc-2.29
1. unlink从宏变成一个名为unlink_chunk的函数了
2. 后向合并(和低地址chunk合并)的unlink前加了prev_size与前一个chunk的size是否相同的检测，不过感觉和unlink中第一个检测重复了
3. 这个版本在tcache_entry结构体中加了一个tcache key，用于检测doubel free
4. _int_malloc()函数在处理unsortedbin时加了一堆检测
```c
size = chunksize (victim);
mchunkptr next = chunk_at_offset (victim, size);

if (__glibc_unlikely (size <= 2 * SIZE_SZ)
    || __glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): invalid size (unsorted)");
if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
    || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
  malloc_printerr ("malloc(): invalid next size (unsorted)");
if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
  malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
if (__glibc_unlikely (bck->fd != victim)
    || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
  malloc_printerr ("malloc(): unsorted double linked list corrupted");
if (__glibc_unlikely (prev_inuse (next)))
  malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```
5. 使用top chunk时会先检查top chunk是否过大，house of force方法失效
```c
victim = av->top;
size = chunksize (victim);

if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```

## glibc-2.30
1. tcache的tcache_perthread_struct的count由char变成uint16_t
2. 由检测tcache的next指针是否为null来判断是否有剩余堆块改为判断count是否大于0
3. _int_malloc()在处理unsortbin需要放入一个largebin范围的chunk时，并且该大小范围largebin不为空，且不小于该链表中所有chunk时，会检测插入位置前后的fd_nextsize和bk_nextsize双向链表

## glibc-2.32
1. 这个版本加了堆指针内存对齐检测(aligned_OK)，指针最后一位必须为0，而不能是8或其他数字
2. 同时也加了PROTECT_PTR保护tcache的next指针与fastbin的fd指针

## glibc-2.34
1. 取消hook机制，__malloc_hook、__free_hook等符号仍然存在，但是没有用了
2. tcache key的值修改了，原来是tcache指针的值，现在由tcache_key_initialize函数初始化一个随机值


