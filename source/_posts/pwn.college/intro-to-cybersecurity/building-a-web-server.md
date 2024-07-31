---
title: building-a-web-server
date: 2024-07-25 19:46:04
category: pwn.college
tags:
---

# challenges
```X86ASM
.intel_syntax noprefix

.globl _start

.text

#============================================
# function
_start:
    call main
    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall

#============================================
# function
# [rbp-0x8]     listen_fd
# [rbp-0x10]    accept_fd
# [rbp-0x18]    fork_fd
main:
    push rbp
    mov rbp, rsp
    sub rsp, 0x18

    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 41     # SYS_socket
    syscall
    mov [rbp-0x8], rax
    
    mov rdi, [rbp-0x8]
    lea rsi, sockaddr_in
    mov rdx, 16
    mov rax, 49     # SYS_bind
    syscall

    mov rdi, [rbp-0x8]
    xor rsi, rsi
    mov rax, 50     # SYS_listen
    syscall

main_loop:
    mov rdi, [rbp-0x8]
    mov rsi, 0
    mov rdx, 0
    mov rax, 43     # SYS_accept
    syscall
    mov [rbp-0x10], rax

    mov rax, 57     # SYS_fork
    syscall
    mov [rbp-0x18], rax

    cmp rax, 0
    je main_subprocess

    mov rdi, [rbp-0x10]
    mov rax, 3      # SYS_close
    syscall

    jmp main_loop

main_subprocess:
    mov rdi, [rbp-0x8]
    mov rax, 3      # SYS_close
    syscall

    mov rdi, [rbp-0x10]
    call process

    leave
    ret

#============================================
# process(int fd)
# [rbp-0x8]         fd
# [rbp-0x408]       request
# [rbp-0x808]       file_path
# [rbp-0x810]       file_fd
# [rbp-0xc10]       file_data
# [rbp-0xc18]       file_data_len
# [rbp-0xc20]       data_addr
process:
    push rbp
    mov rbp, rsp
    sub rsp, 0xc20
    mov [rbp-0x8], rdi
    mov rdi, [rbp-0x8]
    lea rsi, [rbp-0x408]
    mov rdx, 1024
    mov rax, 0       # SYS_read
    syscall
    lea rdi, [rbp-0x408]
    lea rsi, [rbp-0x808]
    mov rdx, 1024
    call get_path
    mov al, byte ptr [rbp-0x408]
    cmp rax, 'G'
    je process_get
    xor rcx, rcx
    mov al, byte ptr [rbp-0x408]
    cmp rax, 'P'
    je process_post
    jmp process_error
process_get:
    lea rdi, [rbp-0x808]
    mov rsi, 0
    mov rax ,2       # SYS_open
    syscall
    mov [rbp-0x810], rax
    mov rdi, [rbp-0x810]
    lea rsi, [rbp-0xc10]
    mov rdx, 1024
    mov rax, 0       # SYS_read
    syscall
    mov [rbp-0xc18], rax
    mov rdi, [rbp-0x810]
    mov rax, 3      # SYS_close
    syscall
    mov rdi, [rbp-0x8]
    lea rsi, reponse
    mov rdx, 19
    mov rax, 1      # SYS_write
    syscall
    mov rdi, [rbp-0x8]
    lea rsi, [rbp-0xc10]
    mov rdx, [rbp-0xc18]
    mov rax, 1      # SYS_write
    syscall
process_post:
    lea rdx, [rbp-0x408]
    mov eax, dword ptr [rdx+rcx]
    inc rcx
    cmp rax, 0x0a0d0a0d
    jne process_post
    add rcx, 3
    lea rax, [rdx+rcx]
    mov [rbp-0xc20], rax
    lea rdi, [rbp-0x808]
    mov rsi, 65
    mov rdx, 0777
    mov rax, 2    # SYS_open
    syscall
    mov [rbp-0x810], rax
    mov rdi, [rbp-0xc20]
    call strlen
    mov rdx, rax
    mov rdi, [rbp-0x810]
    mov rsi, [rbp-0xc20]
    mov rax, 1      # SYS_write
    syscall
    mov [rbp-0xc18], rax
    mov rdi, [rbp-0x810]
    mov rax, 3      # SYS_close
    syscall
    mov rdi, [rbp-0x8]
    lea rsi, reponse
    mov rdx, 19
    mov rax, 1      # SYS_write
    syscall
process_error:
    leave
    ret

#============================================
# int get_path(char *read_request,char *open_path,size_t len)
get_path:
    push rbp
    mov rbp, rsp
    sub rsp, 0x28

    mov [rbp-0x8], rdi                  # read_request
    mov [rbp-0x10], rsi                 # open_path
    mov [rbp-0x18], rdx                 # len
    mov dword ptr [rbp-0x20], 0         # index_read
    mov dword ptr [rbp-0x28], 0         # index_open

    xor rax, rax

get_path_loop0:
    mov rcx, [rbp-0x20]
    cmp rcx, [rbp-0x18]
    jnb get_path_end
    mov rdx, [rbp-0x8]
    mov al, byte ptr [rdx+rcx]
    inc rcx
    mov [rbp-0x20], rcx
    cmp rax, 0x20
    jne get_path_loop0
get_path_loop1:
    mov rcx, [rbp-0x20]
    cmp rcx, [rbp-0x18]
    jnb get_path_end
    mov rdx, [rbp-0x8]
    mov al, byte ptr [rdx+rcx]
    inc rcx
    mov [rbp-0x20], rcx
    cmp rax, 0x20
    je get_path_end
    mov rcx, [rbp-0x28]
    mov rdx, [rbp-0x10]
    mov byte ptr [rdx+rcx], al
    inc rcx
    mov [rbp-0x28], rcx
    jmp get_path_loop1
get_path_end:    
    mov rdx, [rbp-0x10]
    add rdx, [rbp-0x28]
    mov byte ptr [rdx], 0
    mov rax, [rbp-0x20]
    leave
    ret

#============================================
# size_t strlen(char *src)
strlen:
    push rbp
    mov rbp, rsp
    xor rax, rax
    xor rdx, rdx
strlen_loop:
    mov dl, byte ptr [rdi+rax]
    inc rax
    cmp rdx, 0
    jne strlen_loop
    sub rax, 1
    leave
    ret

#============================================

.data
sockaddr_in:
	.short 2        # sin_family
	.short 0x5000   # sin_port
    .long 0         # sin_addr
    .rept 8
    .byte 0
    .endr

reponse:
    .string "HTTP/1.0 200 OK\r\n\r\n"

```
