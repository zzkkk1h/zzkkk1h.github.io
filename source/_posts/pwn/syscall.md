---
title: syscall
date: 2024-05-12 20:03:05
---

# int 80h与syscall
`syscall`和`int 80h`是中断指令,Linux通过对这两个指令的封装为开发者们提供的一种用户态切换至内核态的方法,也就是系统调用

## int 0x80 传统方法
### 概述
“int 0x80”是一种传统的中断指令，用于向处理器发出 0x80 号中断，从而将控制权传递给内核。这种方法自早期 x86 处理器时代以来一直被广泛用于调用系统调用。

### 优点
广泛支持： “int 0x80”在较旧的 Linux 内核和处理器上得到广泛支持。
简便性： 使用“int 0x80”调用系统调用相对简单，只需要几行汇编代码。

### 缺点
不推荐使用： 对于 64 位 x86 架构，不推荐使用“int 0x80”。
性能较差： 与“syscall”相比，“int 0x80”的性能较差，因为它需要额外的中断处理开销。

## syscall 现代方法
### 概述
“syscall”是一种从 Linux 内核 2.4 开始引入的现代系统调用机制。它使用特殊寄存器和指令（例如，eax、rax）来调用系统调用，无需中断。

### 优点
高性能： “syscall”比“int 0x80”提供了更高的性能，因为它消除了中断处理开销。
更安全： “syscall”更安全，因为它防止了由于中断处理中的错误而导致内核崩溃。
跨架构支持： “syscall”跨不同的 x86 架构（包括 32 位和 64 位）提供一致的接口。

### 缺点
依赖性： “syscall”需要较新的 Linux 内核和处理器才能正常工作。
复杂性： 使用“syscall”调用系统调用比使用“int 0x80”稍显复杂，需要了解特殊的寄存器和指令。

## 推荐选择
对于 32 位 Linux 代码，在大多数情况下，“syscall”是调用系统调用的首选方法。它提供了更高的性能、安全性以及跨架构支持。但是，如果你使用的是较旧的 Linux 内核或处理器，你可能需要使用“int 0x80”作为后备选项。
对于 64 位 Linux 代码，只能使用“syscall”，因为“int 0x80”不受支持。

# 调用约定
## int 80h
以`eax`传递系统调用号
参数传递顺序为`ebx`,`ecx`,`edx`,`esi`,`edi`

## syscall
以`rax`传递系统调用号
参数传递顺序为`rdi`,`rsi`,`rdx`,`r10`,`r8`,`r9`

# 系统调用号
## int 80h系统调用号
| 系统调用               | 调用号 | 系统调用               | 调用号              |
| ---------------------- | ------ | ---------------------- | ------------------- |
| exit                   | 1      | fork                   | 2                   |
| read                   | 3      | write                  | 4                   |
| open                   | 5      | close                  | 6                   |
| waitpid                | 7      | creat                  | 8                   |
| link                   | 9      | unlink                 | 10                  |
| execve                 | 11     | chdir                  | 12                  |
| time                   | 13     | mknod                  | 14                  |
| chmod                  | 15     | lchown                 | 16                  |
| break                  | 17     | oldstat                | 18                  |
| lseek                  | 19     | getpid                 | 20                  |
| mount                  | 21     | umount                 | 22                  |
| setuid                 | 23     | getuid                 | 24                  |
| stime                  | 25     | ptrace                 | 26                  |
| alarm                  | 27     | oldfstat               | 28                  |
| pause                  | 29     | utime                  | 30                  |
| stty                   | 31     | gtty                   | 32                  |
| access                 | 33     | nice                   | 34                  |
| ftime                  | 35     | sync                   | 36                  |
| kill                   | 37     | rename                 | 38                  |
| mkdir                  | 39     | rmdir                  | 40                  |
| dup                    | 41     | pipe                   | 42                  |
| times                  | 43     | prof                   | 44                  |
| brk                    | 45     | setgid                 | 46                  |
| getgid                 | 47     | signal                 | 48                  |
| geteuid                | 49     | getegid                | 50                  |
| acct                   | 51     | umount2                | 52                  |
| lock                   | 53     | ioctl                  | 54                  |
| fcntl                  | 55     | mpx                    | 56                  |
| setpgid                | 57     | ulimit                 | 58                  |
| oldolduname            | 59     | umask                  | 60                  |
| chroot                 | 61     | ustat                  | 62                  |
| dup2                   | 63     | getppid                | 64                  |
| getpgrp                | 65     | setsid                 | 66                  |
| sigaction              | 67     | sgetmask               | 68                  |
| ssetmask               | 69     | setreuid               | 70                  |
| setregid               | 71     | sigsuspend             | 72                  |
| sigpending             | 73     | sethostname            | 74                  |
| setrlimit              | 75     | getrlimit              | 76                  |
| getrusage              | 77     | gettimeofday           | 78                  |
| settimeofday           | 79     | getgroups              | 80                  |
| setgroups              | 81     | select                 | 82                  |
| symlink                | 83     | oldlstat               | 84                  |
| readlink               | 85     | uselib                 | 86                  |
| swapon                 | 87     | reboot                 | 88                  |
| readdir                | 89     | mmap                   | 90                  |
| munmap                 | 91     | truncate               | 92                  |
| ftruncate              | 93     | fchmod                 | 94                  |
| fchown                 | 95     | getpriority            | 96                  |
| setpriority            | 97     | profil                 | 98                  |
| statfs                 | 99     | fstatfs                | 100                 |
| ioperm                 | 101    | socketcall             | 102                 |
| syslog                 | 103    | setitimer              | 104                 |
| getitimer              | 105    | stat                   | 106                 |
| lstat                  | 107    | fstat                  | 108                 |
| olduname               | 109    | iopl                   | 110                 |
| vhangup                | 111    | idle                   | 112                 |
| vm86old                | 113    | wait4                  | 114                 |
| swapoff                | 115    | sysinfo                | 116                 |
| ipc                    | 117    | fsync                  | 118                 |
| sigreturn              | 119    | clone                  | 120                 |
| setdomainname          | 121    | uname                  | 122                 |
| modify_ldt             | 123    | adjtimex               | 124                 |
| mprotect               | 125    | sigprocmask            | 126                 |
| create_module          | 127    | init_module            | 128                 |
| delete_module          | 129    | get_kernel_syms        | 130                 |
| quotactl               | 131    | getpgid                | 132                 |
| fchdir                 | 133    | bdflush                | 134                 |
| sysfs                  | 135    | personality            | 136                 |
| afs_syscall            | 137    | setfsuid               | 138                 |
| setfsgid               | 139    | _llseek                | 140                 |
| getdents               | 141    | _newselect             | 142                 |
| flock                  | 143    | msync                  | 144                 |
| readv                  | 145    | writev                 | 146                 |
| getsid                 | 147    | fdatasync              | 148                 |
| _sysctl                | 149    | mlock                  | 150                 |
| munlock                | 151    | mlockall               | 152                 |
| munlockall             | 153    | sched_setparam         | 154                 |
| sched_getparam         | 155    | sched_setscheduler     | 156                 |
| sched_getscheduler     | 157    | sched_yield            | 158                 |
| sched_get_priority_max | 159    | sched_get_priority_min | 160                 |
| sched_rr_get_interval  | 161    | nanosleep              | 162                 |
| mremap                 | 163    | setresuid              | 164                 |
| getresuid              | 165    | vm86                   | 166                 |
| query_module           | 167    | poll                   | 168                 |
| nfsservctl             | 169    | setresgid              | 170                 |
| getresgid              | 171    | prctl                  | 172                 |
| rt_sigreturn           | 173    | rt_sigaction           | 174                 |
| rt_sigprocmask         | 175    | rt_sigpending          | 176                 |
| rt_sigtimedwait        | 177    | rt_sigqueueinfo        | 178                 |
| rt_sigsuspend          | 179    | pread64                | 180                 |
| pwrite64               | 181    | chown                  | 182                 |
| getcwd                 | 183    | capget                 | 184                 |
| capset                 | 185    | sigaltstack            | 186                 |
| sendfile               | 187    | getpmsg                | 188                 |
| putpmsg                | 189    | vfork                  | 190                 |
| ugetrlimit             | 191    | mmap2                  | 192                 |
| truncate64             | 193    | ftruncate64            | 194                 |
| stat64                 | 195    | lstat64                | 196                 |
| fstat64                | 197    | lchown32               | 198                 |
| getuid32               | 199    | getgid32               | 200                 |
| geteuid32              | 201    | getegid32              | 202                 |
| setreuid32             | 203    | setregid32             | 204                 |
| getgroups32            | 205    | setgroups32            | 206                 |
| fchown32               | 207    | setresuid32            | 208                 |
| getresuid32            | 209    | setresgid32            | 210                 |
| getresgid32            | 211    | chown32                | 212                 |
| setuid32               | 213    | setgid32               | 214                 |
| setfsuid32             | 215    | setfsgid32             | 216                 |
| pivot_root             | 217    | mincore                | 218                 |
| madvise                | 219    | madvise1               | 219                 |
| getdents64             | 220    | ⏫delete when C         | lib stub is removed |
| fcntl64                | 221    | gettid                 | 224                 |
| readahead              | 225    | setxattr               | 226                 |
| lsetxattr              | 227    | fsetxattr              | 228                 |
| getxattr               | 229    | lgetxattr              | 230                 |
| fgetxattr              | 231    | listxattr              | 232                 |
| llistxattr             | 233    | flistxattr             | 234                 |
| removexattr            | 235    | lremovexattr           | 236                 |
| fremovexattr           | 237    | tkill                  | 238                 |
| sendfile64             | 239    | futex                  | 240                 |
| sched_setaffinity      | 241    | sched_getaffinity      | 242                 |
| set_thread_area        | 243    | get_thread_area        | 244                 |
| io_setup               | 245    | io_destroy             | 246                 |
| io_getevents           | 247    | io_submit              | 248                 |
| io_cancel              | 249    | fadvise64              | 250                 |
|                        |        | exit_group             | 252                 |
| lookup_dcookie         | 253    | epoll_create           | 254                 |
| epoll_ctl              | 255    | epoll_wait             | 256                 |
| remap_file_pages       | 257    | set_tid_address        | 258                 |
| timer_create           | 259    | timer_settime          | 260                 |
| timer_gettime          | 261    | timer_getoverrun       | 262                 |
| timer_delete           | 263    | clock_settime          | 264                 |
| clock_gettime          | 265    | clock_getres           | 266                 |
| clock_nanosleep        | 267    | statfs64               | 268                 |
| fstatfs64              | 269    | tgkill                 | 270                 |
| utimes                 | 271    | fadvise64_64           | 272                 |
| vserver                | 273    | mbind                  | 274                 |
| get_mempolicy          | 275    | set_mempolicy          | 276                 |
| mq_open                | 277    | mq_unlink              | 278                 |
| mq_timedsend           | 279    | mq_timedreceive        | 280                 |
| mq_notify              | 281    | mq_getsetattr          | 282                 |
| kexec_load             | 283    | waitid                 | 284                 |
| sys_setaltroot         | 285    | add_key                | 286                 |
| request_key            | 287    | keyctl                 | 288                 |
| ioprio_set             | 289    | ioprio_get             | 290                 |
| inotify_init           | 291    | inotify_add_watch      | 292                 |
| inotify_rm_watch       | 293    | migrate_pages          | 294                 |
| openat                 | 295    | mkdirat                | 296                 |
| mknodat                | 297    | fchownat               | 298                 |
| futimesat              | 299    | fstatat64              | 300                 |
| unlinkat               | 301    | renameat               | 302                 |
| linkat                 | 303    | symlinkat              | 304                 |
| readlinkat             | 305    | fchmodat               | 306                 |
| faccessat              | 307    | pselect6               | 308                 |
| ppoll                  | 309    | unshare                | 310                 |
| set_robust_list        | 311    | get_robust_list        | 312                 |
| splice                 | 313    | sync_file_range        | 314                 |
| tee                    | 315    | vmsplice               | 316                 |
| move_pages             | 317    | getcpu                 | 318                 |
| epoll_pwait            | 319    | utimensat              | 320                 |
| signalfd               | 321    | timerfd_create         | 322                 |
| eventfd                | 323    | fallocate              | 324                 |
| timerfd_settime        | 325    | timerfd_gettime        | 326                 |
| signalfd4              | 327    | eventfd2               | 328                 |
| epoll_create1          | 329    | dup3                   | 330                 |
| pipe2                  | 331    | inotify_init1          | 332                 |
| preadv                 | 333    | pwritev                | 334                 |
| rt_tgsigqueueinfo      | 335    | perf_event_open        | 336                 |
| recvmmsg               | 337    | fanotify_init          | 338                 |
| fanotify_mark          | 339    | prlimit64              | 340                 |
| name_to_handle_at      | 341    | open_by_handle_at      | 342                 |
| clock_adjtime          | 343    | syncfs                 | 344                 |
| sendmmsg               | 345    | set_ns                 | 346                 |
| process_vm_readv       | 347    | process_vm_writev      | 348                 |

## syscall系统调用号
| 系统调用               | 调用号 | 系统调用               | 调用号 |
| ---------------------- | ------ | ---------------------- | ------ |
| read                   | 0      | write                  | 1      |
| open                   | 2      | close                  | 3      |
| stat                   | 4      | fstat                  | 5      |
| lstat                  | 6      | poll                   | 7      |
| lseek                  | 8      | mmap                   | 9      |
| mprotect               | 10     | munmap                 | 11     |
| brk                    | 12     | rt_sigaction           | 13     |
| rt_sigprocmask         | 14     | rt_sigreturn           | 15     |
| ioctl                  | 16     | pread64                | 17     |
| pwrite64               | 18     | readv                  | 19     |
| writev                 | 20     | access                 | 21     |
| pipe                   | 22     | select                 | 23     |
| sched_yield            | 24     | mremap                 | 25     |
| msync                  | 26     | mincore                | 27     |
| madvise                | 28     | shmget                 | 29     |
| shmat                  | 30     | shmctl                 | 31     |
| dup                    | 32     | dup2                   | 33     |
| pause                  | 34     | nanosleep              | 35     |
| getitimer              | 36     | alarm                  | 37     |
| setitimer              | 38     | getpid                 | 39     |
| sendfile               | 40     | socket                 | 41     |
| connect                | 42     | accept                 | 43     |
| sendto                 | 44     | recvfrom               | 45     |
| sendmsg                | 46     | recvmsg                | 47     |
| shutdown               | 48     | bind                   | 49     |
| listen                 | 50     | getsockname            | 51     |
| getpeername            | 52     | socketpair             | 53     |
| setsockopt             | 54     | getsockopt             | 55     |
| clone                  | 56     | fork                   | 57     |
| vfork                  | 58     | execve                 | 59     |
| exit                   | 60     | wait4                  | 61     |
| kill                   | 62     | uname                  | 63     |
| semget                 | 64     | semop                  | 65     |
| semctl                 | 66     | shmdt                  | 67     |
| msgget                 | 68     | msgsnd                 | 69     |
| msgrcv                 | 70     | msgctl                 | 71     |
| fcntl                  | 72     | flock                  | 73     |
| fsync                  | 74     | fdatasync              | 75     |
| truncate               | 76     | ftruncate              | 77     |
| getdents               | 78     | getcwd                 | 79     |
| chdir                  | 80     | fchdir                 | 81     |
| rename                 | 82     | mkdir                  | 83     |
| rmdir                  | 84     | creat                  | 85     |
| link                   | 86     | unlink                 | 87     |
| symlink                | 88     | readlink               | 89     |
| chmod                  | 90     | fchmod                 | 91     |
| chown                  | 92     | fchown                 | 93     |
| lchown                 | 94     | umask                  | 95     |
| gettimeofday           | 96     | getrlimit              | 97     |
| getrusage              | 98     | sysinfo                | 99     |
| times                  | 100    | ptrace                 | 101    |
| getuid                 | 102    | syslog                 | 103    |
| getgid                 | 104    | setuid                 | 105    |
| setgid                 | 106    | geteuid                | 107    |
| getegid                | 108    | setpgid                | 109    |
| getppid                | 110    | getpgrp                | 111    |
| setsid                 | 112    | setreuid               | 113    |
| setregid               | 114    | getgroups              | 115    |
| setgroups              | 116    | setresuid              | 117    |
| getresuid              | 118    | setresgid              | 119    |
| getresgid              | 120    | getpgid                | 121    |
| setfsuid               | 122    | setfsgid               | 123    |
| getsid                 | 124    | capget                 | 125    |
| capset                 | 126    | rt_sigpending          | 127    |
| rt_sigtimedwait        | 128    | rt_sigqueueinfo        | 129    |
| rt_sigsuspend          | 130    | sigaltstack            | 131    |
| utime                  | 132    | mknod                  | 133    |
| uselib                 | 13     | 4personality           | 135    |
| ustat                  | 136    | statfs                 | 137    |
| fstatfs                | 138    | sysfs                  | 139    |
| getpriority            | 140    | setpriority            | 141    |
| sched_setparam         | 142    | sched_getparam         | 143    |
| sched_setscheduler     | 144    | sched_getscheduler     | 145    |
| sched_get_priority_max | 146    | sched_get_priority_min | 147    |
| sched_rr_get_interval  | 148    | mlock                  | 149    |
| munlock                | 150    | mlockall               | 151    |
| munlockall             | 152    | vhangup                | 153    |
| modify_ldt             | 154    | pivot_root             | 155    |
| _sysctl                | 156    | prctl                  | 157    |
| arch_prctl             | 158    | adjtimex               | 159    |
| setrlimit              | 160    | chroot                 | 161    |
| sync                   | 162    | acct                   | 163    |
| settimeofday           | 164    | mount                  | 165    |
| umount2                | 166    | swapon                 | 167    |
| swapoff                | 168    | reboot                 | 169    |
| sethostname            | 170    | setdomainname          | 171    |
| iopl                   | 172    | ioperm                 | 173    |
| create_module          | 174    | init_module            | 175    |
| delete_module          | 176    | get_kernel_syms        | 177    |
| query_module           | 178    | quotactl               | 179    |
| nfsservctl             | 180    | getpmsg                | 181    |
| putpmsg                | 182    | afs_syscall            | 183    |
| tuxcall                | 184    | security               | 185    |
| gettid                 | 186    | readahead              | 187    |
| setxattr               | 188    | lsetxattr              | 189    |
| fsetxattr              | 190    | getxattr               | 191    |
| lgetxattr              | 192    | fgetxattr              | 193    |
| listxattr              | 194    | llistxattr             | 195    |
| flistxattr             | 196    | removexattr            | 197    |
| lremovexattr           | 198    | fremovexattr           | 199    |
| tkill                  | 200    | time                   | 201    |
| futex                  | 202    | sched_setaffinity      | 203    |
| sched_getaffinity      | 204    | set_thread_area        | 205    |
| io_setup               | 206    | io_destroy             | 207    |
| io_getevents           | 208    | io_submit              | 209    |
| io_cancel              | 210    | get_thread_area        | 211    |
| lookup_dcookie         | 212    | epoll_create           | 213    |
| epoll_ctl_old          | 214    | epoll_wait_old         | 215    |
| remap_file_pages       | 216    | getdents64             | 217    |
| set_tid_address        | 218    | restart_syscall        | 219    |
| semtimedop             | 220    | fadvise64              | 221    |
| timer_create           | 222    | timer_settime          | 223    |
| timer_gettime          | 224    | timer_getoverrun       | 225    |
| timer_delete           | 226    | clock_settime          | 227    |
| clock_gettime          | 228    | clock_getres           | 229    |
| clock_nanosleep        | 230    | exit_group             | 231    |
| epoll_wait             | 232    | epoll_ctl              | 233    |
| tgkill                 | 234    | utimes                 | 235    |
| vserver                | 236    | mbind                  | 237    |
| set_mempolicy          | 238    | get_mempolicy          | 239    |
| mq_open                | 240    | mq_unlink              | 241    |
| mq_timedsend           | 242    | mq_timedreceive        | 243    |
| mq_notify              | 244    | mq_getsetattr          | 245    |
| kexec_load             | 246    | waitid                 | 247    |
| add_key                | 248    | request_key            | 249    |
| keyctl                 | 250    | ioprio_set             | 251    |
| ioprio_get             | 252    | inotify_init           | 253    |
| inotify_add_watch      | 254    | inotify_rm_watch       | 255    |
| migrate_pages          | 256    | openat                 | 257    |
| mkdirat                | 258    | mknodat                | 259    |
| fchownat               | 260    | futimesat              | 261    |
| newfstatat             | 262    | unlinkat               | 263    |
| renameat               | 264    | linkat                 | 265    |
| symlinkat              | 266    | readlinkat             | 267    |
| fchmodat               | 268    | faccessat              | 269    |
| pselect6               | 270    | ppoll                  | 271    |
| unshare                | 272    | set_robust_list        | 273    |
| get_robust_list        | 274    | splice                 | 275    |
| tee                    | 276    | sync_file_range        | 277    |
| vmsplice               | 278    | move_pages             | 279    |
| utimensat              | 280    | epoll_pwait            | 281    |
| signalfd               | 282    | timerfd_create         | 283    |
| eventfd                | 284    | fallocate              | 285    |
| timerfd_settime        | 286    | timerfd_gettime        | 287    |
| accept4                | 288    | signalfd4              | 289    |
| eventfd2               | 290    | epoll_create1          | 291    |
| dup3                   | 292    | pipe2                  | 293    |
| inotify_init1          | 294    | preadv                 | 295    |
| pwritev                | 296    | rt_tgsigqueueinfo      | 297    |
| perf_event_open        | 298    | recvmmsg               | 299    |
| fanotify_init          | 300    | fanotify_mark          | 301    |
| prlimit64              | 302    | name_to_handle_at      | 303    |
| open_by_handle_at      | 304    | clock_adjtime          | 305    |
| syncfs                 | 306    | sendmmsg               | 307    |
| set_ns                 | 308    | get_cpu                | 309    |
| process_vm_readv       | 310    | process_vm_writev      | 311    |

# 系统调用详解
<table>
  <thead>
    <tr>
      <th>rax</th>
      <th>System Call</th>
      <th>rdi</th>
      <th>rsi</th>
      <th>rdx</th>
      <th>r10</th>
      <th>r8</th>
      <th>r9</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row" data-label="rax">0</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/read" target="_blank">
          sys_read
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">char* buf</td>
      <td data-label="rdx">size_t count</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">1</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/write" target="_blank">
          sys_write
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">const char* buf</td>
      <td data-label="rdx">size_t count</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">2</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/open" target="_blank">
          sys_open
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx">int mode</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">3</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/close" target="_blank">
          sys_close
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">4</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/stat" target="_blank">
          sys_stat
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">struct stat* statbuf</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">5</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fstat" target="_blank">
          sys_fstat
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">struct stat* statbuf</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">6</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lstat" target="_blank">
          sys_lstat
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">struct stat* statbuf</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">7</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/poll" target="_blank">
          sys_poll
        </a>
      </td>
      <td data-label="rdi">struct poll_fd* ufds</td>
      <td data-label="rsi">unsigned int nfds</td>
      <td data-label="rdx">long timeout_msecs</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">8</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lseek" target="_blank">
          sys_lseek
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">off_t offset</td>
      <td data-label="rdx">unsigned int origin</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">9</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mmap" target="_blank">
          sys_mmap
        </a>
      </td>
      <td data-label="rdi">unsigned long addr</td>
      <td data-label="rsi">unsigned long len</td>
      <td data-label="rdx">unsigned long prot</td>
      <td data-label="r10">unsigned long flags</td>
      <td data-label="r8">unsigned long fd</td>
      <td data-label="r9">unsigned long off</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">10</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mprotect" target="_blank">
          sys_mprotect
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx">unsigned long prot</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">11</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/munmap" target="_blank">
          sys_munmap
        </a>
      </td>
      <td data-label="rdi">unsigned long addr</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">12</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/brk" target="_blank">
          sys_brk
        </a>
      </td>
      <td data-label="rdi">unsigned long brk</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">13</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigaction" target="_blank">
          sys_rt_sigaction
        </a>
      </td>
      <td data-label="rdi">int sig</td>
      <td data-label="rsi">const struct sigaction* act</td>
      <td data-label="rdx">struct sigaction* oact</td>
      <td data-label="r10">sizt_t sigsetsize</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">14</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigprocmask" target="_blank">
          sys_rt_sigprocmask
        </a>
      </td>
      <td data-label="rdi">int how</td>
      <td data-label="rsi">sigset_t* nset</td>
      <td data-label="rdx">sigset_t* oset</td>
      <td data-label="r10">sizt_t sigsetsize</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">15</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigreturn" target="_blank">
          sys_rt_sigreturn
        </a>
      </td>
      <td data-label="rdi">unsigned long _unused</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">16</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ioctl" target="_blank">
          sys_ioctl
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">unsigned int cmd</td>
      <td data-label="rdx">unsigned long arg</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">17</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pread64" target="_blank">
          sys_pread64
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">char* buf</td>
      <td data-label="rdx">size_t count</td>
      <td data-label="r10">off_t pos</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">18</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pwrite64" target="_blank">
          sys_pwrite64
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">const char* fd</td>
      <td data-label="rdx">sizt_t count</td>
      <td data-label="r10">off_t pos</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">19</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/readv" target="_blank">
          sys_readv
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">const struct iovec* vec</td>
      <td data-label="rdx">unsigned long vlen</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">20</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/writev" target="_blank">
          sys_writev
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">const struct iovec* vec</td>
      <td data-label="rdx">unsigned long vlen</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">21</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/access" target="_blank">
          sys_access
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">int mode</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">22</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pipe" target="_blank">
          sys_pipe
        </a>
      </td>
      <td data-label="rdi">int* fields</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">23</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/select" target="_blank">
          sys_select
        </a>
      </td>
      <td data-label="rdi">int n</td>
      <td data-label="rsi">fd_set* inp</td>
      <td data-label="rdx">fd_set* outp</td>
      <td data-label="r10">fd_set* exp</td>
      <td data-label="r8">struct timeval* tvp</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">24</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_yield" target="_blank">
          sys_sched_yield
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">25</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mremap" target="_blank">
          sys_mremap
        </a>
      </td>
      <td data-label="rdi">unsigned long addr</td>
      <td data-label="rsi">unsigned long old_len</td>
      <td data-label="rdx">unsigned long new_len</td>
      <td data-label="r10">unsigned long flags</td>
      <td data-label="r8">unsigned long new_addr</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">26</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/msync" target="_blank">
          sys_msync
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx">int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">27</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mincore" target="_blank">
          sys_mincore
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx">unsigned char* vec</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">28</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/madvise" target="_blank">
          sys_madvise
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">sizt_t len_in</td>
      <td data-label="rdx">int behavior</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">29</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/shmget" target="_blank">
          sys_shmget
        </a>
      </td>
      <td data-label="rdi">key_t key</td>
      <td data-label="rsi">size_t size</td>
      <td data-label="rdx">int shmflg</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">30</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/shmat" target="_blank">
          sys_shmat
        </a>
      </td>
      <td data-label="rdi">int shmid</td>
      <td data-label="rsi">char* shmaddr</td>
      <td data-label="rdx">int shmflg</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">31</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/shmctl" target="_blank">
          sys_shmctl
        </a>
      </td>
      <td data-label="rdi">int shmid</td>
      <td data-label="rsi">int cmd</td>
      <td data-label="rdx">struct shmid_ds* buf</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">32</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/dup" target="_blank">
          sys_dup
        </a>
      </td>
      <td data-label="rdi">unsigned int fields</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">33</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/dup2" target="_blank">
          sys_dup2
        </a>
      </td>
      <td data-label="rdi">unsigned int oldfd</td>
      <td data-label="rsi">unsigned int newfd</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">34</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pause" target="_blank">
          sys_pause
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">35</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/nanosleep" target="_blank">
          sys_nanosleep
        </a>
      </td>
      <td data-label="rdi">struct timespec* rqtp</td>
      <td data-label="rsi">struct timespec* rmtp</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">36</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getitimer" target="_blank">
          sys_getitimer
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">struct itimerval* value</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">37</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/alarm" target="_blank">
          sys_alarm
        </a>
      </td>
      <td data-label="rdi">unsigned int seconds</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">38</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setitimer" target="_blank">
          sys_setitimer
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">struct itimerval* value</td>
      <td data-label="rdx">struct itimerval* ovalue</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">39</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getpid" target="_blank">
          sys_getpid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">40</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sendfile" target="_blank">
          sys_sendfile
        </a>
      </td>
      <td data-label="rdi">int out_fd</td>
      <td data-label="rsi">int in_fd</td>
      <td data-label="rdx">off_t* offset</td>
      <td data-label="r10">size_t count</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">41</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/socket" target="_blank">
          sys_socket
        </a>
      </td>
      <td data-label="rdi">int family</td>
      <td data-label="rsi">int type</td>
      <td data-label="rdx">int protocol</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">42</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/connect" target="_blank">
          sys_connect
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct sockaddr* uservaddr</td>
      <td data-label="rdx">int addrlen</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">43</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/accept" target="_blank">
          sys_accept
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct sockaddr* upeer_sockaddr</td>
      <td data-label="rdx">int upeer_addrlen</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">44</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sendto" target="_blank">
          sys_sendto
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">void* buff</td>
      <td data-label="rdx">size_t len</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8">struct sockaddr* addr</td>
      <td data-label="r9">socklen_t addr_len</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">45</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/recvfrom" target="_blank">
          sys_recvfrom
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">void *ubuf</td>
      <td data-label="rdx">size_t len</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8">struct sockaddr* addr</td>
      <td data-label="r9">socklen_t* addr_len</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">46</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sendmsg" target="_blank">
          sys_sendmsg
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct msghdr* msg</td>
      <td data-label="rdx">unsigned int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">47</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/recvmsg" target="_blank">
          sys_recvmsg
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct msghdr* msg</td>
      <td data-label="rdx">unsigned int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">48</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/shutdown" target="_blank">
          sys_shutdown
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">int how</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">49</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/bind" target="_blank">
          sys_bind
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct sockaddr* umyaddr</td>
      <td data-label="rdx">int addrlen</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">50</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/listen" target="_blank">
          sys_listen
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">int backlog</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">51</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getsockname" target="_blank">
          sys_getsockname
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct sockaddr* usockaddr</td>
      <td data-label="rdx">int* usockaddr_len</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">52</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getpeername" target="_blank">
          sys_getpeername
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct sockaddr* usockaddr</td>
      <td data-label="rdx">int* usockaddr_len</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">53</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/socketpair" target="_blank">
          sys_socketpair
        </a>
      </td>
      <td data-label="rdi">int family</td>
      <td data-label="rsi">int type</td>
      <td data-label="rdx">int protocol</td>
      <td data-label="r10">int* usockvec</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">54</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setsockopt" target="_blank">
          sys_setsockopt
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">int level</td>
      <td data-label="rdx">int optname</td>
      <td data-label="r10">char* optval</td>
      <td data-label="r8">int optlen</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">55</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getsockopt" target="_blank">
          sys_getsockopt
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">int level</td>
      <td data-label="rdx">int optname</td>
      <td data-label="r10">char* optval</td>
      <td data-label="r8">int* optlen</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">56</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/clone" target="_blank">
          sys_clone
        </a>
      </td>
      <td data-label="rdi">unsigned long clone_flags</td>
      <td data-label="rsi">unsigned long newsp</td>
      <td data-label="rdx">void* parent_tid</td>
      <td data-label="r10">void* child_tid</td>
      <td data-label="r8">unsigned int tid</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">57</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fork" target="_blank">
          sys_fork
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">58</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/vfork" target="_blank">
          sys_vfork
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">59</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/execve" target="_blank">
          sys_execve
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">const char* argv[]</td>
      <td data-label="rdx">const char* envp[]</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">60</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/exit" target="_blank">
          sys_exit
        </a>
      </td>
      <td data-label="rdi">int error_code</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">61</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/wait4" target="_blank">
          sys_wait4
        </a>
      </td>
      <td data-label="rdi">pid_t upid</td>
      <td data-label="rsi">int* stat_addr</td>
      <td data-label="rdx">int options</td>
      <td data-label="r10">struct rusage* ru</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">62</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/kill" target="_blank">
          sys_kill
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">int sig</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">63</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/uname" target="_blank">
          sys_uname
        </a>
      </td>
      <td data-label="rdi">struct old_utsname* name</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">64</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/semget" target="_blank">
          sys_semget
        </a>
      </td>
      <td data-label="rdi">key_t key</td>
      <td data-label="rsi">int nsems</td>
      <td data-label="rdx">int semflg</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">65</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/semop" target="_blank">
          sys_semop
        </a>
      </td>
      <td data-label="rdi">int semid</td>
      <td data-label="rsi">struct sembuf* tsops</td>
      <td data-label="rdx">unsigned nsops</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">66</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/semctl" target="_blank">
          sys_semctl
        </a>
      </td>
      <td data-label="rdi">int semid</td>
      <td data-label="rsi">int semnum</td>
      <td data-label="rdx">int cmd</td>
      <td data-label="r10">union semun arg</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">67</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/shmdt" target="_blank">
          sys_shmdt
        </a>
      </td>
      <td data-label="rdi">char* shmaddr</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">68</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/msgget" target="_blank">
          sys_msgget
        </a>
      </td>
      <td data-label="rdi">key_t key</td>
      <td data-label="rsi">int msgflg</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">69</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/msgsnd" target="_blank">
          sys_msgsnd
        </a>
      </td>
      <td data-label="rdi">int msquid</td>
      <td data-label="rsi">struct msgbuf* msgp</td>
      <td data-label="rdx">size_t msgsz</td>
      <td data-label="r10">int msgflg</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">70</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/msgrcv" target="_blank">
          sys_msgrcv
        </a>
      </td>
      <td data-label="rdi">int msqid</td>
      <td data-label="rsi">struct msgbuf* msgp</td>
      <td data-label="rdx">size_t msgsz</td>
      <td data-label="r10">long msgtyp</td>
      <td data-label="r8">int msgflg</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">71</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/msgctl" target="_blank">
          sys_msgctl
        </a>
      </td>
      <td data-label="rdi">int msqid</td>
      <td data-label="rsi">int cmd</td>
      <td data-label="rdx">struct msqid_ds* buf</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">72</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fcntl" target="_blank">
          sys_fcntl
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">unsigned int cmd</td>
      <td data-label="rdx">unsigned long arg</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">73</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/flock" target="_blank">
          sys_flock
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">unsigned int cmd</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">74</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fsync" target="_blank">
          sys_fsync
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">75</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fdatasync" target="_blank">
          sys_fdatasync
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">76</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/truncate" target="_blank">
          sys_truncate
        </a>
      </td>
      <td data-label="rdi">const char* path</td>
      <td data-label="rsi">long length</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">77</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ftruncate" target="_blank">
          sys_ftruncate
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">unsigned long length</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">78</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getdents" target="_blank">
          sys_getdents
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">struct linux_dirent* dirent</td>
      <td data-label="rdx">unsigned int count</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">79</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getcwd" target="_blank">
          sys_getcwd
        </a>
      </td>
      <td data-label="rdi">char* buf</td>
      <td data-label="rsi">unsigned long size</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">80</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/chdir" target="_blank">
          sys_chdir
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">81</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fchdir" target="_blank">
          sys_fchdir
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">82</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rename" target="_blank">
          sys_rename
        </a>
      </td>
      <td data-label="rdi">const char* oldname</td>
      <td data-label="rsi">const char* newname</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">83</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mkdir" target="_blank">
          sys_mkdir
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">int mode</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">84</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rmdir" target="_blank">
          sys_rmdir
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">85</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/creat" target="_blank">
          sys_creat
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">int mode</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">86</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/link" target="_blank">
          sys_link
        </a>
      </td>
      <td data-label="rdi">const char* oldname</td>
      <td data-label="rsi">const char* newname</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">87</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/unlink" target="_blank">
          sys_unlink
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">88</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/symlink" target="_blank">
          sys_symlink
        </a>
      </td>
      <td data-label="rdi">const char* oldname</td>
      <td data-label="rsi">const char* newname</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">89</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/readlink" target="_blank">
          sys_readlink
        </a>
      </td>
      <td data-label="rdi">const char* path</td>
      <td data-label="rsi">char* buf</td>
      <td data-label="rdx">int bufsiz</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">90</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/chmod" target="_blank">
          sys_chmod
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">mode_t mode</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">91</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fchmod" target="_blank">
          sys_fchmod
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">mod_t mode</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">92</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/chown" target="_blank">
          sys_chown
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">uid_t user</td>
      <td data-label="rdx">gid_t group</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">93</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fchown" target="_blank">
          sys_fchown
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">uid_t user</td>
      <td data-label="rdx">gid_t group</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">94</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lchown" target="_blank">
          sys_lchown
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">uid_t user</td>
      <td data-label="rdx">guid_t group</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">95</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/umask" target="_blank">
          sys_umask
        </a>
      </td>
      <td data-label="rdi">int mask</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">96</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/gettimeofday" target="_blank">
          sys_gettimeofday
        </a>
      </td>
      <td data-label="rdi">struct timeval* tv</td>
      <td data-label="rsi">struct timezone* tz</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">97</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getrlimit" target="_blank">
          sys_getrlimit
        </a>
      </td>
      <td data-label="rdi">unsigned int resource</td>
      <td data-label="rsi">struct rlimit* rlim</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">98</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getrusage" target="_blank">
          sys_getrusage
        </a>
      </td>
      <td data-label="rdi">int who</td>
      <td data-label="rsi">struct rusage* ru</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">99</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sysinfo" target="_blank">
          sys_sysinfo
        </a>
      </td>
      <td data-label="rdi">struct sysinfo* info</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">100</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/times" target="_blank">
          sys_times
        </a>
      </td>
      <td data-label="rdi">struct tms* tbuf</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">101</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ptrace" target="_blank">
          sys_ptrace
        </a>
      </td>
      <td data-label="rdi">long request</td>
      <td data-label="rsi">long pid</td>
      <td data-label="rdx">unsigned long addr</td>
      <td data-label="r10">unsigned long data</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">102</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getuid" target="_blank">
          sys_getuid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">103</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/syslog" target="_blank">
          sys_syslog
        </a>
      </td>
      <td data-label="rdi">int type</td>
      <td data-label="rsi">char* buf</td>
      <td data-label="rdx">int len</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">104</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getgid" target="_blank">
          sys_getgid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">105</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setuid" target="_blank">
          sys_setuid
        </a>
      </td>
      <td data-label="rdi">uid_t uid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">106</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setgid" target="_blank">
          sys_setgid
        </a>
      </td>
      <td data-label="rdi">gid_t gid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">107</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/geteuid" target="_blank">
          sys_geteuid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">108</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getegid" target="_blank">
          sys_getegid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">109</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setpgid" target="_blank">
          sys_setpgid
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">110</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getppid" target="_blank">
          sys_getppid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">111</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getpgrp" target="_blank">
          sys_getpgrp
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">112</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setsid" target="_blank">
          sys_setsid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">113</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setreuid" target="_blank">
          sys_setreuid
        </a>
      </td>
      <td data-label="rdi">uid_t ruid</td>
      <td data-label="rsi">uid_t euid</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">114</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setregid" target="_blank">
          sys_setregid
        </a>
      </td>
      <td data-label="rdi">gid_t rgid</td>
      <td data-label="rsi">gid_t egid</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">115</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getgroups" target="_blank">
          sys_getgroups
        </a>
      </td>
      <td data-label="rdi">int gidsetsize</td>
      <td data-label="rsi">gid_t* grouplist</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">116</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setgroups" target="_blank">
          sys_setgroups
        </a>
      </td>
      <td data-label="rdi">int gidsetsize</td>
      <td data-label="rsi">gid_t* grouplist</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">117</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setresuid" target="_blank">
          sys_setresuid
        </a>
      </td>
      <td data-label="rdi">uid_t* ruid</td>
      <td data-label="rsi">uid_t* euid</td>
      <td data-label="rdx">uid_t* suid</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">118</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getresuid" target="_blank">
          sys_getresuid
        </a>
      </td>
      <td data-label="rdi">uid_t* ruid</td>
      <td data-label="rsi">uid_t* euid</td>
      <td data-label="rdx">uid_t *suid</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">119</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setresgid" target="_blank">
          sys_setresgid
        </a>
      </td>
      <td data-label="rdi">gid_t rgid</td>
      <td data-label="rsi">gid_t egid</td>
      <td data-label="rdx">gid_t sgid</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">120</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getresgid" target="_blank">
          sys_getresgid
        </a>
      </td>
      <td data-label="rdi">gid_t* rgid</td>
      <td data-label="rsi">gid_t* egid</td>
      <td data-label="rdx">gid_t* sgid</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">121</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getpgid" target="_blank">
          sys_getpgid
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">122</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setfsuid" target="_blank">
          sys_setfsuid
        </a>
      </td>
      <td data-label="rdi">uid_t uid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">123</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setfsgid" target="_blank">
          sys_setfsgid
        </a>
      </td>
      <td data-label="rdi">gid_t gid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">124</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getsid" target="_blank">
          sys_getsid
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">125</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/capget" target="_blank">
          sys_capget
        </a>
      </td>
      <td data-label="rdi">cap_user_header_t header</td>
      <td data-label="rsi">cap_user_data_t dataptr</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">126</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/capset" target="_blank">
          sys_capset
        </a>
      </td>
      <td data-label="rdi">cap_user_header_t header</td>
      <td data-label="rsi">const user_data_t data</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">127</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigpending" target="_blank">
          sys_rt_sigpending
        </a>
      </td>
      <td data-label="rdi">sigset_t* set</td>
      <td data-label="rsi">size_t sigsetsize</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">128</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigtimedwait" target="_blank">
          sys_sigtimedwait
        </a>
      </td>
      <td data-label="rdi">const sigset_t* uthese</td>
      <td data-label="rsi">siginfo_t* uinfo</td>
      <td data-label="rdx">const struct timespec* utf</td>
      <td data-label="r10">size_t sigsetsize</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">129</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigqueueinfo" target="_blank">
          sys_rt_sigqueueinfo
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">int sig</td>
      <td data-label="rdx">siginfo_t* uinfo</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">130</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_sigsuspend" target="_blank">
          sys_rt_sigsuspend
        </a>
      </td>
      <td data-label="rdi">sigset_t* unewset</td>
      <td data-label="rsi">size_t sigsetsize</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">131</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sigaltstack" target="_blank">
          sys_sigaltstack
        </a>
      </td>
      <td data-label="rdi">const stack_t* uss</td>
      <td data-label="rsi">stack_t* uoss</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">132</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/utime" target="_blank">
          sys_utime
        </a>
      </td>
      <td data-label="rdi">char* filename</td>
      <td data-label="rsi">struct utimbuf* times</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">133</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mknod" target="_blank">
          sys_mknod
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi">umode_t mode</td>
      <td data-label="rdx">unsigned dev</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">134</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/uselib" target="_blank">
          sys_uselib
        </a>
      </td>
      <td data-label="rdi">const char* library</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">135</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/personality" target="_blank">
          sys_personality
        </a>
      </td>
      <td data-label="rdi">unsigned int personality</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">136</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ustat" target="_blank">
          sys_ustat
        </a>
      </td>
      <td data-label="rdi">unsigned dev</td>
      <td data-label="rsi">struct ustat* ubuf</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">137</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/statfs" target="_blank">
          sys_statfs
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">struct statfs* buf</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">138</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fstatfs" target="_blank">
          sys_fstatfs
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">struct statfs* buf</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">139</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sysfs" target="_blank">
          sys_sysfs
        </a>
      </td>
      <td data-label="rdi">int option</td>
      <td data-label="rsi">unsigned long arg1</td>
      <td data-label="rdx">unsigned long arg2</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">140</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getpriority" target="_blank">
          sys_getpriority
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">int who</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">141</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setpriority" target="_blank">
          sys_setpriority
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">int who</td>
      <td data-label="rdx">int niceval</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">142</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_setparam" target="_blank">
          sys_sched_setparam
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">struct sched_param* param</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">143</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_getparam" target="_blank">
          sys_sched_getparam
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">struct sched_param* param</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">144</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_setscheduler" target="_blank">
          sys_sched_setscheduler
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">int policy</td>
      <td data-label="rdx">struct sched_param* param</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">145</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_getscheduler" target="_blank">
          sys_sched_getscheduler
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">146</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_get_priority_max" target="_blank">
          sys_sched_get_priority_max
        </a>
      </td>
      <td data-label="rdi">int policy</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">147</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_get_policy_min" target="_blank">
          sys_sched_get_policy_min
        </a>
      </td>
      <td data-label="rdi">int policy</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">148</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_rr_get_interval" target="_blank">
          sys_sched_rr_get_interval
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">struct timespec* interval</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">149</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mlock" target="_blank">
          sys_mlock
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">150</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/munlock" target="_blank">
          sys_munlock
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">151</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mlockall" target="_blank">
          sys_mlockall
        </a>
      </td>
      <td data-label="rdi">int flags</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">152</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/munlockall" target="_blank">
          sys_munlockall
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">153</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/vhangup" target="_blank">
          sys_vhangup
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">154</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/modify_ldt" target="_blank">
          sys_modify_ldt
        </a>
      </td>
      <td data-label="rdi">int func</td>
      <td data-label="rsi">void* ptr</td>
      <td data-label="rdx">unsigned long bytecount</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">155</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pivot_root" target="_blank">
          sys_pivot_root
        </a>
      </td>
      <td data-label="rdi">const char* new_root</td>
      <td data-label="rsi">const char* put_old</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">156</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sysctl" target="_blank">
          sys_sysctl
        </a>
      </td>
      <td data-label="rdi">struct __sysctl_args* args</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">157</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/prctl" target="_blank">
          sys_prctl
        </a>
      </td>
      <td data-label="rdi">int option</td>
      <td data-label="rsi">unsigned long arg2</td>
      <td data-label="rdx">unsigned long arg3</td>
      <td data-label="r10">unsigned long arg4</td>
      <td data-label="r8"></td>
      <td data-label="r9">unsigned long arg5</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">158</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/arch_prctl" target="_blank">
          sys_arch_prctl
        </a>
      </td>
      <td data-label="rdi">struct task_struct* task</td>
      <td data-label="rsi">int code</td>
      <td data-label="rdx">unsigned long* addr</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">159</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/adjtimex" target="_blank">
          sys_adjtimex
        </a>
      </td>
      <td data-label="rdi">struct timex *txc_p</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">160</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setrlimit" target="_blank">
          sys_setrlimit
        </a>
      </td>
      <td data-label="rdi">unsigned int resource</td>
      <td data-label="rsi">struct rlimit* rlim</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">161</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/chroot" target="_blank">
          sys_chroot
        </a>
      </td>
      <td data-label="rdi">const char* filename</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">162</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sync" target="_blank">
          sys_sync
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">163</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/acct" target="_blank">
          sys_acct
        </a>
      </td>
      <td data-label="rdi">const char* name</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">164</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/settimeofday" target="_blank">
          sys_settimeofday
        </a>
      </td>
      <td data-label="rdi">struct timeval* tv</td>
      <td data-label="rsi">struct timezone* tz</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">165</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mount" target="_blank">
          sys_mount
        </a>
      </td>
      <td data-label="rdi">char* dev_name</td>
      <td data-label="rsi">char* dir_name</td>
      <td data-label="rdx">char* type</td>
      <td data-label="r10">unsigned long flags</td>
      <td data-label="r8">void* data</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">166</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/umount2" target="_blank">
          sys_umount2
        </a>
      </td>
      <td data-label="rdi">const char* target</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">167</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/swapon" target="_blank">
          sys_swapon
        </a>
      </td>
      <td data-label="rdi">const char* specialfile</td>
      <td data-label="rsi">int swap_flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">168</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/swapoff" target="_blank">
          sys_swapoff
        </a>
      </td>
      <td data-label="rdi">const char* specialfile</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">169</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/reboot" target="_blank">
          sys_reboot
        </a>
      </td>
      <td data-label="rdi">int magic1</td>
      <td data-label="rsi">int magic2</td>
      <td data-label="rdx">unsigned int cmd</td>
      <td data-label="r10">void* arg</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">170</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sethostname" target="_blank">
          sys_sethostname
        </a>
      </td>
      <td data-label="rdi">char* name</td>
      <td data-label="rsi">int len</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">171</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setdomainname" target="_blank">
          sys_setdomainname
        </a>
      </td>
      <td data-label="rdi">char* name</td>
      <td data-label="rsi">int len</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">172</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/iopl" target="_blank">
          sys_iopl
        </a>
      </td>
      <td data-label="rdi">unsigned int level</td>
      <td data-label="rsi">struct pt_regs* regs</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">173</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ioperm" target="_blank">
          sys_ioperm
        </a>
      </td>
      <td data-label="rdi">unsigned long from</td>
      <td data-label="rsi">unsigned long num</td>
      <td data-label="rdx">int turn_on</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">174</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/create_module" target="_blank">
          sys_create_module
        </a>
      </td>
      <td data-label="rdi"><strong>REMOVED IN Linux 2.6</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">175</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/init_module" target="_blank">
          sys_init_module
        </a>
      </td>
      <td data-label="rdi">void* umod</td>
      <td data-label="rsi">unsigned long len</td>
      <td data-label="rdx">const char* uargs</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">176</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/delete_module" target="_blank">
          sys_delete_module
        </a>
      </td>
      <td data-label="rdi">const char* name_user</td>
      <td data-label="rsi">unsigned int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">177</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/get_kernel_syms" target="_blank">
          sys_get_kernel_syms
        </a>
      </td>
      <td data-label="rdi"><strong>REMOVED IN Linux 2.6</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">178</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/query_module" target="_blank">
          sys_query_module
        </a>
      </td>
      <td data-label="rdi"><strong>REMOVED IN Linux 2.6</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">179</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/quotactl" target="_blank">
          sys_quotactl
        </a>
      </td>
      <td data-label="rdi">unsigned int cmd</td>
      <td data-label="rsi">const char* special</td>
      <td data-label="rdx">quid_t id</td>
      <td data-label="r10">void* addr</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">180</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/nfsservctl" target="_blank">
          sys_nfsservctl
        </a>
      </td>
      <td data-label="rdi"><strong>REMOVED IN Linux 3.1</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">181</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getpmsg" target="_blank">
          sys_getpmsg
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">182</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/putpmsg" target="_blank">
          sys_putpmsg
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">183</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/afs_syscall" target="_blank">
          sys_afs_syscall
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">184</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/tuxcall" target="_blank">
          sys_tuxcall
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">185</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/security" target="_blank">
          sys_security
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">186</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/gettid" target="_blank">
          sys_gettid
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">187</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/readahead" target="_blank">
          sys_readahead
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">off_64t offset</td>
      <td data-label="rdx">size_t count</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">188</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setxattr" target="_blank">
          sys_setxattr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">const void* value</td>
      <td data-label="r10">size_t size</td>
      <td data-label="r8">int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">189</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lsetxattr" target="_blank">
          sys_lsetxaddr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">const void* value</td>
      <td data-label="r10">size_t size</td>
      <td data-label="r8">int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">190</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fsetxattr" target="_blank">
          sys_fsetxaddr
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">const void&amp; value</td>
      <td data-label="r10">size_t size</td>
      <td data-label="r8">int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">191</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getxattr" target="_blank">
          sys_getxaddr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">void *value</td>
      <td data-label="r10">size_t size</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">192</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lgetxattr" target="_blank">
          sys_lgetxattr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">void* value</td>
      <td data-label="r10">size_t size</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">193</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fgetxattr" target="_blank">
          sys_fgetxaddr
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">void* value</td>
      <td data-label="r10">size_t size</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">194</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/listxattr" target="_blank">
          sys_listxattr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">char* list</td>
      <td data-label="rdx">size_t size</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">195</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/llistxattr" target="_blank">
          sys_llistxattr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">char* list</td>
      <td data-label="rdx">size_t size</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">196</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/flistxattr" target="_blank">
          sys_flistxattr
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">char* list</td>
      <td data-label="rdx">size_t size</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">197</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/removexattr" target="_blank">
          sys_removexattr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">198</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lremovexattr" target="_blank">
          sys_lremovexattr
        </a>
      </td>
      <td data-label="rdi">const char* pathname</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">199</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fremovexattr" target="_blank">
          sys_fremovexattr
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">200</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/tkill" target="_blank">
          sys_tkill
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">int sig</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">201</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/time" target="_blank">
          sys_time
        </a>
      </td>
      <td data-label="rdi">time_t* tloc</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">202</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/futex" target="_blank">
          sys_futex
        </a>
      </td>
      <td data-label="rdi">u32* uaddr</td>
      <td data-label="rsi">int op</td>
      <td data-label="rdx">u32 val</td>
      <td data-label="r10">struct timespec* utime</td>
      <td data-label="r8">u32* uaddr2</td>
      <td data-label="r9">u32 val3</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">203</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_setaffinity" target="_blank">
          sys_sched_setaffinity
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">unsigned int len</td>
      <td data-label="rdx">unsigned long* user_mask_ptr</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">204</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sched_getaffinity" target="_blank">
          sys_sched_getaffinity
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">unsigned int len</td>
      <td data-label="rdx">unsigned long* user_mask_ptr</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">205</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/set_thread_area" target="_blank">
          sys_set_thread_area
        </a>
      </td>
      <td data-label="rdi">struct user_desc* u_info</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">206</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/io_setup" target="_blank">
          sys_io_setup
        </a>
      </td>
      <td data-label="rdi">unsigned nr_events</td>
      <td data-label="rsi">aio_context_t* ctxp</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">207</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/io_destroy" target="_blank">
          sys_io_destroy
        </a>
      </td>
      <td data-label="rdi">aio_context_t ctx</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">208</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/io_getevents" target="_blank">
          sys_io_getevents
        </a>
      </td>
      <td data-label="rdi">aio_context_t ctx_id</td>
      <td data-label="rsi">long min_nr</td>
      <td data-label="rdx">long nr</td>
      <td data-label="r10">struct io_event* events</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">209</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/io_submit" target="_blank">
          sys_io_submit
        </a>
      </td>
      <td data-label="rdi">aio_context_t* ctx_id</td>
      <td data-label="rsi">long nr</td>
      <td data-label="rdx">struct iocb** iocbpp</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">210</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/io_cancel" target="_blank">
          sys_io_cancel
        </a>
      </td>
      <td data-label="rdi">aio_context_t* ctx_id</td>
      <td data-label="rsi">struct iocb* iocb</td>
      <td data-label="rdx">struct io_event* result</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">211</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/get_thread_area" target="_blank">
          sys_get_thread_area
        </a>
      </td>
      <td data-label="rdi">struct user_desc* u_info</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">212</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/lookup_dcookie" target="_blank">
          sys_lookup_dcookie
        </a>
      </td>
      <td data-label="rdi">u64 cookie64</td>
      <td data-label="rsi">long buf</td>
      <td data-label="rdx">long len</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">213</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/epoll_create" target="_blank">
          sys_epoll_create
        </a>
      </td>
      <td data-label="rdi">int size</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">214</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_epoll_ctl_old
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">215</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_epoll_wait_old
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">216</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/remap_file_pages" target="_blank">
          sys_remap_file_pages
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">unsigned long size</td>
      <td data-label="rdx">unsigned long prot</td>
      <td data-label="r10">unsigned long pgoff</td>
      <td data-label="r8">unsigned long flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">217</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getdents64" target="_blank">
          sys_getdents64
        </a>
      </td>
      <td data-label="rdi">unsigned int fd</td>
      <td data-label="rsi">struct linux_dirent64* dirent</td>
      <td data-label="rdx">unsigned int count</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">218</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/set_tid_address" target="_blank">
          sys_set_tid_address
        </a>
      </td>
      <td data-label="rdi">int* tidptr</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">219</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/restart_syscall" target="_blank">
          sys_restart_syscall
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">220</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/semtimedop" target="_blank">
          sys_semtimedop
        </a>
      </td>
      <td data-label="rdi">int semid</td>
      <td data-label="rsi">struct sembuf* tsops</td>
      <td data-label="rdx">unsigned nsops</td>
      <td data-label="r10">const struct timespec* timeout</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">221</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fadvise64" target="_blank">
          sys_fadvise64
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">off_t offset</td>
      <td data-label="rdx">size_t len</td>
      <td data-label="r10">int advice</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">222</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timer_create" target="_blank">
          sys_timer_create
        </a>
      </td>
      <td data-label="rdi">const clockid_t which_clock</td>
      <td data-label="rsi">struct sigevent* timer_event_spec</td>
      <td data-label="rdx">timer_t* created_timer_id</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">223</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timer_settime" target="_blank">
          sys_timer_settime
        </a>
      </td>
      <td data-label="rdi">timer_t timer_id</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx">const struct itimerspec* new_setting</td>
      <td data-label="r10">struct itimerspec* old_setting</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">224</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timer_gettime" target="_blank">
          sys_timer_gettime
        </a>
      </td>
      <td data-label="rdi">timer_t timer_id</td>
      <td data-label="rsi">struct itimerspec* setting</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">225</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timer_getoverrun" target="_blank">
          sys_timer_getoverrun
        </a>
      </td>
      <td data-label="rdi">timer_t timer_id</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">226</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timer_delete" target="_blank">
          sys_timer_delete
        </a>
      </td>
      <td data-label="rdi">timer_t timer_id</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">227</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/clock_settime" target="_blank">
          sys_clock_settime
        </a>
      </td>
      <td data-label="rdi">const clockid_t which_clock</td>
      <td data-label="rsi">const struct timespec* tp</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">228</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/clock_gettime" target="_blank">
          sys_clock_gettime
        </a>
      </td>
      <td data-label="rdi">const clockid_t which_clock</td>
      <td data-label="rsi">struct timespec* tp</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">229</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/clock_getres" target="_blank">
          sys_clock_getres
        </a>
      </td>
      <td data-label="rdi">const clockid_t which_clock</td>
      <td data-label="rsi">struct timespect* tp</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">230</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/clock_nanosleep" target="_blank">
          sys_clock_nanosleep
        </a>
      </td>
      <td data-label="rdi">const clockid_t which_clock</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx">const struct timespec* rqtp</td>
      <td data-label="r10">struct timespec* rmtp</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">231</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/exit_group" target="_blank">
          sys_exit_group
        </a>
      </td>
      <td data-label="rdi">int error_code</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">232</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/epoll_wait" target="_blank">
          sys_epoll_wait
        </a>
      </td>
      <td data-label="rdi">int epfd</td>
      <td data-label="rsi">struct epoll_event* events</td>
      <td data-label="rdx">int maxevents</td>
      <td data-label="r10">int timeout</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">233</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/epoll_ctl" target="_blank">
          sys_epoll_ctl
        </a>
      </td>
      <td data-label="rdi">int epfd</td>
      <td data-label="rsi">int op</td>
      <td data-label="rdx">int fd</td>
      <td data-label="r10">struct epoll_event* event</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">234</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/tgkill" target="_blank">
          sys_tgkill
        </a>
      </td>
      <td data-label="rdi">pid_t tgid</td>
      <td data-label="rsi">pid_t pid</td>
      <td data-label="rdx">int sig</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">235</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/utimes" target="_blank">
          sys_utimes
        </a>
      </td>
      <td data-label="rdi">char* filename</td>
      <td data-label="rsi">struct timeval* utimes</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">236</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/vserver" target="_blank">
          sys_vserver
        </a>
      </td>
      <td data-label="rdi"><strong>UNIMPLEMENTED</strong></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">237</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mbind" target="_blank">
          sys_mbind
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">unsigned long len</td>
      <td data-label="rdx">unsigned long mode</td>
      <td data-label="r10">unsigned long *nmask</td>
      <td data-label="r8">unsigned long maxnode</td>
      <td data-label="r9">unsigned flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">238</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/set_mempolicy" target="_blank">
          sys_set_mempolicy
        </a>
      </td>
      <td data-label="rdi">int mode</td>
      <td data-label="rsi">unsigned long* nmask</td>
      <td data-label="rdx">unsigned long maxnode</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">239</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/get_mempolicy" target="_blank">
          sys_get_mempolicy
        </a>
      </td>
      <td data-label="rdi">int* policy</td>
      <td data-label="rsi">unsigned long* nmask</td>
      <td data-label="rdx">unsigned long maxnode</td>
      <td data-label="r10">unsigned long addr</td>
      <td data-label="r8">unsigned long flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">240</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mq_open" target="_blank">
          sys_mq_open
        </a>
      </td>
      <td data-label="rdi">const char* u_name</td>
      <td data-label="rsi">int oflag</td>
      <td data-label="rdx">mode_t mode</td>
      <td data-label="r10">struct mq_attr* u_attr</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">241</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mq_unlink" target="_blank">
          sys_mq_unlink
        </a>
      </td>
      <td data-label="rdi">const char* u_name</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">242</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mq_timedsend" target="_blank">
          sys_mq_timedsend
        </a>
      </td>
      <td data-label="rdi">mqd_t mqdes</td>
      <td data-label="rsi">const char* u_msg_ptr</td>
      <td data-label="rdx">size_t msg_len</td>
      <td data-label="r10">unsigned int msg_prio</td>
      <td data-label="r8">const struct timespec* u_abs_timeout</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">243</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mq_timedreceive" target="_blank">
          sys_mq_timedreceive
        </a>
      </td>
      <td data-label="rdi">mqd_t mqdes</td>
      <td data-label="rsi">char* u_msg_ptr</td>
      <td data-label="rdx">size_t msg_len</td>
      <td data-label="r10">unsigned int* u_msg_prio</td>
      <td data-label="r8">const struct timespec* u_abs_timeout</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">244</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mq_notify" target="_blank">
          sys_mq_notify
        </a>
      </td>
      <td data-label="rdi">mqd_t mqdes</td>
      <td data-label="rsi">const struct sigevent* u_notification</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">245</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mq_getsetattr" target="_blank">
          sys_mq_getsetattr
        </a>
      </td>
      <td data-label="rdi">mqd_t mqdes</td>
      <td data-label="rsi">const struct mq_attr* u_mqstat</td>
      <td data-label="rdx">struct mq_attr* u_omqstat</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">246</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/kexec_load" target="_blank">
          sys_kexec_load
        </a>
      </td>
      <td data-label="rdi">unsigned long entry</td>
      <td data-label="rsi">unsigned long nr_segments</td>
      <td data-label="rdx">struct kexec_segment* segments</td>
      <td data-label="r10">unsigned long flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">247</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/waitid" target="_blank">
          sys_waitid
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">pid_t upid</td>
      <td data-label="rdx">struct siginfo* infop</td>
      <td data-label="r10">int options</td>
      <td data-label="r8">struct rusage* ru</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">248</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/add_key" target="_blank">
          sys_add_key
        </a>
      </td>
      <td data-label="rdi">const char* _type</td>
      <td data-label="rsi">const char* _description</td>
      <td data-label="rdx">const void* _payload</td>
      <td data-label="r10">size_t plen</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">249</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/request_key" target="_blank">
          sys_request_key
        </a>
      </td>
      <td data-label="rdi">const char* _type</td>
      <td data-label="rsi">const char* _description</td>
      <td data-label="rdx">const char* _callout_info</td>
      <td data-label="r10">key_serial_t destringid</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">250</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/keyctl" target="_blank">
          sys_keyctl
        </a>
      </td>
      <td data-label="rdi">int option</td>
      <td data-label="rsi">unsigned long arg2</td>
      <td data-label="rdx">unsigned long arg3</td>
      <td data-label="r10">unsigned long arg4</td>
      <td data-label="r8">unsigned long arg5</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">251</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ioprio_set" target="_blank">
          sys_ioprio_set
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">int who</td>
      <td data-label="rdx">int ioprio</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">252</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ioprio_get" target="_blank">
          sys_ioprio_get
        </a>
      </td>
      <td data-label="rdi">int which</td>
      <td data-label="rsi">int who</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">253</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/inotify_init" target="_blank">
          sys_inotify_init
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">254</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/inotify_add_watch" target="_blank">
          sys_inotify_add_watch
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">const char* pathname</td>
      <td data-label="rdx">u32 mask</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">255</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/inotify_rm_watch" target="_blank">
          sys_inotify_rm_watch
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">int wd</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">256</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/migrate_pages" target="_blank">
          sys_migrate_pages
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">unsigned long maxnode</td>
      <td data-label="rdx">const unsigned long* old_nodes</td>
      <td data-label="r10">const unsigned long* new_nodes</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">257</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/openat" target="_blank">
          sys_openat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">int flags</td>
      <td data-label="r10">int mode</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">258</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mkdirat" target="_blank">
          sys_mkdirat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* pathname</td>
      <td data-label="rdx">int mode</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">259</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/mknodat" target="_blank">
          sys_mknodat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">int mode</td>
      <td data-label="r10">unsigned dev</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">260</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fchownat" target="_blank">
          sys_fchownat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">uid_t user</td>
      <td data-label="r10">gid_t group</td>
      <td data-label="r8">int flag</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">261</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/futimesat" target="_blank">
          sys_futimesat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">struct timeval* utimes</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">262</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/newfstatat" target="_blank">
          sys_newfstatat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">struct stat* statbuf</td>
      <td data-label="r10">int flag</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">263</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/unlinkat" target="_blank">
          sys_unlinkat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* pathname</td>
      <td data-label="rdx">int flag</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">264</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/renameat" target="_blank">
          sys_renameat
        </a>
      </td>
      <td data-label="rdi">int oldfd</td>
      <td data-label="rsi">const char* oldname</td>
      <td data-label="rdx">int newfd</td>
      <td data-label="r10">const char* newname</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">265</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/linkat" target="_blank">
          sys_linkat
        </a>
      </td>
      <td data-label="rdi">int oldfd</td>
      <td data-label="rsi">const char* oldname</td>
      <td data-label="rdx">int newfd</td>
      <td data-label="r10">const char* newname</td>
      <td data-label="r8">int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">266</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/symlinkat" target="_blank">
          sys_symlinkat
        </a>
      </td>
      <td data-label="rdi">const char* oldname</td>
      <td data-label="rsi">int newfd</td>
      <td data-label="rdx">const char* newname</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">267</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/readlinkat" target="_blank">
          sys_readlinkat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* pathname</td>
      <td data-label="rdx">char* buf</td>
      <td data-label="r10">int bufsiz</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">268</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fchmodat" target="_blank">
          sys_fchmodat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">mode_t mode</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">269</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/faccessat" target="_blank">
          sys_faccessat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">int mode</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">270</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pselect6" target="_blank">
          sys_pselect6
        </a>
      </td>
      <td data-label="rdi">int n</td>
      <td data-label="rsi">fd_set* inp</td>
      <td data-label="rdx">fd_set* outp</td>
      <td data-label="r10">fd_set* exp</td>
      <td data-label="r8">struct timespec* tsp</td>
      <td data-label="r9">void* sig</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">271</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/ppoll" target="_blank">
          sys_ppoll
        </a>
      </td>
      <td data-label="rdi">struct pollfd* ufds</td>
      <td data-label="rsi">unsigned int nfds</td>
      <td data-label="rdx">struct timespec* tsp</td>
      <td data-label="r10">const sigset_t* sigmask</td>
      <td data-label="r8">size_t sigsetsize</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">272</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/unshare" target="_blank">
          sys_unshare
        </a>
      </td>
      <td data-label="rdi">unsigned long unshare_flags</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">273</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/set_robust_list" target="_blank">
          sys_set_robust_list
        </a>
      </td>
      <td data-label="rdi">struct robust_list_head* head</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">274</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/get_robust_list" target="_blank">
          sys_get_robust_list
        </a>
      </td>
      <td data-label="rdi">int pid</td>
      <td data-label="rsi">struct robust_list_head** head_ptr</td>
      <td data-label="rdx">size_t* len_ptr</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">275</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/splice" target="_blank">
          sys_splice
        </a>
      </td>
      <td data-label="rdi">int fd_in</td>
      <td data-label="rsi">off_t* off_in</td>
      <td data-label="rdx">int fd_out</td>
      <td data-label="r10">off_t* off_out</td>
      <td data-label="r8">size_t len</td>
      <td data-label="r9">unsigned int flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">276</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/tee" target="_blank">
          sys_tee
        </a>
      </td>
      <td data-label="rdi">int fdin</td>
      <td data-label="rsi">int fdout</td>
      <td data-label="rdx">size_t len</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">277</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sync_file_range" target="_blank">
          sys_sync_file_range
        </a>
      </td>
      <td data-label="rdi">long fd</td>
      <td data-label="rsi">off_t offset</td>
      <td data-label="rdx">off_t bytes</td>
      <td data-label="r10">long flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">278</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/vmsplice" target="_blank">
          sys_vmsplice
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">const struct iovec* iov</td>
      <td data-label="rdx">unsigned long nr_segs</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">279</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/move_pages" target="_blank">
          sys_move_pages
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">unsigned long nr_pages</td>
      <td data-label="rdx">const void** pages</td>
      <td data-label="r10">const int* nodes</td>
      <td data-label="r8">int* status</td>
      <td data-label="r9">int flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">280</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/utimensat" target="_blank">
          sys_utimensat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">struct timespec* utimes</td>
      <td data-label="r10">int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">281</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/epoll_wait" target="_blank">
          sys_epoll_wait
        </a>
      </td>
      <td data-label="rdi">int epfd</td>
      <td data-label="rsi">struct epoll_event* events</td>
      <td data-label="rdx">int maxevents</td>
      <td data-label="r10">int timeout</td>
      <td data-label="r8">const sigset_t* sigmask</td>
      <td data-label="r9">size_t sigsetsize</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">282</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/signalfd" target="_blank">
          sys_signalfd
        </a>
      </td>
      <td data-label="rdi">int ufd</td>
      <td data-label="rsi">sigset_t* user_mask</td>
      <td data-label="rdx">size_t sizemask</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">283</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timerfd_create" target="_blank">
          sys_timerfd_create
        </a>
      </td>
      <td data-label="rdi">int clockid</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">248</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/eventfd" target="_blank">
          sys_eventfd
        </a>
      </td>
      <td data-label="rdi">unsigned int count</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">285</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/fallocate" target="_blank">
          sys_fallocate
        </a>
      </td>
      <td data-label="rdi">long fd</td>
      <td data-label="rsi">long mode</td>
      <td data-label="rdx">off_t offset</td>
      <td data-label="r10">off_t len</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">286</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timerfd_settime" target="_blank">
          sys_timerfd_settime
        </a>
      </td>
      <td data-label="rdi">int ufd</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx">const struct itimerspec* utmr</td>
      <td data-label="r10">struct itimerspec* otmr</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">287</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/timerfd_gettime" target="_blank">
          sys_timerfd_gettime
        </a>
      </td>
      <td data-label="rdi">int ufd</td>
      <td data-label="rsi">struct itimerspec* otmr</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">288</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/accept4" target="_blank">
          sys_accept4
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct sockaddr* upeer_sockaddr</td>
      <td data-label="rdx">int* upeer_addrlen</td>
      <td data-label="r10">int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">289</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/signalfd4" target="_blank">
          sys_signalfd4
        </a>
      </td>
      <td data-label="rdi">int ufd</td>
      <td data-label="rsi">sigset_t* user_mask</td>
      <td data-label="rdx">size_t sizemask</td>
      <td data-label="r10">int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">290</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/eventfd2" target="_blank">
          sys_eventfd2
        </a>
      </td>
      <td data-label="rdi">unsigned int count</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">291</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/epoll_create1" target="_blank">
          sys_epoll_create1
        </a>
      </td>
      <td data-label="rdi">int flags</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">292</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/dup3" target="_blank">
          sys_dup3
        </a>
      </td>
      <td data-label="rdi">unsigned int oldfd</td>
      <td data-label="rsi">unsigned int newfd</td>
      <td data-label="rdx">int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">293</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pipe2" target="_blank">
          sys_pipe2
        </a>
      </td>
      <td data-label="rdi">int* filedes</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">294</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/inotify_init1" target="_blank">
          sys_inotify_init1
        </a>
      </td>
      <td data-label="rdi">int flags</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">295</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/preadv" target="_blank">
          sys_preadv
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">const struct iovec* vec</td>
      <td data-label="rdx">unsigned long vlen</td>
      <td data-label="r10">unsigned long pos_l</td>
      <td data-label="r8">unsigned long pos_h</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">296</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/pwritev" target="_blank">
          sys_pwritev
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">const struct iovec* vec</td>
      <td data-label="rdx">unsigned long vlen</td>
      <td data-label="r10">unsigned long pos_l</td>
      <td data-label="r8">unsigned long pos_h</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">297</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/rt_tgsigqueueinfo" target="_blank">
          sys_rt_tgsigqueueinfo
        </a>
      </td>
      <td data-label="rdi">pid_t tgid</td>
      <td data-label="rsi">pid_t pid</td>
      <td data-label="rdx">int sig</td>
      <td data-label="r10">siginfo_t* uinfo</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">298</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/perf_event_open" target="_blank">
          sys_perf_event_open
        </a>
      </td>
      <td data-label="rdi">struct perf_event_attr* attr_uptr</td>
      <td data-label="rsi">pid_t pid</td>
      <td data-label="rdx">int cpu</td>
      <td data-label="r10">int group_fd</td>
      <td data-label="r8">unsigned long flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">299</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/recvmmsg" target="_blank">
          sys_recvmmsg
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct msghdr* mmsg</td>
      <td data-label="rdx">unsigned int vlen</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8">struct timespec* timeout</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">300</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_fanotify_init
        </a>
      </td>
      <td data-label="rdi">unsigned int flags</td>
      <td data-label="rsi">unsigned int event_f_flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">301</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_fanotify_mark
        </a>
      </td>
      <td data-label="rdi">long fanotify_fd</td>
      <td data-label="rsi">long flags</td>
      <td data-label="rdx">__u64 mask</td>
      <td data-label="r10">long dfd</td>
      <td data-label="r8">long pathname</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">302</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_prlimit64
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">unsigned int resource</td>
      <td data-label="rdx">const struct rlimit64* new_rlim</td>
      <td data-label="r10">struct rlimit64* old_rlim</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">303</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_name_to_handle_at
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">struct file_handle* handle</td>
      <td data-label="r10">int *mnt_id</td>
      <td data-label="r8">int flag</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">304</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_open_by_handle_at
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* name</td>
      <td data-label="rdx">struct file_handle* handle</td>
      <td data-label="r10">int *mnt_id</td>
      <td data-label="r8">int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">305</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_clock_adjtime
        </a>
      </td>
      <td data-label="rdi">clockid_t which_clock</td>
      <td data-label="rsi">struct time* tx</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">306</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/syncfs" target="_blank">
          sys_syncfs
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">307</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/sendmmsg" target="_blank">
          sys_sendmmsg
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct mmsghdr* mmsg</td>
      <td data-label="rdx">unsigned int vlen</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">308</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/setns" target="_blank">
          sys_setns
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">struct mmsghdr* mmsg</td>
      <td data-label="rdx">unsigned int vlen</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">309</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/getcpu" target="_blank">
          sys_getcpu
        </a>
      </td>
      <td data-label="rdi">unsigned* cpup</td>
      <td data-label="rsi">unsigned* nodep</td>
      <td data-label="rdx">struct getcpu_cache* unused</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">310</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/process_vm_readv" target="_blank">
          sys_process_vm_readv
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">const struc iovec* lvec</td>
      <td data-label="rdx">unsigned long liovcnt</td>
      <td data-label="r10">const struct iovec* rvec</td>
      <td data-label="r8">unsigned long riovcnt</td>
      <td data-label="r9">unsigned long flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">311</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/process_vm_writev" target="_blank">
          sys_process_vm_writev
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">const struct iovec* lvec</td>
      <td data-label="rdx">unsigned long liovcnt</td>
      <td data-label="r10">const struct iovcc* rvec</td>
      <td data-label="r8">unsigned long riovcnt</td>
      <td data-label="r9">unsigned long flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">312</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/kcmp" target="_blank">
          sys_kcmp
        </a>
      </td>
      <td data-label="rdi">pid_t pid1</td>
      <td data-label="rsi">pid_t pid2</td>
      <td data-label="rdx">int type</td>
      <td data-label="r10">unsigned long idx1</td>
      <td data-label="r8">unsigned long idx2</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">313</th>
      <td data-label="System Call">
        <a href="https://linux.die.net/man/2/finit_module" target="_blank">
          sys_finit_module
        </a>
      </td>
      <td data-label="rdi">int fd</td>
      <td data-label="rsi">const char* param_values</td>
      <td data-label="rdx">int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">314</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_sched_setattr
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">struct sched_attr* attr</td>
      <td data-label="rdx">unsigned int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">315</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_sched_getattr
        </a>
      </td>
      <td data-label="rdi">pid_t pid</td>
      <td data-label="rsi">struct sched_attr* attr</td>
      <td data-label="rdx">unsigned int size</td>
      <td data-label="r10">unsigned int flags</td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">316</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_renameat2
        </a>
      </td>
      <td data-label="rdi">int olddfd</td>
      <td data-label="rsi">const char* oldname</td>
      <td data-label="rdx">int newdfd</td>
      <td data-label="r10">const char* newname</td>
      <td data-label="r8">unsigned int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">317</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_seccomp
        </a>
      </td>
      <td data-label="rdi">unsigned int op</td>
      <td data-label="rsi">unsigned int flags</td>
      <td data-label="rdx">const char *uargs</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">318</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_getrandom
        </a>
      </td>
      <td data-label="rdi">char* buf</td>
      <td data-label="rsi">size_t count</td>
      <td data-label="rdx">unsigned int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">319</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_memfd_create
        </a>
      </td>
      <td data-label="rdi">const char* uname_ptr</td>
      <td data-label="rsi">unsigned int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">320</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_kexec_file_load
        </a>
      </td>
      <td data-label="rdi">int kernel_fd</td>
      <td data-label="rsi">int initrd_fd</td>
      <td data-label="rdx">unsigned long cmdline_len</td>
      <td data-label="r10">const char* cmdline_ptr</td>
      <td data-label="r8">unsigned long flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">321</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          sys_bpf
        </a>
      </td>
      <td data-label="rdi">int cmd</td>
      <td data-label="rsi">union bpf_attr* attr</td>
      <td data-label="rdx">unsigned int size</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">322</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          stub_execveat
        </a>
      </td>
      <td data-label="rdi">int dfd</td>
      <td data-label="rsi">const char* filename</td>
      <td data-label="rdx">const char* argv</td>
      <td data-label="r10">const char* envp</td>
      <td data-label="r8">int flags</td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">323</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          userfaultfd
        </a>
      </td>
      <td data-label="rdi">int flags</td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">324</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          membarrier
        </a>
      </td>
      <td data-label="rdi">int cmd</td>
      <td data-label="rsi">int flags</td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">325</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          mlock2
        </a>
      </td>
      <td data-label="rdi">unsigned long start</td>
      <td data-label="rsi">size_t len</td>
      <td data-label="rdx">int flags</td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">326</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          copy_file_range
        </a>
      </td>
      <td data-label="rdi">int fd_in</td>
      <td data-label="rsi">off_t* off_in</td>
      <td data-label="rdx">int fd_out</td>
      <td data-label="r10">off_t* off_out</td>
      <td data-label="r8">size_t len</td>
      <td data-label="r9">unsigned int flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">327</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          preadb2
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">const struct iovec* vec</td>
      <td data-label="rdx">unsigned long vlen</td>
      <td data-label="r10">unsigned long pos_l</td>
      <td data-label="r8">unsigned long pos_h</td>
      <td data-label="r9">int flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">328</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          pwritev2
        </a>
      </td>
      <td data-label="rdi">unsigned long fd</td>
      <td data-label="rsi">const struct iovec* vec</td>
      <td data-label="rdx">unsigned long vlen</td>
      <td data-label="r10">unsigned long pos_l</td>
      <td data-label="r8">unsigned long pos_h</td>
      <td data-label="r9">int flags</td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">329</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          pkey_mprotect
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">330</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          pkey_alloc
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">331</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          pkey_free
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">332</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          statx
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">333</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          io_pgetevents
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">334</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          rseq
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
    <tr>
      <th scope="row" data-label="rax">335</th>
      <td data-label="System Call">
        <a href="#" target="_blank">
          pkey_mprotect
        </a>
      </td>
      <td data-label="rdi"></td>
      <td data-label="rsi"></td>
      <td data-label="rdx"></td>
      <td data-label="r10"></td>
      <td data-label="r8"></td>
      <td data-label="r9"></td>
    </tr>
  </tbody>
</table>

# 参考资料
[linux syscall和int 80的区别](https://blog.csdn.net/bjbz_cxy/article/details/140602272)
[32 位 Linux 代码中“int 0x80”与“syscall”：系统调用方法解析](https://www.bytezonex.com/archives/kCMSUXpw.html)
[Linux32位系统调用号——奇偶排列表格方便查找](https://blog.csdn.net/qq_41202237/article/details/107249667)
[Linux64位系统调用号——奇偶排列表格方便查找](https://blog.csdn.net/qq_41202237/article/details/107250349)
[x86_64 LInux Syscall Reference | Adam Hacks](https://hackeradam.com/x86-64-linux-syscalls/)

