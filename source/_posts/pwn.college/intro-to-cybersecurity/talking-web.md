---
title: talking-web
date: 2024-07-25 11:30:44
category: pwn.college
tags:
---

# HTTP报文
## 格式
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

# Send an HTTP request
## curl
```sh
curl 127.0.0.1:80
```

## nc
```sh
nc 127.0.0.1 80
GET / HTTP/1.1
```

输入完GET这一行后，输入两个换行即可发送

## python
```python
import requests

url = "http://127.0.0.1:80"

response = requests.get(url)

print(response.content)
```

# Set the host header in an HTTP request
## curl
```sh
curl 127.0.0.1:80 -H host:1c61bf39a9545b12f6fe638081f14f5c
```

## nc
```sh
nc 127.0.0.1 80
GET / HTTP/1.1
Host: c3b1fc17a0766e184c9af77b59799187
```

## python
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

# Set the path in an HTTP request
## curl
```sh
curl 127.0.0.1:80/756549fa99c1d39df50fa0dbc7001b5b
```

## nc
```sh
nc 127.0.0.1 80
GET /dff70448ab02fa153e53c321d12c3e25 HTTP/1.1
```

## python
```python
import requests

url = "http://127.0.0.1:80/be21ae3ca3c57337269c87354f7fb58a"

response = requests.get(url)

print(response.content)
```

# URL encode a path in an HTTP request
## curl
```sh
curl 127.0.0.1:80/468d0524%20a0f46d01/13a2115f%2045f6bf42
```

## nc
```sh
nc 127.0.0.1 80
GET /e834594f%20d12bbc07/45b1bdd9%2077ad1aa4 HTTP/1.1
```

## python
```python
import requests
from urllib.parse import quote

base_url = "http://127.0.0.1:80"
path = "/e1467bf6 1173372a/0d30c414 6d22c249"
url = base_url + quote(path)

response = requests.get(url)

print(response.content)
```

# Specify an argument in an HTTP request
## curl
```sh
curl 127.0.0.1:80/?a=21c2593a91c22ea996d92149d6ee1310
```

## nc
```sh
nc 127.0.0.1 80
GET /?a=0c59ad68454000d755026a99dadaa303 HTTP/1.1
```

## python
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

# Specify multiple arguments in an HTTP request
## curl
```sh
curl -v -G --data-urlencode 'a=b40ff87c1dfc9445e66bd1dffd31ecf3' --data-urlencode 'b=e9e53eab 8cccb234&d985bc70#d49f0c63' 127.0.0.1:80
```

## nc
```sh
nc 127.0.0.1 80
GET /?a=01df1fb634dda7a5f27c6c54d072b51d&b=de8950c2%20d91fa17a%2678fc768c%23e848a330 HTTP/1.1
```

## python
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

# Include form data in an HTTP request
## curl
```sh
curl 127.0.0.1:80 -d "a=d59caa292e43dd969de6c0d6adebd053"
```

## nc
```sh
nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

a=0a849ab7d1b57ed2f864880911873622
```
如果在输入请求数据前nc就已经发送请求包了，请检查你有没有写对请求头的Host、Content-Type、Content-Length部分

## python
```python
import requests

url = "http://127.0.0.1:80"
a = 'ab3f0e720c694b54bf8fb2e2c4e6c6f5'
data = {'a':a}

response = requests.post(url,data)

print(response.content)
```

# Include form data with multiple fields in an HTTP request
## curl
```sh
curl 127.0.0.1:80 -d "a=a4431e83e83cae7723c24b83f465475e" --data-urlencode "b=6100a2f0 e8809d07&587a0ea8#9b1109cd"
```

## nc
```sh
nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

a=b0f2f1b6f49b2896213fb29b3b93a1ef&b=57792821%20bc13e5dc%261426d3c1%23972f7bb8
```

## python
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

# Include json data in an HTTP request
## curl
```sh
curl 127.0.0.1:80 -H 'Content-Type:application/json' -d '{"a":"547135c945b35920ab6b764faba0467c"}'
```

## nc
```sh
nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 40

{"a":"506924275dda4823072f030cb9e36878"}
```

## python
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

# Include complex json data in an HTTP request
## curl
```sh
curl 127.0.0.1:80 -H 'Content-Type:application/json' -d '{"a":"afb674d6a6635008d8f123b6db1c7fe1","b":{"c":"eaa06025","d":["f3e76d78","8897c850 15e64e19&86faa062#707120a5"]}}'
```

## nc
```sh
nc 127.0.0.1 80
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 116

{"a":"e0e3ffb1ea8c041f948fd4a52b8b03ef","b":{"c":"07027b1c","d":["9caee2fb","40d89ef2 c4b79a11&7fa007c8#ccf64a5f"]}}
```

## python
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

# Follow an HTTP redirect from HTTP response
## curl
```sh
curl 127.0.0.1:80 -L
```
-L 表示跟踪重定向

## nc
```sh
nc 127.0.0.1 80
GET / HTTP/1.1

nc 127.0.0.1 80
GET /8987117b1c7a13a67e6ebdab1040b023 HTTP/1.1
```

## python
```python
import requests

url = "127.0.0.1:80"

# requests 默认进行重定向，如果不想重定向，加上allow_redirects=False参数
response = requests.get(url)

print(response.content)
```

# Include a cookie from HTTP response
## curl
```sh
curl 127.0.0.1:80 -v

curl 127.0.0.1:80 --cookie "cookie=b0a72e415cbb83c7d2671097074329c0"
```

## nc
```sh
nc 127.0.0.1 80
GET / HTTP/1.1

nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: cookie=4203ce2d43f46581fe45652da89f9310
```

## python
```python
import requests

url = "http://127.0.0.1:80"

with requests.Session() as s:
    r = s.get(url)
    print(r.content)

```

# Make multiple requests in response to stateful HTTP responses
## curl
```sh
curl 127.0.0.1:80 -v
curl 127.0.0.1:80 --cookie "session=eyJzdGF0ZSI6MX0.ZqI1lw.eBOyNFmp0kEvgn4a1KTi6--ZyvE" -v
curl 127.0.0.1:80 --cookie "session=eyJzdGF0ZSI6Mn0.ZqI1vA.zPh9QlVY-OvqFsXUk6IvcmafTBU" -v
curl 127.0.0.1:80 --cookie "session=eyJzdGF0ZSI6M30.ZqI2AQ.71jPgAYQa35fYtKd79FZU9l2Omg" -v
```

## nc
```sh
nc 127.0.0.1 80
GET / HTTP/1.1

nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6MX0.ZqI20w.GYw4a8ICn5uSqs2EPgpS6VPwfmE

nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6Mn0.ZqI4EA.ZyJQGgplU-tBR8ZmkGnhwt9-fWE

nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6M30.ZqI4NA.G_jGq5vQx6fd2HY3SgqzG95ZXo4
```

## python
```python
import requests

url = "http://127.0.0.1:80"

with requests.Session() as s:
    r = s.get(url)
    print(r.content)
```