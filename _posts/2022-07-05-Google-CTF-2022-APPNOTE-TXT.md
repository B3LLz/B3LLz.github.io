---
layout: post
title: "Google CTF 2022 - APPNOTE.TXT"
author: "B3LLz"
tags: write-up
---
# Google CTF 2022 - APPNOTE.TXT

# APPNOTE.TXT - 50pt (misc)

**Every single archive manager unpacks this to a different file...**

---

주어진 파일은 `dump.zip`이며 압축해제를 할 시 하나의 텍스트 파일만이 나오는 상태이다.

![Untitled](/images/appnote1.png)

# PKZIP 구조 및 압축해제 프로세스

![Untitled](/images/appnote2.png)

ZIP 파일의 압축해제 프로세스는 다음과 같다.

1. 최초 실행 시 `End of Central Directory`로 이동한다.
2. `End of Central Directory`에서 정보를 읽는다.
3. `End of Central Directory`에서 찾은 정보로 `Central Directory`의 주소로 이동한다.
4. `Central Directory`에서 정보를 읽는다.
5. `End of Central Directory`에서 `Central Directory`의 개수만큼 반복하여 `End of Central Directory` 전까지 읽는다.
6. `Central Directory`에서 읽은 `Local Header`의 주소로 접근하여 해당하는 파일을 압축해제 한다.

위의 압축해제 프로세스에 따라 APPNOTE.TXT의 문제에 접근해보겠다.

## End of Central Directory

ZIP 파일을 압축해제 할 때 처음으로 접근하는 곳이며 Signature는 `50 4B 05 06`이다.

![Untitled](/images/appnote3.png)

박스 안에 있는 부분이 `Central Directory`의 시작 주소를 가리킨다.

## Central Directory

`End of Central Directory`에서 읽은 정보를 통해 접근되어지는 주소이며 Signature는 `50 4B 01 02`이다.

![Untitled](/images/appnote4.png)

박스 안에 있는 값은 `Local Header`의 주소를 나타낸다. `Local Header`에는 압축해제 하고자 하는 파일 정보가 들어 있다.

## Local Header

압축해제 하고자 하는 실제 파일의 정보가 들어있는 부분이며 Signature는 `50 4B 03 04`이다.

![Untitled](/images/appnote5.png)

`Local Header`를 보면 파일의 내용과 파일 제목을 볼 수 있다.

# Solve

주어진 zip 파일을 보면 `End of Central Directory`에 해당하는 Signature가 여러개 존재하는 것을 확인할 수 있다. 여러개의 `End of Central Diretory`의 정보를 통해 이에 해당하는 파일의 내용을 알 수 있다.

![Untitled](/images/appnote6.png)

## parsing code

```python
from pathlib import Path
from pwn import *

END_OF_CTR_SIG = b"\x50\x4B\x05\x06"

class Parse_Zipfile:
    def __init__(self):
        self.p = Path("./dump.zip")
        self.data = self.p.read_bytes()
        self.ctr_dir_ls = []
    
    def End_of_Central_Dir(self):
        end_ctr_dir = self.data.split(END_OF_CTR_SIG)[1:]
        for i in range(len(end_ctr_dir)):
            self.ctr_dir_ls.append(end_ctr_dir[i][-6:-2])
    
    def Central_Dir(self):
        for i in self.ctr_dir_ls:
            offset = u32(i)
            print(chr(self.data[offset-1]), end='')
            

if __name__ == "__main__":
    pZip = Parse_Zipfile()

    pZip.End_of_Central_Dir()
    pZip.Central_Dir()
```

FLAG : `CTF{p0s7m0d3rn_z1p}`

> Reference
PKZIP 구조:  [https://jmoon.co.kr/48](https://jmoon.co.kr/48)
>
