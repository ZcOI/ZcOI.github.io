from pwn import*
p=remote('',)
# gdb.attach(p)
# p=process('')
payload=b'a'* + p32()
p.sendline(payload)
p.interactive()
