#! /usr/bin/env python2

from fault import *
from pwn import *
from gmpy2 import *
from Crypto.Util.number import GCD

import time

def menu(r):
    for _ in xrange(8):
        r.recvline()

#r = remote("localhost", 23333)
r = remote("crypto.chal.csaw.io", 1001)
R = RSA()
e = 0x10001

menu(r)

r.sendline('3')
c1 = int(r.recvline().strip(), 16)

# get N, or rather, a multiple of it
menu(r)
r.sendline('4')
r.recvuntil("input the data:")
r.sendline("\x02")
x1 = int(r.recvline().strip(), 16)
r.sendline('4')
r.recvuntil("input the data:")
r.sendline("\x03")
x2 = int(r.recvline().strip(), 16)

N = GCD(pow(s2n("\x02"), e) - x1, pow(s2n("\x03"), e) - x2)

y = 0
p = 0
q = 0
while True:
    fake_flag = 'fake_flag{%s}' % (('%X' % y).rjust(32, '0'))
    menu(r)
    r.sendline('4')
    r.recvuntil("input the data:")
    r.sendline(fake_flag)
    c2 = int(r.recvline().strip(), 16)
    g = GCD(c1 - c2, N)
    if g != 1:
        assert is_prime(g)
        p = g
        q = N // p
        R.generate(p, q)
        break
    y += 1

menu(r)
r.sendline('1')
c = int(r.recvline().strip(), 16)
print(n2s(R.decrypt(c)))
