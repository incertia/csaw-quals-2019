#! /usr/bin/env python2

from supercurve import *

from pwn import *

curve = SuperCurve(
    field = 14753, order = 7919,
    a = 1, b = -1, g = (1, 1),
)

r = remote("crypto.chal.csaw.io", 1000)
r.recvuntil('(')
x = int(r.recvuntil(',')[:-1])
r.recvuntil(' ')
y = int(r.recvuntil(')')[:-1])
r.recvline()
r.recvline()

base = curve.g
sec = None
for e in xrange(curve.order):
    if curve.mult(e, base) == (x, y):
        sec = e
        break

assert sec != None
r.sendline(str(sec))
print r.recvline().strip()
