#! /usr/bin/env python2

from pwn import *
import random

import string

real = True

def con():
    if real:
        return remote("crypto.chal.csaw.io", 1002)
    else:
        return remote("localhost", 10002)

def c(s, l):
    for x in s:
        if l.find(x) == -1:
            return False
    return True

def xor(x, y):
    c = ""
    for (a, b) in zip(x, y):
        c += chr(ord(a) ^ ord(b))
    return c

def goodpad(s):
    assert len(s) == 16
    p = ord(s[-1])
    if p > 0 and p <= 16:
        for ch in s[-p:]:
            if ord(ch) != p:
                return False
        return True
    else:
        return False

def unpad(s):
    p = ord(s[-1])
    return s[:-p]

chars = string.digits + string.punctuation + string.letters
b = "Encrypted Flag: "

#seed = 0L
#s1 = None
#s2 = None
#while s1 == None or s2 == None:
#    random.seed(seed)
#    nums = []
#    for _ in xrange(300):
#        nums.append(random.getrandbits(32))
#
#    if s1 == None:
#        for i in xrange(100):
#            for j in xrange(100):
#                if nums[3 * i] == nums[3 * j + 1]:
#                    s1 = seed
#                    s1i = i
#                    s1j = j
#                    print "s1: {}".format((s1, s1i, s1j))
#                    break
#    if s2 == None:
#        for i in xrange(100):
#            for j in xrange(100):
#                if nums[3 * i] == nums[3 * j + 2]:
#                    s2 = seed
#                    s2i = i
#                    s2j = j
#                    print "s2: {}".format((s2, s2i, s2j))
#                    break
#    seed += 1
(s1, s1i, s1j) = (72454, 16, 35)
(s2, s2i, s2j) = (71789, 38, 15)

random.seed(s1)
p0s = []
p1s = []
p2s = []
for _ in xrange(100):
    p0s.append(random.getrandbits(32))
    p1s.append(random.getrandbits(32))
    p2s.append(random.getrandbits(32))
assert p0s[s1i] == p1s[s1j]
random.seed(s2)
p0s = []
p1s = []
p2s = []
for _ in xrange(100):
    p0s.append(random.getrandbits(32))
    p1s.append(random.getrandbits(32))
    p2s.append(random.getrandbits(32))
assert p0s[s2i] == p2s[s2j]

print int(str(s1).rjust(16, '0'))
print int(str(s2).rjust(16, '0'))

part1 = ""
part2 = ""

r = con()
r.recvline()
r.send(str(s1).rjust(16, '0'))
r.recvline()

p0s = []
p1s = []
p2s = []

for _ in xrange(100):
    # encrypted thing
    v = bytes(r.recvn(48))
    p0 = v[ 0:16]
    p1 = v[16:32]
    p2 = v[32:48]
    # newline
    r.recvn(1)
    p0s.append(xor(p0, b))
    p1s.append(p1)
    p2s.append(p2)

part1 = xor(p0s[s1i], p1s[s1j])
r.close()

r = con()
r.recvline()
r.send(str(s2).rjust(16, '0'))
r.recvline()

p0s = []
p1s = []
p2s = []

for _ in xrange(100):
    # encrypted thing
    v = bytes(r.recvn(48))
    p0 = v[ 0:16]
    p1 = v[16:32]
    p2 = v[32:48]
    # newline
    r.recvn(1)
    p0s.append(xor(p0, b))
    p1s.append(p1)
    p2s.append(p2)

part2 = xor(p0s[s2i], p2s[s2j])
r.close()

print part1 + part2
