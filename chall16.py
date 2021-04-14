from pwn import *

def main():
	binary = context.binary = ELF("./chall_16")
	p = process("./chall_16")
	p.sendline(binary.string(binary.sym.key))
	p.interactive()
main()
