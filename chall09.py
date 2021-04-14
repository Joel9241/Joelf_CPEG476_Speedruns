from pwn import *
def main():
	binary = context.binary = ELF("./chall_09")
	p = process("./chall_09")
	p.sendline(xor(binary.string(binary.sym.key), bytes.fromhex("30")))
	p.interactive()
main()
