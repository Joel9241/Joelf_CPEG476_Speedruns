from pwn import *
from ctypes import *

def main():
	binary = context.binary = ELF("./chall_17")
	p = process("./chall_17")
	libc = cdll.LoadLibrary("libc.so.6")
	libc.srand(libc.time(None))
	p.sendline(str(libc.rand()))
	print(p.recv())
main()
