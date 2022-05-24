#!/usr/bin/python3
from pwn import *


nbArg=len(sys.argv)
address="address"
port=22
imagepath="./binary"

startString=b"0\n"


def HeapLeak():
    data=p.recvline().decode("utf-8")
    leak=int(str(data),16)
    log.info(str(hex(leak)))
    return leak

def exploit():
    p_length=0
    if nbArg>2:
        p_length=int(sys.argv[2])
        log.info("Payload prefix length: "+str(p_length))
    p.recvuntil(startString)
    payload=p_length*b'A'
    p.sendline(payload)
    print(p.recvall(timeout=1))
    p.interactive

if __name__ == "__main__":
    if nbArg < 2:
        print("Zutth - pyton PWN sample - v0.1")
        print("    ")
        print("Usage: "+str(sys.argv[0])+" mode [p_length]")
        print("    ")
        print("    Modes:")
        print("    ")
        print("        remote   -  se connecte au serveur du chal")
        print("        debug    -  permet d'accrocher un debugger")
        print("        local    -  lance le binaire en local")
        sys.exit()

    if sys.argv[1].lower()=="debug":
        print("\033[1;33;40m ================= \033[0m\n")
        print("\033[1;33;40m    DEBUG  MODE    \033[0m\n")
        print("\033[1;33;40m ================= \033[0m\n")
        print("nb arg: "+str(nbArg))
        print("args  : "+str(sys.argv))
        elf=ELF(imagepath)
        p=elf.process()
        pid = util.proc.pidof(p)[0]
        print("Le pid est: "+"\033[1;33;40m"+str(pid)+"\033[0m\n")
        util.proc.wait_for_debugger(pid)

    if sys.argv[1].lower()=="local":
        print("\033[1;34;40m ================= \033[0m\n")
        print("\033[1;34;40m    LOCAL  MODE    \033[0m\n")
        print("\033[1;34;40m ================= \033[0m\n")
        print("[s] Chargement de "+str(imagepath))
        p=process(imagepath)
    
    if sys.argv[1].lower()=="remote":
        print("\033[1;31;40m ================= \033[0m\n")
        print("\033[1;31;40m 💀 REMOTE MODE 💀 \033[0m\n")
        print("\033[1;31;40m ================= \033[0m\n")
        p=remote(address,port)

exploit()
