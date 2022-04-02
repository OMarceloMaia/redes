import socket
import binascii
import os

ret =  os.system("ifconfig wlp2s0 promisc")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

bf = s.recv(2000)
h = binascii.hexlify(bf)
l = h.split(b'\n') #[ , , ]
i = int(h, 16)
b = bin(i)
print(b[2:]) #0b

ret =  os.system("ifconfig wlp2s0 -promisc")
s.close()
