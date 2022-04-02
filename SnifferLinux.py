#!/usr/bin/env python
# -*- coding: utf-8 -*-

#programa Sniffer
import socket
import struct
import string
import binascii

# create a raw socket
# (address family,socket type, protocol number)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
''' socket.ntohs(0x0003) captures all the send & receive traffic from the network interface. '''
#verifica criação do socket
# if(s == -1):
    # print 'Não foi possível criar o socket'
# else:
    # print 'socket foi criado em ', s, ('\n')

#bind it to the public interface (qual das interfaces?wlan0, eth0, ...)
s.bind(('wlp2s0', 0x0800))

#i = 0
#while i<10:
#	i += 1
#receive a package
L = s.recv(2000)
#print(buff, type(buff),'\n')
	
#print
LL = list(L)
#print('LL = ', LL, ('\n'))
#print('ToS = ', LL[15], ('\n'))

# # fecha socket
# s.close()
#---------------------------------------------------------------------------------------------------------------

#Campos

MacDest = []
i = 0
while i <= 5:
    MacDest.append(hex(L[i]))
    i = i +1
print('MacDest = ', MacDest, ('\n'))

MacOrig = []
i = 6
while i <= 11:
    MacOrig.append(hex(L[i]))
    i = i +1
print('MacOrig = ', MacOrig, ('\n'))

# abaixo, eh como join() que retorna dupla. por isto pega o 1o. elemento com [0]
TipoIP = hex(socket.ntohs(struct.unpack('H', L[12:14])[0]))
print('TipoProt = ', TipoIP, ('\n'))

#inicio cabecalho IP
print('[Byte de inicio do cabecalho IP = ', 14, (']\n'))

versao = L[14] >> 4
print('versao = ', versao, ('\n'))

IpHdrLen = L[14] & 0x0f
print('IpHdrLen = ', IpHdrLen, ('\n'))

ToS = L[15]
print('ToS = ', ToS, ('\n'))

comprimentoTotal = socket.ntohs(struct.unpack('H', L[16:18])[0])
print('Tamanho do Datagrama = ', comprimentoTotal, ('\n'))

id = socket.ntohs(struct.unpack('H', L[18:20])[0])
print('identificacao = ', id, ('\n'))

flags = (L[20] & 0xe0) >> 5
print('flagsIP = ', bin(flags), ('\n'))

offsetFragmento = socket.ntohs(struct.unpack('H', L[20:22])[0] & 0x1f)
print('fragment_offset = ', offsetFragmento, ('\n'))

TTL = L[22]
print('TTL = ', TTL, ('\n'))

protocolo = L[23]
print('Protocolo = ', protocolo, ('\n'))

verifica = socket.ntohs(struct.unpack('H', L[24:26])[0])
print('checksum = ', verifica, ('\n'))

EndOrigem = socket.inet_ntoa(struct.unpack('4s', L[26:30])[0])
print('Endereco de Origem = ', EndOrigem, ('\n'))

EndDestino = socket.inet_ntoa(struct.unpack('4s', L[30:34])[0])
print('Endereco de Destino = ', EndDestino, ('\n'))

if IpHdrLen > 5:
    opcoes = L[34:(34 + 4*(IpHdrLen - 5))]
else:
    opcoes = None
    print('Nao ha opcoes IP', ('\n'))

#inicio Protocolo de Transporte
IPT = 14 + 4*(IpHdrLen)
print('[Byte de inicio do cabecalho de transporte = ', IPT, (']\n'))

if protocolo == 6:

    portaOrigem = socket.ntohs(struct.unpack('H', L[IPT:IPT+2])[0])
    print('Porta de Origem = ', portaOrigem, ('\n'))
    portaDestino = socket.ntohs(struct.unpack('H', L[IPT+2:IPT+4])[0])
    print('Porta de Destino = ', portaDestino, ('\n'))

    numeroSeq = socket.ntohl(struct.unpack('!L', L[IPT+4:IPT+8])[0])
    print('Numero de Sequencia = ', numeroSeq, ('\n'))

    numeroConf = socket.ntohl(struct.unpack('!L', L[IPT+8:IPT+12])[0])
    print('Numero de Ack = ', numeroConf, ('\n'))

    TcpHdrLen = L[IPT+12] & 0xf0 >> 4
    print('TcpHdrLen = ', TcpHdrLen, ('\n'))

    Reservado = (L[IPT+12] & 0x0f) << 2 + (L[IPT+13] & 0x0f << 2)
    print('Reservado = ', Reservado, ('\n'))

    flags = L[IPT+13] & 0x3f
    y = bin(flags)
    yy = y[2:]
#    print 'yy = ', yy, ('\n')

    print('flagsTCP = UAPRSF')
    print('flagsTCP = ', yy, ('\n'))

    RxWindow = socket.ntohs(struct.unpack('H', L[IPT+14:IPT+16])[0])
    print('RxWindow = ', RxWindow, ('\n'))

    TcpChk = socket.ntohs(struct.unpack('H', L[IPT+16:IPT+18])[0])
    print('TcpChk = ', TcpChk, ('\n'))

    PontUrg = socket.ntohs(struct.unpack('H', L[IPT+18:IPT+20])[0])
    print('PontUrg = ', PontUrg, ('\n'))

    #inicio dos dados
    StartDataT = IPT + 4*(TcpHdrLen)
    print('[inicio dos dados (tcp) =', StartDataT, (']\n'))

    #Comprimento dos dados
    compT = comprimentoTotal - (4 * IpHdrLen) - (4 * TcpHdrLen)
    scT = str(compT)+'s'
    print('tamanho dos dados = ', scT, ('\n'))

    if TcpHdrLen > 5:
        opcoes = L[IPT+20:StartDataT]
        print('Options = ', binascii.hexlify(opcoes), ('\n'))
    else:
        opcoes = None
        print('Nao ha opcoes TCP', ('\n'))

    #Dados]
    DataTCP = L[StartDataT:]
    #DataTCP = socket.ntohs(struct.unpack(scT, S[StartDataT:StartDataT + compT]) [0])
    print('Dados TCP = ', binascii.hexlify(DataTCP), ('\n'))

elif protocolo == 17:
    portaOrigem = socket.ntohs(struct.unpack('H', L[IPT:IPT+2])[0])
    print('Porta de Origem = ', portaOrigem, ('\n'))

    portaDestino = socket.ntohs(struct.unpack('H', L[IPT+2:IPT+4])[0])
    print('Porta de Destino = ', portaDestino, ('\n'))

    UdpLen = socket.ntohs(struct.unpack('H', L[IPT+4:IPT+6])[0])
    print('UdpLen = ', UdpLen, ('\n'))

    DataLen = UdpLen - 8
    print('Tamanho dos Dados = ', DataLen, ('\n'))

    UdpChk = socket.ntohs(struct.unpack('H', L[IPT+6:IPT+8])[0])
    print('UdpChk = ', UdpChk, ('\n'))

    #inicio dos dados
    StartDataU = IPT + 8
    print('[inicio dos dados (udp) =', StartDataU, (']\n'))

    FimDados = StartDataU + DataLen
    print('Fim dos dados = ', FimDados, ('\n'))

    DataUDP = L[StartDataU:]
    print('Dados UDP = ', binascii.hexlify(DataUDP), ('\n'))

# fecha socket
s.close()