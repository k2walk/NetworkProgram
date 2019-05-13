import socket
import struct
import time
from new_packet_sniffer import Ethernet, ARP

eth = Ethernet()
arp = ARP()

eth.dst = '00:0c:29:46:5a:ab'
eth.src = '00:0c:29:da:a4:c2'
eth.type = 0x0806

arp.HWtype = 0x0001
arp.protocol = 0x0800
arp.HWsize = 6
arp.protoSize = 4
arp.opcode = 0x0001
arp.sendMac = '00:0c:29:da:a4:c2'
arp.sendIP = '172.16.0.142'
arp.targetMac = '00:00:00:00:00:00'
arp.targetIP = '172.16.0.144'

frame =  eth.get_header() + arp.get_header()

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
sock.bind( ('eth0',0) )

while True:
  time.sleep(1)
  sock.send( frame )

