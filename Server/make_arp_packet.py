import socket
import struct
from new_packet_sniffer import Ethernet, ARP

eth = Ethernet()
arp = ARP()

eth.dst = '00:0c:29:46:5a:ab'
eth.src = '00:0C:29:DA:A4:C2'
eth.type = 0x0806

arp.hw_type = 0x0001
arp.proc_type = 0x0800
arp.hw_size = 6
arp.proc_size = 4
arp.opcode = 0x0001
arp.smac = '00:0C:29:DA:A4:C2'
arp.sip = '100.100.100.103'
arp.dmac = '00:00:00:00:00:00'
arp.dip = '100.100.100.112'

frame =  eth.get_header() + arp.get_header()

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
sock.bind( ('eth0',0) )

sock.send( frame )
