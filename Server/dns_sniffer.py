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
from mydns import DNS

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(('eth0',0))

while True:
  data = raw.recv(65535)
  packet = Packet(data)
  if packet.eth.type == 0x0800 and packet.ip.protocol == 17 and ( packet.ip.dstIp == '192.168.8.143' or packet.ip.srcIp == '192.168.8.143' ) and ( packet.udp.dst_port == 53 or packet.udp.src_port == 53 ):
    dns = DNS(data[42:])
    print("********************* IP Header ********************")
    print(packet.ip.srcIp, '->', packet.ip.dstIp, packet.eth.type)
    print('version :', packet.ip.version)
    print('headerLen :', packet.ip.headerLen)
    print('typeOfService :', packet.ip.typeOfService)
    print('totLength :', packet.ip.totLength)
    print('identification :', packet.ip.identification)
    print('ipFlags :', packet.ip.ipFlags)
    print('fragmentOffset :', packet.ip.fragmentOffset)
    print('timeToLive :', packet.ip.timeToLive)
    print('protocol :', packet.ip.protocol)
    print('headerChecksum :', packet.ip.headerChecksum)
    print('srcIp :', packet.ip.srcIp)
    print('dstIp :', packet.ip.dstIp)
    print("******************** UDP Header *******************")
    print("src_port :", packet.udp.src_port)
    print("dst_port :", packet.udp.dst_port)
    print("length :", packet.udp.length)
    print("checksum :", packet.udp.checksum)
    print("data :", packet.udp.data)
    print("******************** DNS Header *******************")
    print("identification :", dns.identification)
    print("codes_and_flags :", dns.codes_and_flags)
    print("total_questions :", dns.total_questions)
    print("total_answers :", dns.total_answers)
    print("total_authority :", dns.total_authority)
    print("total_additional :", dns.total_additional)
    print("query_name :", dns.query_name)
    print("query_type :", dns.query_type)
    print("query_class :", dns.query_class)
    if ( ( dns.codes_and_flags & 0xF000 ) >> 15 )  == 1 and dns.total_answers >= 1:
      print("answer_name :", dns.answer_name)
      print("answer_type :", dns.answer_type)
      print("answer_class :", dns.answer_class)
      print("answer_ttl :", dns.answer_ttl)
      print("answer_data_length :", dns.answer_data_length)
      print("answer_address :", dns.answer_address)
#    print("raw packet :", packet.raw + dns.get_header())
