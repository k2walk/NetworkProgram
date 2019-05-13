import socket
import struct
import time
from new_packet_sniffer import Ethernet, IP, ICMP, Echo, TCP, Packet

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

eth = Ethernet()
ip = IP()
tcp = TCP()

ip.version = 4
ip.headerLen = 0
ip.typeOfService = 0
ip.totLength = 0
ip.identification = 24742
ip.ipFlags = 0
ip.fragmentOffset = 0
ip.timeToLive = 64
ip.protocol = 6
ip.headerChecksum = 0
ip.srcIp = '192.168.0.25'
ip.dstIp = '192.168.0.26'

tcp.src_port = 22222
tcp.dst_port = 55555
tcp.seq_num = 12345678
tcp.ack_num = 0
tcp.offset = 0
tcp.flags = 2
tcp.rsv = 0
tcp.window = 65535
tcp.checksum = 0
tcp.urg = 0

tcp.offset = len(tcp.get_header())
ip.headerLen = len(ip.get_header())
ip.totLength = len(ip.get_header() + tcp.get_header())
ip.headerChecksum = make_chksum( ip.get_header() )

tcp_totLength = (ip.totLength - ip.headerLen)
tcp_totLength_Byte = struct.pack('!H', tcp_totLength)
pseudo_header = ip._srcIp + ip._dstIp + b'\x00' + ip._protocol + tcp_totLength_Byte + tcp.get_header()
tcp.checksum = make_chksum( pseudo_header )

eth.src = '00:0c:29:da:a4:c2'
eth.dst = '50:6a:03:af:27:98'
eth.type = 0x0800

packet = eth.get_header() + ip.get_header() + tcp.get_header()

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
sock.bind( ('eth0',0) )

#sock.send( packet )
#data, client = sock.recvfrom(65535)
#print( data[42:].decode(errors='ignore') )

#data = data[0]

#i = 1 
#while True:
#  time.sleep(1)
sock.send( packet )
#  data = sock.recv(65535)
 # print(data)
#  print("len",len(data))
#  print( i )
#  print( packet )
#  i += 1

# Find SYN-ACK
while True:
  response = sock.recv( 65535 )
  packet = Packet ( response )
  if packet.eth.type == 0x0800 and packet.ip.protocol == 6:
    if packet.tcp.ack_num == 12345679:
      print( "-------------------- SYN-ACK Received ----------------------" )
      print( packet.raw )
      print( packet.eth.src, '->', packet.eth.dst, packet.eth.type )
      print( str(packet.ip.srcIp) + ':' + str(packet.tcp.src_port), '->',
             str(packet.ip.dstIp) + ':' + str(packet.tcp.dst_port),
             str(packet.tcp.seq_num) + '|' + str(packet.tcp.ack_num), packet.tcp.flags )
      print()

      ip.headerChecksum = 0
      tcp.checksum = 0
#      tcp.offset = 0
#      ip.totLength = 0
#      ip.headerChecksum = 0
#      tcp_totLength = 0

      tcp.seq_num = packet.tcp.ack_num
      tcp.ack_num = packet.tcp.seq_num + 1
      tcp.flags = 16

      #tcp.offset = len(tcp.get_header())
      print("TCP H :", len(tcp.get_header()))
      print("TCP Offset :", tcp.offset)
      #ip.headerLen = len(ip.get_header())
      ip.totLength = len(ip.get_header() + tcp.get_header())
      ip.headerChecksum = make_chksum( ip.get_header() )

      tcp_totLength = (ip.totLength - len(ip.get_header()))
      tcp_totLength_Byte = struct.pack('!H', tcp_totLength)
      pseudo_header = ip._srcIp + ip._dstIp + b'\x00' + ip._protocol + tcp_totLength_Byte + tcp.get_header()
      tcp.checksum = make_chksum( pseudo_header )
      
      ack_packet = eth.get_header() + ip.get_header() + tcp.get_header()
      packet = Packet(ack_packet)
      sock.send( ack_packet )
      print( "------------------------ ACK Send -------------------------" )
      print( packet.raw )
      print( packet.eth.src, '->', packet.eth.dst, packet.eth.type )
      print( str(packet.ip.srcIp) + ':' + str(packet.tcp.src_port), '->',
             str(packet.ip.dstIp) + ':' + str(packet.tcp.dst_port),
             str(packet.tcp.seq_num) + '|' + str(packet.tcp.ack_num), packet.tcp.flags )
      print()
      print("TCP H :", len(tcp.get_header()))
      print("TCP Offset :", tcp.offset)

      break

# Send ACK

