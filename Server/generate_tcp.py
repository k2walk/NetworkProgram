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
ip.identification = 36488
ip.ipFlags = 2
ip.fragmentOffset = 0
ip.timeToLive = 64
ip.protocol = 6
ip.headerChecksum = 0
ip.srcIp = '192.168.0.25'
ip.dstIp = '192.168.0.26'

tcp.src_port = 50614
tcp.dst_port = 55555
tcp.seq_num = 969597854
tcp.ack_num = 1591845183
tcp.offset = 0
tcp.flags = 24
tcp.rsv = 0
tcp.window = 229
tcp.checksum = 0
tcp.urg = 0
tcp.data = 'hello'

tcp.offset = len(tcp.get_header())
ip.headerLen = len(ip.get_header())
ip.totLength = len(ip.get_header() + tcp.get_header())
ip.headerChecksum = make_chksum( ip.get_header() )

tcp_totLength = (ip.totLength - ip.headerLen)
tcp_totLength_Byte = struct.pack('!H', tcp_totLength)
pseudo_header = ip._srcIp + ip._dstIp + b'\x00' + ip._protocol + tcp_totLength_Byte + tcp.get_header()
tcp.checksum = make_chksum( pseudo_header )

eth.src = '00:0c:29:3b:f8:5b'
eth.dst = '00:0c:29:da:a4:c2'
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
data = sock.recv(65535)
print(data)

