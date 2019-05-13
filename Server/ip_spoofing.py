import socket
import struct
import time
import random
from new_packet_sniffer import Ethernet, IP, ICMP, Echo, TCP

i = 0
while True:

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
      chksum = chksum + carry
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
  ip.srcIp = '172.16.0.143'
  ip.dstIp = '172.16.0.144'

  a, b, c, d = random.randrange(1,255), random.randrange(1,255), random.randrange(1,255), random.randrange(1,255)
  ip.srcIp = '%d.%d.%d.%d' % (a,b,c,d)

  tcp.src_port = 22223
  tcp.dst_port = 12345
  tcp.seq_num = 1
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

#i = 0
#while True:
  time.sleep(1)
#  packet = eth.get_header() + ip.get_header() + tcp.get_header()
  sock.send( packet )
#  data = sock.recv(65535)
 # print(data)
#  print("len",len(data))
  print(i)
  i += 1

