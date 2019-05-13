import socket
import struct
import time
from new_packet_sniffer import Ethernet, IP, ICMP, Echo, UDP

def make_chksum( header ):
  size = len(header)
  if size % 2:
    header += b'\x00'
    size += 1

  size //= 2
  header = struct.unpack('!' + str(size) + 'H', header)
  chksum = sum(header)
  carry = chksum >> 16
  chksum = chksum & 0xFFFF
  chksum += carry
  chksum = chksum ^ 0xFFFF
  return chksum

eth = Ethernet()
ip = IP()
udp = UDP()

eth.dst = 'ff:ff:ff:ff:ff:ff'
eth.src = '00:0c:29:da:a4:c2'
eth.type = 0x0800

ip.version = 4
ip.headerLen = 20
ip.typeOfService = 0
ip.totLength = 0
ip.identification = 1004
ip.ipFlags = 2
ip.fragmentOffset = 0
ip.timeToLive = 64
ip.protocol = 17
ip.headerChecksum = 0
ip.srcIp = '8.8.8.8'
ip.dstIp = '8.8.8.8'

ip.headerLen = len(ip.get_header())
ip.totLength = len(ip.get_header()) + len(icmp.get_header())
ip.headerChecksum = make_chksum( ip.get_header() )

udp.src_port = 10
udp.dst_port = 22223
udp.length = 8
udp.checksum = 0
udp.data = 'hello'

pseudo_header = ip._srcIp + ip._dstIp + b'\x00' + ip._protocol + udp.length + udp.get_header()
udp.checksum = make_chksum( pseudo_header )

packet = eth.get_header() + ip.get_header() + udp.get_header()

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003) )
sock.bind( ('eth0',0) )

while True:
  time.sleep(1)
  sock.send( packet )

