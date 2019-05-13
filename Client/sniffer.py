import socket
import struct
from new_packet_sniffer import Ethernet
from new_packet_sniffer import ARP
from new_packet_sniffer import IP
from new_packet_sniffer import ICMP
from new_packet_sniffer import Echo

class Packet:

  def __init__(self, raw):
   self._raw = raw
   self._eth = Ethernet(raw[:])
   self._arp = ARP(raw[:])
   self._ip = IP(raw[:])
   self._echo = Echo(raw[34:])

  @property
  def raw(self):
    return self._raw

  @property
  def eth(self):
    return self._eth

  @property
  def arp(self):
    return self._arp

  @property
  def ip(self):
    return self._ip

  @property
  def echo(self):
    return self._echo

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(('eth0',0))

while True:
  data = raw.recv(65535)
  packet = Packet(data)
  if packet.eth.type == 0x0800 and packet.ip.protocol == 1:
    print("********************* IP Header ********************")
    print(packet.ip.srcIp, '->', packet.ip.dstIp, packet.eth.type)
    print('versionLen =', packet.ip.versionLen)
    print('version =', packet.ip.version)
    print('headerLen =', packet.ip.headerLen)
    print('typeOfService =', packet.ip.typeOfService)
    print('totLength =', packet.ip.totLength)
    print('identification =', packet.ip.identification)
    print('flagOffset =', packet.ip.flagOffset)
    print('ipFlags =', packet.ip.ipFlags)
    print('fragmentOffset =', packet.ip.fragmentOffset)
    print('timeToLive =', packet.ip.timeToLive)
    print('protocol =', packet.ip.protocol)
    print('headerChecksum =', packet.ip.headerChecksum)
    print('srcIp =', packet.ip.srcIp)
    print('dstIp =', packet.ip.dstIp)
    print("******************** ICMP Header *******************")
    print('type =', packet.echo.type)
    print('code =', packet.echo.code)
    print('chksum =', packet.echo.chksum)
    print('id =', packet.echo.id)
    print('seq =', packet.echo.seq)
    print('payload =', packet.echo.payload)
