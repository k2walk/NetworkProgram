import socket
import struct
from new_packet_sniffer import Ethernet
from new_packet_sniffer import ARP

class Packet:

  def __init__(self, raw):
   self._raw = raw
   self._eth = Ethernet(raw[:14])
   self._arp = ARP(raw[:42])

  @property
  def raw(self):
    return self._raw

  @property
  def eth(self):
    return self._eth

  @property
  def arp(self):
    return self._arp

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(('eth0',0))

while True:
  data = raw.recv(65535)
  packet = Packet(data)
  if packet.eth.type == 0x0806:
    print(packet.eth.src,'->', packet.eth.dst, packet.eth.type)
    print('hw_type =', packet.arp.hw_type)
    print('proc_type =', packet.arp.proc_type)
    print('hw_size =', packet.arp.hw_size)
    print('proc_size =', packet.arp.proc_size)
    print('opcode =', packet.arp.opcode)
    print('smac =', packet.arp.smac)
    print('sip =', packet.arp.sip)
    print('dmac =', packet.arp.dmac)
    print('dip =', packet.arp.dip)
    print("eth =", packet.eth)
    print("arp =", packet.arp)
    print("raw =", packet.raw)

