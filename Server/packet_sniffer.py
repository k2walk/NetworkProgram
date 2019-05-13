import socket
import struct
class Ethernet:

  def __init__( self, dst=None, src=None, eth_type=None ):

    if type(dst) == str or type(src) == str:
      if '-' in dst: dst = dst.split('-')
      elif ':' in dst: dst = dst.split(':')
      
      if '-' in src: src = src.split('-')
      elif ':' in src: src = src.split(':')

    if type(dst) != bytes or type(src) != bytes:
      if dst != None:
        dst = ''.join(dst)
        dst = bytes.gromhex(dst)
      elif src != None:
        src = ''.join(src)
        src = bytes.fromhex(src)

    self._src = src
    self._dst = dst
    self._type = eth_type

  @property
  def dst(self):
    dst = struct.unpack('!BBBBBB', self._dst )
    return '%02x:%02x:%02x:%02x:%02x:%02x' % dst

  @property
  def src(self):
    src = struct.unpack('!BBBBBB', self._src )
    return '%02x:%02x:%02x:%02x:%02x:%02x' % src

  @property
  def type(self):
    type = struct.unpack('!H', self._type )
    return '0x%04x' % type

raw = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons( 0x0003 ) )
raw.bind( ('eth0', 0) )

data = raw.recv(65535)
data = data[:14]
view = struct.unpack('!BBBBBBBBBBBBH', data[:14])

print(data)
print(view)
print("")

