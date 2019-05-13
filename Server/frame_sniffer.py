import socket
import struct

raw = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons( 0x0003 ) )
raw.bind( ('eth0', 0) )
while True:
  eth_frame = raw.recv(65535)
  eth_frame = eth_frame[:14]
  view = struct.unpack('!BBBBBBBBBBBBH', eth_frame[:14])
  print(eth_frame)
  print(view)
  print("")
