import socket
import struct

raw = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.htons( 0x0003 ) )
raw.bind( ('eth0', 0) )
while True:
  data = raw.recv(65535)
  print("raw:", data)
  data = data[34:]
  view = struct.unpack('!HHLLBBHHH',data[:20])
  print(view)

#    print("host:", host)
#    print("raw:", data)
#    view = struct.unpack('!HHLLBBHHH',data[:20])
#    print(view)

#    src, dst, hdr_len, chk = struct.unpack('!4H', data[:8])
#    (payload,) = struct.unpack('!' + str(hdr_len-8) + 's', data[8:])
#    print(src, '->', dst)
#    print("data:", payload.decode())
