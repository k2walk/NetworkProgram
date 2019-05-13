import socket
import struct

raw = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP )
raw.bind( ('0.0.0.0', 0) )

while True:
  data, host = raw.recvfrom(65535)
  if host[0] == '100.100.100.112':
    ip = data[:20]
    tcp = data[20:]
    print("HOST:",host)
    print("IP:",ip)
    print("TCP:",tcp)
    print("")
