import socket

udp_socket = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
udp_socket.bind( ('0.0.0.0', 0) )

while True:
  data, host = udp_socket.recvfrom(65535)
  ip = data[:20]
  udp = data[20:]
  if host[0] == '192.168.3.149' or host[0] == '192.168.3.43':
    ip = data[:20]
    udp = data[20:]
    print("IP:", ip)
    print("UDP:", udp)
    print('')
