import socket
			    #IPv4           #UDP
serverSock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )

serverSock.bind( ( '192.168.0.102', 22223 ) )

while True:
  data, client = serverSock.recvfrom(1500)
  print("recv:", client )
  data =  data.split(b'\n')
  data = data[0]
  if not data.isdigit():
    print("invalid value")
    serverSock.sendto(b'input error', client)
    continue

  data = int(data.decode())
  data = data * 24 * 60 * 60
  print("data:", data)
  serverSock.sendto( str(data).encode(), client)
