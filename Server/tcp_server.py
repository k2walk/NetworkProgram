#!python3
import socket

serverSock = socket.socket( socket.AF_INET, socket.SOCK_STREAM ) 
#serverSock.bind( ('172.16.0.141', 9040) )
serverSock.bind( ('192.168.0.102', 9040) )
serverSock.listen()

while True:
  clientSock, info = serverSock.accept()
  print("connection:", info[0])
  data = clientSock.recv(1500)
  data = data.decode()
  data = data.split('\n')
  data = int(data[0])

  sec = data * 24 * 60 * 60
  clientSock.send(str(sec).encode())
  print(data)
  clientSock.close()
