# http
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect( ('192.168.8.202', 80) )

request = "TRACE /index.html HTTP/1.1\r\n"
request += "HOST: 192.168.8.143\r\n"
request += "\r\n"

sock.send( request.encode() )
response = sock.recv(65535)
print(response.decode())
