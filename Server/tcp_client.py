import socket

host = '192.168.0.26'
port = 55555

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect( (host, port) )

day = input("input: ")
sock.send( day.encode() )
sec = sock.recv(1500)
print(sec.decode())

