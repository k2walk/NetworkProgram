import socket
# Find SYN-ACK
while True:
  response = sock.recv( 65535 )
    packet = Packet ( response )
    if packet.eth.ptye == 0x0800 and packet.ip.type == 6:
      if packet.tcp.ack == 0x12345679:
        print( packet.raw )
        print( packet.eth.src, '->', packet.eth.dst, packet.eth.type )
        print( str(packet.ip.src) + ':' + str(packet.tcp.src), '->',
               str(packet.ip.dst) + ':' + str(packet.tcp.dst),
               str(packet.tcp.seq) + '|' + str(packet.tcp.ack), packet.tcp.flag )
        print()
        break

# Send ACK
