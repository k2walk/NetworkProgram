#! python3
import struct

seq = input()
print(seq)
#seq = seq[2:len(seq)-1].encode()
#ip_header = struct.unpack('!BBHHxxBBHBBBBBBBB',seq[14:34])
#tcp_header = struct.unpack('!HHIIxBHHH',seq[34:54])
#data = seq[66:]

print("ip_header:",ip_header)
print("tcp_header:",tcp_header)
print("data:",data)
