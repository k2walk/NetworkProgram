import struct

class Packet:

  def __init__(self, raw):
   self._raw = raw
   self._eth = Ethernet(raw[:])
   self._arp = ARP(raw[:])
   self._ip = IP(raw[14:34])
   self._echo = Echo(raw[34:])
   self._udp = UDP(raw[34:])
   self._tcp = TCP(raw[34:])
#   self._dns = DNS(raw[42:])

  @property
  def raw(self):
    return self._raw

  @property
  def eth(self):
    return self._eth

  @property
  def arp(self):
    return self._arp

  @property
  def ip(self):
    return self._ip

  @property
  def echo(self):
    return self._echo

  @property
  def udp(self):
    return self._udp

  @property
  def tcp(self):
    return self._tcp

#  @property
#  def dns(self):
#    return self._dns

class Ethernet :
	def __init__(self, raw = None) :
		if raw != None :
			self._dst = raw[:6]
			self._src = raw[6:12]
			self._type = raw[12:14]
	def get_header(self) :
		return self._dst + self._src + self._type

	@property
	def dst(self) :
		dst = struct.unpack('!BBBBBB', self._dst)
		return '%02x:%02x:%02x:%02x:%02x:%02x' % dst
	@dst.setter
	def dst(self, dst):
		if '-' in dst :
			dst = dst.split('-')
		elif ':' in dst :
			dst = dst.split(':')
		dst = ''.join(dst)
		self._dst = bytes.fromhex(dst)
	@property
	def src(self) :
		src = struct.unpack('!BBBBBB', self._src)
		return '%02x:%02x:%02x:%02x:%02x:%02x' % src
	@src.setter
	def src(self, src) :
		if '-' in src:
			src = src.split('-')
		elif ':' in src : 
			src = src.split(':')
		src = ''.join(src)
		self._src = bytes.fromhex(src)

	@property
	def type(self) :
		(type,) = struct.unpack('!H', self._type)
		return type
	@type.setter
	def type(self, type) :
		self._type = struct.pack('!H', type)
class ARP :
	def __init__(self, raw=None):
		if raw != None:
			self._HWtype = raw[14:16]
			self._protocol = raw[16:18]
			self._HWsize = raw[18:19]
			self._protoSize = raw[19:20]
			self._opcode = raw[20:22]
			self._sendMac = raw[22:28]
			self._sendIP = raw[28:32]
			self._targetMac = raw[32:38]
			self._targetIP = raw[38:42]

	def get_header(self):
		return self._HWtype + self._protocol + self._HWsize + self._protoSize +self._opcode + self._sendMac + self._sendIP + self._targetMac + self._targetIP

	@property
	def HWtype(self):
		return self._HWtype

	@HWtype.setter
	def HWtype(self, HWtype):
		self._HWtype = struct.pack('!H', HWtype)
#-------------------------------------------------------
	@property
	def protocol(self):
		return self._protocol
	@protocol.setter
	def protocol(self, protocol):
		self._protocol = struct.pack('!H', protocol)

#-------------------------------------------------------
	@property
	def HWsize(self):
		#(HWsize,) = struct.unpack('!B', self._HWsize)
		return self._HWsize

	@HWsize.setter
	def HWsize(self, HWsize):
		self._HWsize = struct.pack('!B', HWsize)

# -------------------------------------------------------
	@property
	def protoSize(self):
		#(protoSize,) = struct.unpack('!B', self._protoSize)
		return self._protoSize

	@protoSize.setter
	def protoSize(self, protoSize) :
		self._protoSize = struct.pack('!B', protoSize)
# -------------------------------------------------------
	@property
	def opcode(self):
		#(opcode,) = struct.unpack('!H', self._opcode)
		return self._opcode

	@opcode.setter
	def opcode(self, opcode):
		self._opcode = struct.pack('!H', opcode)
# -------------------------------------------------------
	@property
	def sendMac(self):
		sendMac = struct.unpack('!BBBBBB', self._sendMac)
		return '%02x:%02x:%02x:%02x:%02x:%02x' % sendMac

	@sendMac.setter
	def sendMac(self, sendMac):
		if '-' in sendMac:
			sendMac = sendMac.split('-')
		elif ':' in sendMac:
			sendMac = sendMac.split(':')
		sendMac = ''.join(sendMac)
		self._sendMac = bytes.fromhex(sendMac)
# -------------------------------------------------------
	@property
	def sendIP(self):
		sendIP = struct.unpack('!BBBB', self._sendIP)
		return '%d.%d.%d.%d' % sendIP

	@sendIP.setter
	def sendIP(self, ip):
		ip = ip.split('.')
		ip = list(map(int, ip))
		self._sendIP = struct.pack('!BBBB', ip[0], ip[1], ip[2], ip[3])
# -------------------------------------------------------
	@property
	def targetMac(self):
		targetMac = struct.unpack('!BBBBBB', self._targetMac)
		return '%02x:%02x:%02x:%02x:%02x:%02x' % targetMac

	@targetMac.setter
	def targetMac(self, targetMac):
		if '-' in targetMac:
			targetMac = targetMac.split('-')
		elif ':' in targetMac:
			targetMac = targetMac.split(':')
		targetMac = ''.join(targetMac)
		self._targetMac = bytes.fromhex(targetMac)
# -------------------------------------------------------
	@property
	def targetIP(self):
		targetIP = struct.unpack('!BBBB', self._targetIP)
		return '%d.%d.%d.%d' % targetIP

	@targetIP.setter
	def targetIP(self, ip):
		ip = ip.split('.')
		ip = list(map(int, ip))
		self._targetIP = struct.pack('!B', ip[0])
		self._targetIP += struct.pack('!B', ip[1])
		self._targetIP += struct.pack('!B', ip[2])
		self._targetIP += struct.pack('!B', ip[3])

class IP :
	def __init__(self, raw=None):
		if raw != None:
			self._versionLen = raw[:1]
			self._typeOfService = raw[1:2]
			self._totLength = raw[2:4]
			self._identification = raw[4:6]
			self._ipFlags = raw[6:7]
			self._fragmentOffset = raw[7:8]
			self._timeToLive = raw[8:9]
			self._protocol = raw[9:10]
			self._headerChecksum = raw[10:12]
			self._srcIp = raw[12:16]
			self._dstIp = raw[16:20]
		else:
			self._versionLen = b'\x00'

	def get_header(self):
		return self._versionLen + self._typeOfService + self._totLength + self._identification + self._ipFlags + self._fragmentOffset + self._timeToLive + self._protocol + self._headerChecksum + self._srcIp + self._dstIp
	
#-------------------------------------------------------
	@property
	def version(self):
		(version,) = struct.unpack('!B', self._versionLen)
		return version >> 4

	@version.setter
	def version(self, version):
		(tmp,) = struct.unpack('!B', self._versionLen)
		version = version << 4
		tmp += version
		self._versionLen = struct.pack('!B', tmp)
#-------------------------------------------------------
	@property
	def headerLen(self):
		(headerLen,) = struct.unpack('!B', self._versionLen)
		return ( headerLen & 0x0F ) << 2

	@headerLen.setter
	def headerLen(self, headerLen):
		(tmp,) = struct.unpack('!B', self._versionLen)
		headerLen = headerLen >> 2
		tmp += headerLen
		self._versionLen = struct.pack('!B', tmp)
#-------------------------------------------------------
	@property
	def typeOfService(self):
		(typeOfService,) = struct.unpack('!B', self._typeOfService)
		return typeOfService
	
	@typeOfService.setter
	def typeOfService(self, typeOfService):
		self._typeOfService = struct.pack('!B', typeOfService)
#-------------------------------------------------------
	@property
	def totLength(self):
		(totLength,) = struct.unpack('!H', self._totLength)
		return totLength

	@totLength.setter
	def totLength(self, totLength):
		self._totLength = struct.pack('!H', totLength)
#-------------------------------------------------------
	@property
	def identification(self):
		(identification,) = struct.unpack('!H', self._identification)
		return identification

	@identification.setter
	def identification(self, identification):
		self._identification = struct.pack('!H', identification)
#-------------------------------------------------------
	@property
	def ipFlags(self):
		(ipFlags,) = struct.unpack('!B', self._ipFlags)
		return ipFlags >> 5

	@ipFlags.setter
	def ipFlags(self, ipFlags):
		ipFlags = ipFlags << 5
		self._ipFlags = struct.pack('!B', ipFlags)
#-------------------------------------------------------
	@property
	def fragmentOffset(self):
		(fragmentOffset,) = struct.unpack('!B', self._fragmentOffset)
		return fragmentOffset << 3

	@fragmentOffset.setter
	def fragmentOffset(self, fragmentOffset):
		fragmentOffset = fragmentOffset >> 3
		self._fragmentOffset = struct.pack('!B', fragmentOffset)
#-------------------------------------------------------
	@property
	def timeToLive(self):
		(timeToLive,) = struct.unpack('!B', self._timeToLive)
		return timeToLive

	@timeToLive.setter
	def timeToLive(self, timeToLive):
		self._timeToLive = struct.pack('!B', timeToLive)
#-------------------------------------------------------
	@property
	def protocol(self):
		(protocol,) = struct.unpack('!B', self._protocol)
		return protocol

	@protocol.setter
	def protocol(self, protocol):
		self._protocol = struct.pack('!B', protocol)
#-------------------------------------------------------
	@property
	def headerChecksum(self):
		(headerChecksum,) = struct.unpack('!H',self._headerChecksum)
		return headerChecksum

	@headerChecksum.setter
	def headerChecksum(self, headerChecksum):
		self._headerChecksum = struct.pack('!H', headerChecksum)
#-------------------------------------------------------
	@property
	def srcIp(self):
		srcIp = struct.unpack('!BBBB', self._srcIp)
		return '%d.%d.%d.%d' % srcIp

	@srcIp.setter
	def srcIp(self, srcIp):
		srcIp = srcIp.split('.')
		srcIp = list(map(int, srcIp))
		self._srcIp = struct.pack('!BBBB', srcIp[0], srcIp[1], srcIp[2], srcIp[3])
#-------------------------------------------------------
	@property
	def dstIp(self):
		dstIp = struct.unpack('!BBBB', self._dstIp)
		return '%d.%d.%d.%d' % dstIp

	@dstIp.setter
	def dstIp(self, dstIp):
		dstIp = dstIp.split('.')
		dstIp = list(map(int, dstIp))
		self._dstIp = struct.pack('!BBBB', dstIp[0], dstIp[1], dstIp[2], dstIp[3]) 
#-------------------------------------------------------

class ICMP:
  def __init__( self, raw=None ):
    if raw != None:
      self._type = raw[0:1]
      self._code = raw[1:2]
      self._chksum = raw[2:4]

  def get_header( self ):
    return self._type + self._code + self._chksum

  @property
  def type( self ):
    (type,) = struct.unpack( '!B', self._type )
    return type

  @type.setter
  def type( self, type ):
    self._type = struct.pack( '!B', type )

  @property
  def code( self ):
    (code,) = struct.unpack('!B', self._code )
    return code

  @code.setter
  def code( self, code ):
    self._code = struct.pack( '!B', code )

  @property
  def chksum( self ):
    (chksum,) = struct.unpack('!H', self._chksum )
    return chksum

  @chksum.setter
  def chksum( self, chksum ):
    self._chksum = struct.pack( '!H', chksum )

class Echo( ICMP ):
  def __init__( self, raw=None):
    if raw != None:
      super().__init__(raw)

      self._id = raw[4:6]
      self._seq = raw[6:8]
      self._payload = raw[8:]

  def get_header( self ):
    return super().get_header() + self._id + self._seq + self._payload

  @property
  def id( self ):
    (id,) = struct.unpack( '!H', self._id )
    return id

  @id.setter
  def id( self, id ):
    self._id = struct.pack( '!H', id )

  @property
  def seq( self ):
    (seq,) = struct.unpack( '!H', self._seq )
    return seq

  @seq.setter
  def seq( self, seq ):
    self._seq = struct.pack( '!H', seq )

  @property
  def payload( self ):
    return self._payload.decode(errors='ignore')

  @payload.setter
  def payload( self, payload ):
    self._payload = payload.encode(errors='ignore')

class UDP:
  def __init__(self, raw=None):
    if raw != None:
      self._src_port = raw[:2]
      self._dst_port = raw[2:4]
      self._length = raw[4:6]
      self._checksum = raw[6:8]
      self._data = raw[8:]

  def get_header( self ):
    return self._src_port + self._dst_port + self._length + self._checksum + self._data

  @property
  def src_port( self ):
    (src_port,) = struct.unpack('!H', self._src_port)
    return src_port

  @src_port.setter
  def src_port( self, src_port ):
    self._src_port = struct.pack('!H', src_port)

  @property
  def dst_port( self ):
    (dst_port,) = struct.unpack('!H', self._dst_port)
    return dst_port

  @dst_port.setter
  def dst_port( self, dst_port ):
    self._dst_port = struct.pack('!H', dst_port)
  
  @property
  def length( self ):
    (length,) = struct.unpack('!H', self._length)
    return length

  @length.setter
  def length( self, length ):
    self._length = struct.pack('!H', length)

  @property
  def checksum( self ):
    (checksum,) = struct.unpack('!H', self._checksum)
    return checksum

  @checksum.setter
  def checksum( self, checksum ):
    self._checksum = struct.pack('!H', checksum)

  @property
  def data( self ):
    return self._data.decode(errors='ignore')

  @data.setter
  def data( self, data ):
    self._data = data.encode(errors='ignore')

class TCP:
  def __init__( self, raw = None ):
    if raw != None:
      self._src_port = raw[:2]
      self._dst_port = raw[2:4]
      self._seq_num = raw[4:8]
      self._ack_num = raw[8:12]
      self._offset_and_rsv = raw[12:13]
      self._flags = raw[13:14]
      self._window = raw[14:16]
      self._checksum = raw[16:18]
      self._urg = raw[18:20]
      self._data = raw[20:]
    else:
      self._offset_and_rsv = b'\x00'
      self._data = ''

  def get_header( self ):
    if self._data == '':
      return self._src_port + self._dst_port + self._seq_num + self._ack_num + self._offset_and_rsv + self._flags + self._window + self._checksum + self._urg
    else:
      return self._src_port + self._dst_port + self._seq_num + self._ack_num + self._offset_and_rsv + self._flags + self._window + self._checksum + self._urg + self._data

  @property
  def src_port( self ):
    (src_port,) = struct.unpack('!H', self._src_port)
    return src_port

  @src_port.setter
  def src_port( self, src_port ):
    self._src_port = struct.pack('!H', src_port)

  @property
  def dst_port( self ):
    (dst_port,) = struct.unpack('!H', self._dst_port)
    return dst_port

  @dst_port.setter
  def dst_port( self, dst_port ):
    self._dst_port = struct.pack('!H', dst_port)
  
  @property
  def seq_num( self ):
    (seq_num,) = struct.unpack('!L', self._seq_num)
    return seq_num

  @seq_num.setter
  def seq_num( self, seq_num ):
    self._seq_num = struct.pack('!L', seq_num)

  @property
  def ack_num( self ):
    (ack_num,) = struct.unpack('!L', self._ack_num)
    return ack_num

  @ack_num.setter
  def ack_num( self, ack_num ):
    self._ack_num = struct.pack('!L', ack_num)

  @property
  def offset( self ):
    (offset,) = struct.unpack('!B', self._offset_and_rsv)
    return offset >> 2 
  
  @offset.setter
  def offset( self, offset ):
    (tmp,) = struct.unpack('!B', self._offset_and_rsv)
    tmp += offset << 2
    self._offset_and_rsv = struct.pack('!B', tmp)

  @property
  def rsv( self ):
    (rsv,) = struct.unpack('!B', self._offset_and_rsv)
    return rsv & 0x0F

  @rsv.setter
  def rsv( self, rsv ):
    (tmp,) = struct.unpack('!B', self._offset_and_rsv)
    tmp += rsv
    self._offset_and_rsv = struct.pack('!B', tmp)

  @property
  def flags( self ):
    (flags,) = struct.unpack('!B', self._flags)
    return flags

  @flags.setter
  def flags( self, flags ):
    self._flags = struct.pack('!B', flags)

  @property
  def window( self ):
    (window,) = struct.unpack('!H', self._window)
    return window
  @window.setter
  def window( self, window ):
    self._window = struct.pack('!H', window)

  @property
  def checksum( self ):
    (checksum,) = struct.unpack('!H', self._checksum)
    return checksum

  @checksum.setter
  def checksum( self, checksum ):
    self._checksum = struct.pack('!H', checksum)

  @property
  def urg( self ):
    (urg,) = struct.unpack('!H', self._urg)
    return urg

  @urg.setter
  def urg( self, urg ):
    self._urg = struct.pack('!H', urg)

  @property
  def data( self ):
    return self._data.decode(errors='ignore')

  @data.setter
  def data( self, data ):
    self._data = data.encode(errors='ignore')

#class DNS:
#  def __init__( self, raw = None ):
#    if raw != None:
#      self._identification = raw[:2]
#      self._codes_and_flags = raw[2:4]
#      self._total_questions = raw[4:6]
#      self._total_answers = raw[6:8]
#      self._total_authority = raw[8:10]
#      self._total_additional = raw[10:12]
#      self._query = raw[12:]
#
#  @property
#  def identification( self ):
#    (identification,) = struct.unpack('!H', self._identification)
#    return identification
#
#  @identification.setter
#  def identification( self, identification ):
#    self._identification = struct.pack('!H', identification)
#
#  @property
#  def codes_and_flags( self ):
#    (codes_and_flags,) = struct.unpack('!H', self._codes_and_flags)
#    return codes_and_flags
#
#  @codes_and_flags.setter
#  def codes_and_flags( self, codes_and_flags ):
#    self._codes_and_flags = struct.pack('!H', codes_and_flags)
#
#  @property
#  def total_questions( self ):
#    (total_questions,) = struct.unpack('!H', self._total_questions)
#    return total_questions
#
#  @total_questions.setter
#  def total_questions( self, total_questions ):
#    self._total_questions = struct.pack('!H', total_questions)
#
#  @property
#  def total_answers( self ):
#    (total_answers,) = struct.unpack('!H', self._total_answers)
#    return total_answers
#
#  @total_answers.setter
#  def total_answers( self, total_answers ):
#    self._total_answers = struct.pack('!H', total_answers)
#
#  @property
#  def total_authority( self ):
#    (total_authority,) = struct.unpack('!H', self._total_authority)
#    return total_authority
#
#  @total_authority.setter
#  def total_authority( self, total_authority ):
#    self._total_authority = struct.pack('!H', total_authority)
#
#  @property
#  def total_additional( self ):
#    (total_additional,) = struct.unpack('!H', self._total_additional)
#    return total_additional
#
#  @total_additional.setter
#  def total_additional( self, total_additional ):
#    self._total_additional = struct.pack('!H', total_additional)
#
#  @property
#  def query( self ):
#    query = self._query.decode(errors='ignore')
#    return query
#
#  @query.setter
#  def query( self, query ):
#    self._query = query.encode(errors='ignore')


