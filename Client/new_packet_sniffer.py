import struct

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
			self._versionLen = raw[14:15]
			self._version = raw[14:15]
			self._headerLen = raw[14:15]
			self._typeOfService = raw[15:16]
			self._totLength = raw[16:18]
			self._identification = raw[18:20]
			self._flagOffset = raw[20:22]
			self._ipFlags = raw[20:21]
			self._fragmentOffset = raw[21:22]
			self._timeToLive = raw[22:23]
			self._protocol = raw[23:24]
			self._headerChecksum = raw[24:26]
			self._srcIp = raw[26:30]
			self._dstIp = raw[30:34]

	def get_header(self):
		versionLen = struct.pack('!B', self._version + self._headerLen)
		flagOffset = struct.pack('!H', self._ipFlags + self._fragmentOffset)
		return versionLen + self._typeOfService + self._totLength + self._identification + flagOffset + self._timeToLive + self._protocol + self._headerChecksum + self._srcIp + self._dstIp
	
#-------------------------------------------------------
	@property
	def versionLen(self):
		(versionLen,) = struct.unpack('!B', self._versionLen)
		return versionLen

	@versionLen.setter
	def versionLen(self, versionLen):
		self._versionLen = struct.pack('!B', versionLen)
#-------------------------------------------------------
	@property
	def version(self):
		(version,) = struct.unpack('!B', self._version)
		self._version = version >> 4
		return self._version

	@version.setter
	def version(self, version):
		self._version = version << 4
#-------------------------------------------------------
	@property
	def headerLen(self):
		(headerLen,) = struct.unpack('!B', self._headerLen)
		self._headerLen = ( headerLen & 0x0F ) << 2
		return self._headerLen

	@headerLen.setter
	def headerLen(self, headerLen):
		self._headerLen = headerLen  >> 2
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
	def flagOffset(self):
		(flagOffset,) = struct.unpack('!H', self._flagOffset)
		return flagOffset

	@flagOffset.setter
	def flagOffset(self, flagOffset):
		self._flagOffset = struct.pack('!H', flagOffset)
#-------------------------------------------------------
	@property
	def ipFlags(self):
		(ipFlags,) = struct.unpack('!B', self._ipFlags)
		self._ipFlags = ipFlags >> 5
		return self._ipFlags

	@ipFlags.setter
	def ipFlags(self, ipFlags):
		self._ipFlags = ipFlags << 13
#-------------------------------------------------------
	@property
	def fragmentOffset(self):
		(fragmentOffset,) = struct.unpack('!B', self._fragmentOffset)
		return fragmentOffset

	@fragmentOffset.setter
	def fragmentOffset(self, fragmentOffset):
		self._fragmentOffset = fragmentOffset
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
    return self._src_port + self._dst_port + self._length + self._checksum

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
    return data

  @data.setter
  def data( self, data ):
    self._data = data
