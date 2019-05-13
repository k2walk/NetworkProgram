import struct

class DNS:
  def __init__( self, raw = None ):
    if raw != None:
      self._identification = raw[:2]
      self._codes_and_flags = raw[2:4]
      self._total_questions = raw[4:6]
      self._total_answers = raw[6:8]
      self._total_authority = raw[8:10]
      self._total_additional = raw[10:12]
      extend_query = raw[12:]
      q_place = list(extend_query).index(0)+1
      self._query_name = extend_query[:q_place]
      self._query_type = extend_query[q_place:q_place+2]
      self._query_class = extend_query[q_place+2:q_place+4]      
      extend_answer = extend_query[q_place+4:]
      if extend_answer[:2] == b'\xc0\x0c':
        self._answer_name = extend_query[:q_place]
        self._answer_type = extend_answer[2:4]
        self._answer_class = extend_answer[4:6]
        if self._answer_class == b'\x00\x01':
          self._answer_ttl = extend_answer[6:10]
          self._answer_data_length = extend_answer[10:12]
          self._answer_address = extend_answer[12:16]

  def get_header( self ):
    query_header = self._identification + self._codes_and_flags + self._total_questions + self._total_answers + self._total_authority + self._total_additional + self._query_name + self._query_type + self._query_class
    if ( ( self.codes_and_flags & 0xF000 ) >> 15 ) == 0:
      return query_header
    else:
      answer_header = self._answer_name + self._answer_type + self._answer_class + self._answer_ttl + self._answer_data_length + self._answer_address
      if self.total_answers == 1:
        return query_header + answer_header
      
  @property
  def identification( self ):
    (identification,) = struct.unpack('!H', self._identification)
    return identification

  @identification.setter
  def identification( self, identification ):
    self._identification = struct.pack('!H', identification)

  @property
  def codes_and_flags( self ):
    (codes_and_flags,) = struct.unpack('!H', self._codes_and_flags)
    return codes_and_flags

  @codes_and_flags.setter
  def codes_and_flags( self, codes_and_flags ):
    self._codes_and_flags = struct.pack('!H', codes_and_flags)

  @property
  def total_questions( self ):
    (total_questions,) = struct.unpack('!H', self._total_questions)
    return total_questions

  @total_questions.setter
  def total_questions( self, total_questions ):
    self._total_questions = struct.pack('!H', total_questions)

  @property
  def total_answers( self ):
    (total_answers,) = struct.unpack('!H', self._total_answers)
    return total_answers

  @total_answers.setter
  def total_answers( self, total_answers ):
    self._total_answers = struct.pack('!H', total_answers)

  @property
  def total_authority( self ):
    (total_authority,) = struct.unpack('!H', self._total_authority)
    return total_authority

  @total_authority.setter
  def total_authority( self, total_authority ):
    self._total_authority = struct.pack('!H', total_authority)

  @property
  def total_additional( self ):
    (total_additional,) = struct.unpack('!H', self._total_additional)
    return total_additional

  @total_additional.setter
  def total_additional( self, total_additional ):
    self._total_additional = struct.pack('!H', total_additional)

  @property
  def query_name( self ):
    query_name = self._query_name.decode(errors='ignore')
    domain = ''
    for x in self._query_name:
      if 1 <= x < 48 or 58 <= x < 64:
        domain += '.'
        continue
      domain += chr( x )
    return domain[1:-1]

  @query_name.setter
  def query_name( self, query_name ):
    self._query_name = query_name.encode(errors='ignore')

  @property
  def query_type( self ):
    (query_type,) = struct.unpack('!H', self._query_type)
    return query_type

  @query_type.setter
  def query_type( self, query_type ):
    self._query_type = struct.pack('!H', query_type)

  @property
  def query_class( self ):
    (query_class,) = struct.unpack('!H', self._query_class)
    return query_class

  @query_class.setter
  def query_class( self, query_class ):
    self._query_class = struct.pack('!H', query_class)

  @property
  def answer_name( self ):
    answer_name = self._answer_name.decode(errors='ignore')
    domain = ''
    for x in self._answer_name:
      if 1 <= x < 48 or 58 <= x < 64:
        domain += '.'
        continue
      domain += chr( x )
    return domain[1:-1]

  @answer_name.setter
  def answer_name( self, answer_name ):
    self._answer_name = answer_name.encode(errors='ignore')

  @property
  def answer_type( self ):
    (answer_type,) = struct.unpack('!H', self._answer_type)
    return answer_type

  @answer_type.setter
  def answer_type( self, answer_type ):
    self._answer_type = struct.pack('!H', answer_type)

  @property
  def answer_class( self ):
    (answer_class,) = struct.unpack('!H', self._answer_class)
    return answer_class

  @answer_class.setter
  def answer_class( self, answer_class ):
    self._answer_class = struct.pack('!H', answer_class)

  @property
  def answer_ttl( self ):
    (answer_ttl,) = struct.unpack('!L', self._answer_ttl)
    return answer_ttl

  @answer_ttl.setter
  def answer_ttl( self, answer_ttl ):
    self._answer_ttl = struct.pack('!L', answer_ttl)

  @property
  def answer_data_length( self ):
    (answer_data_length,) = struct.unpack('!H', self._answer_data_length)
    return answer_data_length

  @answer_data_length.setter
  def answer_data_length( self, answer_data_length ):
    self._answer_data_length = struct.pack('!H', answer_data_length)

  @property
  def answer_address( self ):
    answer_address = struct.unpack('!BBBB', self._answer_address)
    return '%d.%d.%d.%d' % answer_address

  @answer_address.setter
  def answer_address( self, answer_address ):
    answer_address = answer_address.split('.')
    answer_address = list(map(int, answer_address))
    self._answer_address = struct.pack('!BBBB', answer_address[0], answer_address[1], answer_address[2], answer_address[3])
