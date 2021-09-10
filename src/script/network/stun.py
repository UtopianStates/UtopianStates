''' 
STUN:
    Reference:
        - https://blog.csdn.net/momo0853/article/details/105387675
        - https://www.netmanias.com/en/post/techdocs/6067/nat-network-protocol/nat-behavior-discovery-using-stun-rfc-5780
'''
from enum import Enum, unique
import io
import logging
import random
import socket
import struct


@unique
class MessageType(Enum):
    BINDING_REQUEST         = 0x0001
    BINDING_RESPONSE        = 0x0101
    BINDING_ERROR_RESPONSE  = 0x0111
    SHARED_SECRET_REQUEST   = 0x0002
    SHARED_SECRET_RESPONSE  = 0x0102
    SHARED_SECRET_ERROR     = 0x0112

@unique
class AttributeType(Enum):
    MAPPED_ADDRESS      = 0x0001
    RESPONSE_ADDRESS    = 0x0002
    CHANGE_REQUEST      = 0x0003
    SOURCE_ADDRESS      = 0x0004
    CHANGED_ADDRESS     = 0x0005
    USERNAME            = 0x0006
    PASSWORD            = 0x0007
    MESSAGE_INTEGRITY   = 0x0008
    ERROR_CODE          = 0x0009
    UNKNOWN_ATTRIBUTES  = 0x000a
    REFLECTED_FROM      = 0x000b
    XOR_MAPPED_ADDRESS  = 0x8020
    SERVER              = 0x8022
    SECONDARY_ADDRESS   = 0x8050

#@unique
class NAT_TYPE(Enum):
    ''' NAT type enum '''
    WAN      = 'wan_address'
    BLOCKED = 'blocked'
    SYMMETRIC_FIREWALL = 'response_to_request_source'
    FULL_CONE = 'full_cone'
    ADDR_RISTRICTED  = 'addr_ristricted_cone'
    PORT_RISTRICTED  = 'port_ristricted_cone'
    SYMMETRIC = 'symmetric'

class STUNHeader(object):
    """ 20 bytes header """
    def __init__(self, type=None, length=0, transaction_id=None):
        self.type = type
        self.length = length
        self.transaction_id = random.randint(0, (1 << 128) - 1) if transaction_id is None else transaction_id

    def to_bytes(self):
        return struct.pack('!HH', self.type.value, self.length) + \
                self.transaction_id.to_bytes(16, 'big')
    
    @classmethod
    def from_bytes(cls, data):
        assert len(data) == 20
        _type, _len, _tid = struct.unpack('!HH16s', data)
        return cls(
                type=MessageType(_type),
                length=_len,
                transaction_id = int.from_bytes(_tid, 'big'))
    
    def __str__(self):
        return "header: name=%s,length=%s,id=%s" % (
                self.type.name if self.type else None, self.length, self.transaction_id)

class STUNAttribute(object):
    ''' STUN attribute '''
    HEADER_LENGTH = 4

    def __init__(self, type=None, length=0, value=b''):
        ''' init '''
        self.type = type
        self.length = length
        self.value = value

    def change_request(self, change_addr=False, change_port=False):
        ''' CHANGE-REQUEST '''
        if change_addr and change_port:
            _binary = b'\x00\x00\x00\x06'
        elif change_addr:
            _binary = b'\x00\x00\x00\x04'
        elif change_port:
            _binary = b'\x00\x00\x00\x02'
        else:
            _binary = b'\x00\x00\x00\x00'
        return STUNAttribute(type=AttributeType.CHANGE_REQUEST,
                length=len(_binary),
                value=_binary)

    def to_bytes(self):
        ''' to big endian bytes '''
        self.length = len(self.value)
        return struct.pack('!HH', self.type.value, self.length) + self.value
    
    def is_address(self):
        ''' is address '''
        return self.length == 8 and self.type in [
                AttributeType.MAPPED_ADDRESS,
                AttributeType.RESPONSE_ADDRESS,
                AttributeType.CHANGED_ADDRESS]
    
    def address(self):
        ''' parse address '''
        if not self.is_address():
            return None
        _, _family, port, ip = struct.unpack('!cBHI', self.value)
        return socket.inet_ntoa(struct.pack('!I', ip)), port
    
    def __str__(self):
        ''' to str '''
        if self.is_address():
            return "attr: name=%s,address=%s" % (self.type.name, self.address())
        else:
            return "attr: name=%s" % (self.type.name if self.type else None)

class STUNMessage(object):
    ''' STUN message '''

    def __init__(self, header=None, attributes=[]):
        ''' init '''
        self.header = header
        self.attributes = attributes
    
    def to_bytes(self):
        ''' to big endian bytes '''
        header = b''
        body = b''
        for attr in self.attributes:
            body += attr.to_bytes()
        self.header.length = len(body)
        header = self.header.to_bytes()
        return header + body
    
    @classmethod
    def from_bytes(cls, data):
        ''' from bytes '''
        header = STUNHeader.from_bytes(data[:20])
        attributes = []
        datalen = header.length
        f = io.BytesIO(data[20:])
        while datalen > 0:
            _type, _len = struct.unpack('!HH', f.read(STUNAttribute.HEADER_LENGTH))
            _value = f.read(_len)
            attributes.append(STUNAttribute(
                type=AttributeType(_type),
                length=_len,
                value=_value))
            datalen -= STUNAttribute.HEADER_LENGTH + _len
        return cls(header=header, attributes=attributes)
    
    def __str__(self):
        return '{}: [{}]'.format(self.header,
                ','.join(map(str, self.attributes)))

class STUN():
    ''' STUN '''

    def __init__(self, local_host, local_port, stun_host, stun_port):
        ''' init '''
        self.local_host = local_host
        self.local_port = int(local_port)
        self.stun_host = stun_host
        self.stun_port = int(stun_port)
        print("init", stun_host, stun_port)

        # Open socket
        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_udp.settimeout(2.0)
        self.sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_udp.bind((self.local_host, self.local_port))

    def close(self):
        ''' close '''
        self.sock_udp.close()

    def send(self, request):
        BUFFER_SIZE = 4096
        self.sock_udp.sendto(request.to_bytes(), (self.stun_host, self.stun_port))
        try:
            data, _ = self.sock_udp.recvfrom(BUFFER_SIZE)
        except socket.timeout as e:
            logging.warning('socket timeout')
            return None
        print("data", data)
        response = STUNMessage.from_bytes(data)
        return response

    def test_nat_1(self):
        ''' test NAT type 1 '''
        request = STUNMessage(header=STUNHeader(type=MessageType.BINDING_REQUEST))
        return self.send(request)

    def check_nat(self):
        ''' check NAT type '''
        resp = self.test_nat_1()
        print("resp", resp)
        if resp is None:
            return NAT_TYPE.BLOCKED
        return None
