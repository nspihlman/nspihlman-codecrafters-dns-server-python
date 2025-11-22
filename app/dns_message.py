from dataclasses import dataclass
import struct

@dataclass
class DNSHeader:
    packet_id: int
    qr: int
    op_code: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 0 
    ra: int = 0
    z: int = 0
    rcode: int = 0
    qdcount: int = 0 
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def to_bytes(self):
        header = self.packet_id                    
        header = (header << 1) | self.qr
        header = (header << 4) | self.op_code
        header = (header << 1) | self.aa
        header = (header << 1) | self.tc
        header = (header << 1) | self.rd
        header = (header << 1) | self.ra
        header = (header << 3) | self.z
        header = (header << 4) | self.rcode
        header = (header << 16) | self.qdcount
        header = (header << 16) | self.ancount
        header = (header << 16) | self.nscount
        header = (header << 16) | self.arcount
        return header.to_bytes(12, byteorder="big")
    
    @classmethod
    def from_buffer(cls, buffer):
        # bytes 0 and 1 are the packet_id
        # 
        id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buffer[:12])
        qr     = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa     = (flags >> 10) & 0x1
        tc     = (flags >> 9)  & 0x1
        rd     = (flags >> 8)  & 0x1
        ra     = (flags >> 7)  & 0x1
        z      = (flags >> 4)  & 0x7
        rcode  = flags & 0xF

        return cls(packet_id=id, qr=qr, op_code=opcode, aa=aa, tc=tc, rd=rd, 
                   ra=ra, z = z, rcode=rcode, qdcount=qd, ancount=an, nscount=ns, arcount=ar)
    
    @classmethod
    def respond_to_query(cls, header):
        # Header is type DNSHeader
        return cls(
            packet_id=header.packet_id, 
            qr=1, 
            op_code=header.op_code, 
            rd=header.rd, 
            rcode=0 if header.op_code == 0 else 4,
            qdcount=header.qdcount,
            ancount=1)

@dataclass
class DNSQuestion:
    domain_name: str  # Domain Name 
    r_type: int = 1 # Record Type
    d_class: int = 1 # Domain Class 

    def to_bytes(self):
        question = encode_domain_name(self.domain_name)
        question += self.r_type.to_bytes(2, byteorder="big")
        question += self.d_class.to_bytes(2, byteorder="big")
        return question
    

@dataclass
class DNSAnswer:
    domain_name: str  # Domain Name
    data: list[int]  # data specific to the record type. For now it'll hold an IP address
    r_type: int = 1  # Record Type
    d_class: int = 1  # Domain Class
    ttl: int  = 3600  # Duration in seconds that a recoed can be cached before requerying
    length: int = 4  # length of the RDATA field in bytes

    def to_bytes(self):
        answer = encode_domain_name(self.domain_name)
        answer += self.r_type.to_bytes(2, byteorder="big")
        answer += self.d_class.to_bytes(2, byteorder="big")
        answer += self.ttl.to_bytes(4, byteorder="big")
        answer += self.length.to_bytes(2, byteorder="big")
        for val in self.data:
            answer += val.to_bytes(1, byteorder="big")
        return answer

@dataclass
class DNSMessage:
    header: DNSHeader
    question: DNSQuestion
    answer: DNSAnswer

    def to_bytes(self):
        return self.header.to_bytes() + self.question.to_bytes() + self.answer.to_bytes()
    
    @classmethod
    def from_buffer(cls, buffer):
        return cls(header=DNSHeader.from_buffer(buffer), question=DNSQuestion("codecrafters.io"), answer=DNSAnswer("codecrafters.io", [8,8,8,8]))
    
    @classmethod
    def respond_to_query(cls, query):
        # Query is type DNSMessage
        return cls(header=DNSHeader.respond_to_query(query.header), question=DNSQuestion("codecrafters.io"), answer=DNSAnswer("codecrafters.io", [8,8,8,8]))

def encode_domain_name(name: str):
    labels = name.split('.')
    encoded_name = b''
    for label in labels:
        encoded_name += len(label).to_bytes(1, byteorder="big")
        encoded_name += bytes(label, encoding='utf-8')
    encoded_name += b'\x00'
    return encoded_name