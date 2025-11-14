from dataclasses import dataclass

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
    r_type: int = 1  # Record Type
    d_class: int = 1  # Domain Class
    ttl: int  = 3600  # Duration in seconds that a recoed can be cached before requerying
    length: int = 4  # length of the RDATA field in bytes
    data: list[int] = [8,8,8,8]  # data specific to the record type. For now it'll hold an IP address

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
    

def encode_domain_name(name: str):
    labels = name.split('.')
    encoded_name = b''
    for label in labels:
        encoded_name += len(label).to_bytes(1, byteorder="big")
        encoded_name += bytes(label, encoding='utf-8')
    encoded_name += b'\x00'
    return encoded_name