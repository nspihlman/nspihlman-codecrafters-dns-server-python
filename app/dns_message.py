from dataclasses import dataclass

@dataclass
class DNS_Header:
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
class DNS_Message:
    header: DNS_Header
    
