import socket
from app.dns_message import DNSMessage, DNSHeader, DNSQuestion, DNSAnswer

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # TODO: Uncomment the code below to pass the first stage

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            user_message = DNSMessage.from_buffer(buf)
            response = DNSMessage.respond_to_query(user_message)
            # response = DNSMessage(
            #     DNSHeader(
            #         packet_id=user_message.header.packet_id, 
            #         qr=1, 
            #         qdcount=1, 
            #         ancount=1), 
            #     DNSQuestion(domain_name='codecrafters.io'),
            #     DNSAnswer(domain_name='codecrafters.io', data=[8,8,8,8]))

            udp_socket.sendto(response.to_bytes(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
