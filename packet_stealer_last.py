import socket
import binascii

class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """
    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    whole_ip = ""
    raw_ip_addr = str(binascii.hexlify(raw_ip_addr))[2:-1]
    for i in range(0,(len(raw_ip_addr)),2):
            ip = raw_ip_addr[i:i+2]
            ip_num = int(ip,16)
            if(i < (len(raw_ip_addr)) - 2):
                whole_ip += str(ip_num)+"."
            else:
                whole_ip += str(ip_num)
    return whole_ip


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    
    source_port = int(binascii.hexlify(ip_packet_payload[0:2]),16)

    destnation_port = int(binascii.hexlify(ip_packet_payload[2:4]),16)

    temp = binascii.hexlify(ip_packet_payload[12:13])
    offset = int(str(temp)[2:3],16)

    payload = ((ip_packet_payload[offset*4:]))
    return TcpPacket(source_port, destnation_port, offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    by0 = binascii.hexlify(ip_packet[0:1])
    ihl = int(by0[1:])

    pro = binascii.hexlify(ip_packet[9:10])
    protocol = int(pro)

    source_address = ip_packet[12:16]
    destination_address = ip_packet[16:20]
    
    source_address = parse_raw_ip_addr(source_address)

    destination_address = parse_raw_ip_addr(destination_address)
    
    payload = ip_packet[ihl*4:]
    
    return IpPacket(protocol, ihl, source_address, destination_address, payload)


def setup_raw_socekt():
    TCP = 0x0006
    stealer = socket.socket(socket.AF_INET,socket.SOCK_RAW,TCP)
    return stealer


def main():
    stealer = setup_raw_socekt()
    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        packet,addr = stealer.recvfrom(4096)
        ip_packet = parse_network_layer_packet((packet))
        if ip_packet.protocol == 6:
            tcp_packet = parse_application_layer_packet(ip_packet.payload)
            try:
                data = tcp_packet.payload.decode('UTF-8')
                if len(tcp_packet.payload) > 0:
                    print(f"[{ip_packet.source_address}:{tcp_packet.src_port}] SENT: ")
                    print(data)
            except:
                print("DATA CAN'T BE DECODED")
    pass



if __name__ == "__main__":
    main()