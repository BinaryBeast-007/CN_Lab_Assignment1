import socket
import struct

def parse_ethernet_header(data):
    destination_mac, source_mac, ethernet_protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(ethernet_protocol), data[14:]

def get_mac_address(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def parse_ip_header(data):
    version_and_header_length = data[0]
    version = version_and_header_length >> 4
    header_length = (version_and_header_length & 0xF) * 4
    time_to_live, protocol, source_ip, target_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, time_to_live, protocol, get_ip_address(source_ip), get_ip_address(target_ip), data[header_length:]

def get_ip_address(ip_bytes):
    return '.'.join(map(str, ip_bytes))

def parse_tcp_header(data):
    source_port, destination_port, sequence_number, acknowledgment_number, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    return source_port, destination_port, sequence_number, acknowledgment_number, flags, data[offset:]

def sniff_packets(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ETH_P_ALL
    sock.bind((interface, 0))
    counter = 0
    try:
        while True:
            raw_data, _ = sock.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
            
            if eth_proto == 8:  # IPv4
                version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(data)

                if proto == 6:  # TCP
                    counter += 1
                    src_port, dest_port, sequence, ack, flags, data = parse_tcp_header(data)
                    print(f"Ethernet Frame: source_mac: {src_mac}, destination_mac: {dest_mac}, ethernet_protocol: {eth_proto}")
                    print(f"IPv4 Packet: source_ip: {src_ip}, destination_ip: {dest_ip}, time_to_live: {ttl}, protocol: {proto}")
                    print(f"TCP Segment: source_port: {src_port}, destination_port: {dest_port}, sequence_number: {sequence}, acknowledgment_number: {ack}, flags: {flags}")
                    #print(f"Data: {data}\n")
                    print(f"data flow number {counter}")
                    
    except KeyboardInterrupt:
        print("Packet sniffer stopped.")

if __name__ == "__main__":
    interface = "enp0s1"  # Change this to your network interface
    sniff_packets(interface)
