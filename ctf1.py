import struct

def decode_pcap_file(pcap_file):
    with open(pcap_file, "rb") as file:
        # Read and skip the pcap file header (24 bytes)
        file.read(24)

        packet_number = 1  # Initialize packet number

        while True:
            # Read the pcap packet header (16 bytes)
            header = file.read(16)
            if not header:
                break

            # Extract packet timestamp and length
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", header)

            # Read the packet data
            packet_data = file.read(incl_len)

            # Search for specific information in the packet data
            if b"Flag" in packet_data:
                print(f"Flag found in packet {packet_number}")
            if b"secret" in packet_data:
                print(f"Username 'secret' found in packet {packet_number}")
            if packet_data.startswith(b"\x46\xA4"):
                print(f"TCP checksum '0x46a4' found in packet {packet_number}")
            if b"\x83\x90~v" in packet_data:
                print(f"Device IP '131.144.126.118' found in packet {packet_number}")
            if packet_data[34:36] == b"\x1a\x04":
                print(f"Sum of connection ports found in packet {packet_number}")
            if  b"milkshake" in packet_data:
                print(f"Milkshake request from localhost found in packet {packet_number}")

            packet_number += 1

if __name__ == "__main__":
    pcap_file = "1.pcap"  # Replace with the path to your pcap file
    decode_pcap_file(pcap_file)
