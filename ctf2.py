import struct

def find_secret_in_packet(pcap_file, packet_number):
    with open(pcap_file, "rb") as file:
        # Read and skip the pcap file header (24 bytes)
        file.read(24)

        current_packet_number = 1  # Initialize packet number

        while True:
            # Read the pcap packet header (16 bytes)
            header = file.read(16)
            if not header:
                break

            # Extract packet timestamp and length
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", header)

            # Read the packet data
            packet_data = file.read(incl_len)

            # Check if this is the target packet
            if current_packet_number == packet_number:
                # Search for 'secret' within this packet's data
                if b"secret" in packet_data:
                    secret_index = packet_data.index(b"secret")
                    secret_data = packet_data[secret_index:secret_index + 500]  # Extract 10 bytes after 'secret'
                    print(f"Secret found in packet {packet_number}: {secret_data.decode('utf-8')}")
                    break

            current_packet_number += 1

if __name__ == "__main__":
    pcap_file = "1.pcap"  # Replace with the path to your pcap file
    target_packet_number = 3135
    find_secret_in_packet(pcap_file, target_packet_number)
