
import socket
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff, hexdump


class Server:
    def __init__(self):
        self.ip = '0.0.0.0'
        self.port = 12345

    def analyze_packet(self, packet_bytes):
        """Reconstructs the packet and extracts protocol, IPs, and Ports."""
        try:
            # Reconstruct the Scapy packet from raw bytes
            pkt = Ether(packet_bytes)

            proto = "Other"
            src = "Unknown"
            dst = "Unknown"
            sport = "-"
            dport = "-"

            # 1. Check for ARP (Layer 2)
            if ARP in pkt:
                proto = "ARP"
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst

            # 2. Check for IP (Layer 3)
            elif IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst

                # 3. Check for Transport Layer (Layer 4)
                if TCP in pkt:
                    proto = "TCP"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                elif ICMP in pkt:
                    proto = "ICMP"
                else:
                    proto = "IP"

            raw_hex = packet_bytes.hex()

            # Return all 5 fields as a pipe-separated string
            return f"{proto}|{src}|{dst}|{sport}|{dport}|{raw_hex}"

        except Exception as e:
            print(f"Analysis error: {e}")
            return "Error|0.0.0.0|0.0.0.0|-|- "

    def handle_client(self, conn, addr):
        print(f"[NEW SENSOR] {addr} connected.")
        while True:
            try:
                # Receive the length of the packet first or a fixed buffer
                packet_data = conn.recv(2048)
                if not packet_data:
                    break

                # Analyze the raw bytes
                result = self.analyze_packet(packet_data)

                # Send the analysis back (e.g., "TCP|192.168.1.1|8.8.8.8")
                conn.sendall(result.encode())
            except Exception as e:
                print(f"Error handling data: {e}")
                break
        conn.close()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.ip, self.port))
        server_socket.listen()
        print(f"[READY] Analysis Server listening on {self.port}")
        while True:
            conn, addr = server_socket.accept()
            # Fixed the thread target bug here:
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()


if __name__ == "__main__":
    Server().start_server()
