import socket
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet6 import IPv6
from scapy.all import sniff, hexdump
from scapy.layers.inet6 import IPv6


import sqlite3

class UserDatabase:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self._create_table()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
        with self._get_connection() as conn:
            conn.execute(query)
            conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", "1234"))

    def validate_user(self, username, password):
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (username, password))
            result = cursor.fetchone()
            return result is not None

class Authenticator:
    def __init__(self):
        self.db = UserDatabase()

    def handle_auth_request(self, raw_data):
        try:
            parts = raw_data.split("|")
            if len(parts) == 3 and parts[0] == "AUTH":
                _, user, pwd = parts
                if self.db.validate_user(user, pwd):
                    return "SUCCESS"
            return "FAIL"
        except Exception as e:
            print(f"Error in auth logic: {e}")
            return "FAIL"


class Server:
    def __init__(self):
        self.ip = '0.0.0.0'
        self.port = 12345


    def analyze_packet(self, packet_bytes):

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

            # 2. Check for IPv4 (Layer 3)
            elif IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst

                # 3. Check for Transport Layer (Layer 4)
                if TCP in pkt:
                    proto = "TCP"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    if dport == 443 or sport == 443:
                        proto += "- https"
                    elif dport == 80 or sport == 80:
                        proto += "- http"
                    if dport == 53 or sport == 53 or dport ==5353 or sport ==5353:
                        proto += "- DNS"
                elif UDP in pkt:
                    proto = "UDP"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    if dport == 443 or sport == 443:
                        proto += "- https"
                    elif dport == 80 or sport == 80:
                        proto += "- http"
                elif ICMP in pkt:
                    proto = "ICMP"
                else:
                    proto = "IPv4"

            # 4. Check for IPv6 (Layer 3)
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst

                # Check transport layer inside IPv6
                if TCP in pkt:
                    proto = "TCPv6"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    if dport == 443 or sport == 443:
                        proto += "- https"
                    elif dport == 80 or sport == 80:
                        proto += "- http"
                elif UDP in pkt:
                    proto = "UDPv6"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    if dport == 443 or sport == 443:
                        proto += "- https"
                    elif dport == 80 or sport == 80:
                        proto += "- http"
                else:
                    proto = "IPv6"

            raw_hex = packet_bytes.hex()

            # Return all fields as a pipe-separated string
            return f"{proto}|{src}|{dst}|{sport}|{dport}|{raw_hex}"

        except Exception as e:
            print(f"Analysis error: {e}")
            return "Error|0.0.0.0|0.0.0.0|-|-|"

    def handle_client(self, conn, addr):
        print(f"[NEW SENSOR] {addr} connected.")
        auth_handler = Authenticator()  # יצירת מופע אחד

        while True:
            try:
                packet_data = conn.recv(8192)
                if not packet_data:
                    break

                try:
                    # מנסים לפענח את הביטים לטקסט
                    decoded_msg = packet_data.decode('utf-8', errors='ignore')

                    if decoded_msg.startswith("AUTH|"):
                        result = auth_handler.handle_auth_request(decoded_msg)

                        if result == "SUCCESS":
                            conn.sendall("Auth_success".encode())
                            print(f"[AUTH] {addr} Logged in successfully.")
                        else:
                            conn.sendall("FAIL".encode())

                        continue
                except Exception as e:
                    pass

                result = self.analyze_packet(packet_data)
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
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()


if __name__ == "__main__":
    Server().start_server()
