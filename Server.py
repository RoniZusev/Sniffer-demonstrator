import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet6 import IPv6
from scapy.all import sniff, hexdump
import sqlite3
import bcrypt


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

            cursor = conn.execute("SELECT * FROM users WHERE username = ?", ("admin",))
            if not cursor.fetchone():
                default_password = "1234".encode('utf-8')
                hashed_admin_pwd = bcrypt.hashpw(default_password, bcrypt.gensalt())


                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                             ("admin", hashed_admin_pwd))

    def register_user(self, username, password):
        password_bytes = password.encode('utf-8')

        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        try:
            with self._get_connection() as conn:
                conn.execute(query, (username, hashed_password))
                return True
        except sqlite3.IntegrityError:
            return False

    def validate_user(self, username, password):
        query = "SELECT password FROM users WHERE username = ?"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (username,))
            result = cursor.fetchone()

            if result:
                stored_hash = result[0]
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    return True
            return False

class Authenticator:
    def __init__(self):
        self.db = UserDatabase()

    def handle_auth_request(self, raw_data):
        try:
            parts = raw_data.split("|")
            if len(parts) == 3:
                action, user, pwd = parts

                # התחברות
                if action == "AUTH":
                    if self.db.validate_user(user, pwd):
                        return "SUCCESS", user

                # הרשמה
                elif action == "REGISTER":
                    if self.db.register_user(user, pwd):
                        return "REG_SUCCESS", user
                    else:
                        return "REG_FAIL_EXISTS", None

            return "FAIL", None

        except Exception as e:
            print(f"Error in auth logic: {e}")
            return "FAIL", None


class ServerGUI:
    def __init__(self, root, server_instance):
        self.root = root
        self.server = server_instance
        self.root.title("NetDefender - Command & Control Center")
        self.root.geometry("900x650")
        self.root.configure(bg="#0b0f19")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#151b2b", foreground="#e0e0e0", fieldbackground="#151b2b", rowheight=35,
                        font=("Segoe UI", 10))
        style.map("Treeview", background=[("selected", "#c0392b")])  # צבע אדום כשבוחרים שורה לניתוק
        style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"), background="#0b0f19", foreground="#00ffcc",
                        borderwidth=0)

        # Header
        header_frame = tk.Frame(self.root, bg="#0b0f19")
        header_frame.pack(fill="x", pady=(20, 10), padx=25)
        tk.Label(header_frame, text="🛡️ NetDefender C&C Server", font=("Segoe UI", 22, "bold"), fg="#ffffff",
                 bg="#0b0f19").pack(side="left")
        self.status_lbl = tk.Label(header_frame, text="● SERVER ONLINE", font=("Consolas", 14, "bold"), fg="#00ffcc",
                                   bg="#0b0f19")
        self.status_lbl.pack(side="right")

        # Stats & Controls
        control_frame = tk.Frame(self.root, bg="#151b2b", highlightbackground="#2a3441", highlightthickness=1)
        control_frame.pack(fill="x", padx=25, pady=(0, 20), ipadx=10, ipady=10)

        self.active_count_var = tk.IntVar(value=0)
        tk.Label(control_frame, text="Active Sensors:", font=("Segoe UI", 12), fg="#a0aabf", bg="#151b2b").pack(
            side="left", padx=10)
        tk.Label(control_frame, textvariable=self.active_count_var, font=("Segoe UI", 16, "bold"), fg="#ffffff",
                 bg="#151b2b").pack(side="left")

        # כפתור הניתוק
        self.kick_btn = tk.Button(control_frame, text="🛑 TERMINATE SENSOR", font=("Segoe UI", 10, "bold"),
                                  bg="#c0392b", fg="white", activebackground="#e74c3c", cursor="hand2",
                                  command=self.request_disconnect, borderwidth=0, padx=20)
        self.kick_btn.pack(side="right", padx=10)

        # Table
        table_frame = tk.Frame(self.root, bg="#0b0f19")
        table_frame.pack(expand=True, fill="both", padx=25, pady=(0, 25))

        columns = ("ip", "port", "status", "user")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        for col in columns: self.tree.heading(col, text=col.replace("_", " ").title())

        self.tree.tag_configure("oddrow", background="#1a2133")
        self.tree.tag_configure("evenrow", background="#151b2b")
        self.tree.tag_configure("auth", foreground="#00ffcc", font=("Segoe UI", 10, "bold"))
        self.tree.pack(expand=True, fill="both")
        self.row_counter = 0

    def request_disconnect(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Selection Required", "Please select a sensor from the list to disconnect.")
            return

        sensor_id = selected[0]  # ה-ID הוא ה-ip:port
        if messagebox.askyesno("Confirm Termination", f"Are you sure you want to disconnect sensor {sensor_id}?"):
            self.server.kick_client(sensor_id)

    def add_client(self, addr):
        uid = f"{addr[0]}:{addr[1]}"
        tag = "evenrow" if self.row_counter % 2 == 0 else "oddrow"
        self.row_counter += 1
        self.root.after(0, lambda: self.tree.insert("", "end", iid=uid,
                                                    values=(addr[0], addr[1], "Pending Auth...", "Waiting..."),
                                                    tags=(tag,)))
        self.root.after(0, lambda: self.active_count_var.set(self.active_count_var.get() + 1))

    def update_client_auth(self, addr, username):
        uid = f"{addr[0]}:{addr[1]}"
        self.root.after(0, lambda: self._update_row(uid, addr[0], addr[1], "Authenticated ✓", username))

    def _update_row(self, uid, ip, port, status, user):
        if self.tree.exists(uid):
            new_tags = tuple(set(self.tree.item(uid, "tags")) | {"auth"})
            self.tree.item(uid, values=(ip, port, status, user), tags=new_tags)

    def remove_client(self, addr_str):
        self.root.after(0, lambda: self._delete_row(addr_str))

    def _delete_row(self, uid):
        if self.tree.exists(uid):
            self.tree.delete(uid)
            self.active_count_var.set(max(0, self.active_count_var.get() - 1))


class Server:
    def __init__(self):
        self.ip = '0.0.0.0'
        self.port = 12345
        self.ui = None
        #  { "ip:port": socket_object }
        self.active_connections = {}
        self.lock = threading.Lock()

    def kick_client(self, addr_str):
        with self.lock:
            if addr_str in self.active_connections:
                print(f"[KICK] Manually disconnecting {addr_str}")
                try:
                    # סגירת הסוקט תגרום ל-recv ב-Thread של הלקוח להיכשל ולצאת בצורה מסודרת
                    self.active_connections[addr_str].shutdown(socket.SHUT_RDWR)
                    self.active_connections[addr_str].close()
                except Exception as e:
                    print(f"Error kicking client: {e}")

    def analyze_packet(self, packet_bytes):
        try:
            pkt = Ether(packet_bytes)
            try:
                src_mac, dst_mac = pkt.src, pkt.dst
            except:
                src_mac, dst_mac = "-", "-"

            proto, src, dst, sport, dport = "Other", "Unknown", "Unknown", "-", "-"

            if pkt.type == 0x0806 or ARP in pkt:
                proto = "ARP"
                if ARP in pkt: src, dst = pkt[ARP].psrc, pkt[ARP].pdst
            elif IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                if TCP in pkt:
                    proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
                    if dport in [443] or sport in [443]:
                        proto += "- https"
                    elif dport in [80] or sport in [80]:
                        proto += "- http"
                    elif dport in [25, 465, 587] or sport in [25, 465, 587]:
                        proto += "- SMTP"  # זיהוי SMTP
                elif UDP in pkt:
                    proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
                    if dport in [53, 5353] or sport in [53, 5353]:
                        proto += "- DNS"
                    elif dport in [67, 68] or sport in [67, 68]:
                        proto += "- DHCP"  # זיהוי DHCP ל-IPv4
                elif ICMP in pkt:
                    proto = "ICMP"
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
                if TCP in pkt:
                    proto, sport, dport = "TCPv6", pkt[TCP].sport, pkt[TCP].dport
                    if dport in [25, 465, 587] or sport in [25, 465, 587]: proto += "- SMTP"  # זיהוי SMTP ב-IPv6
                elif UDP in pkt:
                    proto, sport, dport = "UDPv6", pkt[UDP].sport, pkt[UDP].dport
                    if dport in [546, 547] or sport in [546, 547]: proto += "- DHCPv6"  # זיהוי DHCP ל-IPv6

            return f"{proto}|{src}|{dst}|{sport}|{dport}|{src_mac}|{dst_mac}|{packet_bytes.hex()}"
        except:
            return "Error|0.0.0.0|0.0.0.0|-|-|-|-|"

    def handle_client(self, conn, addr):
        addr_str = f"{addr[0]}:{addr[1]}"
        with self.lock:
            self.active_connections[addr_str] = conn

        self.ui.add_client(addr)
        auth_handler = Authenticator()

        while True:
            try:
                data = conn.recv(8192)
                if not data: break

                msg = data.decode('utf-8', errors='ignore')
                if msg.startswith("AUTH|") or msg.startswith("REGISTER|"):
                    res, user = auth_handler.handle_auth_request(msg)
                    if res == "SUCCESS":
                        conn.sendall("Auth_success".encode())
                        self.ui.update_client_auth(addr, user)
                    else:
                        conn.sendall(res.encode() if "REG" in res else "FAIL".encode())
                    continue

                analysis = self.analyze_packet(data)
                conn.sendall(analysis.encode())

            except:
                break

        with self.lock:
            if addr_str in self.active_connections:
                del self.active_connections[addr_str]

        self.ui.remove_client(addr_str)
        conn.close()

    def start(self):
        root = tk.Tk()
        self.ui = ServerGUI(root, self)

        def listen_loop():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((self.ip, self.port))
            s.listen()
            while True:
                c, a = s.accept()
                threading.Thread(target=self.handle_client, args=(c, a), daemon=True).start()

        threading.Thread(target=listen_loop, daemon=True).start()
        root.mainloop()


if __name__ == "__main__":
    Server().start()
