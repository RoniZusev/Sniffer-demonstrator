import socket
import time
import tkinter as tk
from tkinter import ttk
import threading

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import collections
from scapy.all import sniff

server_ip = '127.0.0.1'
port = 12345

# Start with no sniffing
sniffing = False

# Shared storage for captured packet summaries (used by Analyze window)
captured_packets = []
captured_lock = threading.Lock()

arp_table = {}  # {ip: mac}
arp_alerts = []
arp_lock = threading.Lock()


class User:

    def __init__(self):
        self.ip = '127.0.0.1'

    def create_main_window(self):
        root = tk.Tk()
        root.title("Roni's Sniffer")
        root.configure(bg="#1e1e1e")

        window_width, window_height = 900, 540
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = (screen_w - window_width) // 2
        y = (screen_h - window_height) // 2
        root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        root.minsize(700, 420)

        # Fonts
        header_font = ("Segoe UI", 36, "bold")
        sub_font = ("Segoe UI", 12)
        btn_font = ("Segoe UI", 14, "bold")
        footer_font = ("Segoe UI", 11)

        # ttk style
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("Big.TButton",
                        font=btn_font,
                        padding=(18, 10),
                        relief="flat")
        style.map("Big.TButton",
                  foreground=[('active', 'white')],
                  background=[('active', '#00a046')])

        # Grid layout
        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)

        # Header
        header = tk.Frame(root, bg="#1e1e1e")
        header.grid(row=0, column=0, sticky="nsew", padx=24, pady=(18, 6))
        title = tk.Label(header, text="The Ultimate Sniffer", font=header_font, fg="white", bg="#1e1e1e")
        title.pack(anchor="center")
        subtitle = tk.Label(header, text="Inspect, analyze and debug network traffic", font=sub_font, fg="#bdbdbd",
                            bg="#1e1e1e")
        subtitle.pack(anchor="center", pady=(6, 0))

        # Main frame (center)
        main = tk.Frame(root, bg="#151515")
        main.grid(row=1, column=0, sticky="nsew", padx=20, pady=18)
        main.grid_rowconfigure(0, weight=1)
        main.grid_columnconfigure((0, 1), weight=1, uniform="col")

        # Left card - Regular Sniffer
        left_card = tk.Frame(main, bg="#1c1c1c", padx=18, pady=18)
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=10)
        lbl1 = tk.Label(left_card, text="Regular Sniffer", font=("Segoe UI", 18, "bold"), fg="white", bg="#1c1c1c")
        lbl1.grid(row=0, column=0, sticky="w")
        desc1 = tk.Label(left_card,
                         text="Capture live traffic from an interface and view packet summaries in realtime.",
                         font=sub_font, fg="#cfcfcf", bg="#1c1c1c", wraplength=380, justify="left")
        desc1.grid(row=1, column=0, sticky="w", pady=(8, 18))
        start_btn = ttk.Button(left_card, text="▶ Start Sniffer (Ctrl+S)", style="Big.TButton",
                               command=lambda: self.start_sniffer(root))
        start_btn.grid(row=2, column=0, sticky="w")

        # Right card - Analyze Malware
        right_card = tk.Frame(main, bg="#1c1c1c", padx=18, pady=18)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=10)
        lbl2 = tk.Label(right_card, text="Analyze Malware", font=("Segoe UI", 18, "bold"), fg="white", bg="#1c1c1c")
        lbl2.grid(row=0, column=0, sticky="w")
        desc2 = tk.Label(right_card, text="Run deeper analysis on suspicious packets or payloads to detect anomalies.",
                         font=sub_font, fg="#cfcfcf", bg="#1c1c1c", wraplength=380, justify="left")
        desc2.grid(row=1, column=0, sticky="w", pady=(8, 18))
        analyze_btn = ttk.Button(right_card, text="⚠ Analyze Malware (Ctrl+A)", style="Big.TButton",
                                 command=lambda: self.anylaze_problems(root))
        analyze_btn.grid(row=2, column=0, sticky="w")

        # Keyboard shortcuts
        root.bind_all("<Control-s>", lambda _e: self.start_sniffer(root))
        root.bind_all("<Control-S>", lambda _e: self.start_sniffer(root))
        root.bind_all("<Control-a>", lambda _e: self.anylaze_problems(root))
        root.bind_all("<Control-A>", lambda _e: self.anylaze_problems(root))

        # Footer
        footer = tk.Frame(root, bg="#202020")
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        author = tk.Label(footer, text="© Roni Zusev", font=footer_font, fg="#bdbdbd", bg="#202020")
        author.grid(row=0, column=0, columnspan=2, sticky="n", pady=8)

        return root

    def start_sniffer(self, parent):
        global sniffing
        sniffer_window = tk.Toplevel(parent)
        try:
            sniffer_window.state('zoomed')
        except tk.TclError:
            pass

        sniffer_window.title("Sniffer Active")
        sniffer_window.geometry("900x600")
        sniffer_window.configure(bg="#1e1e1e")

        # --- Table ---
        columns = ("src_ip", "dst_ip", "port", "protocol")
        tree = ttk.Treeview(sniffer_window, columns=columns, show="headings")
        tree.heading("src_ip", text="Source IP")
        tree.heading("dst_ip", text="Destination IP")
        tree.heading("port", text="Port")
        tree.heading("protocol", text="Protocol")
        tree.pack(expand=True, fill="both", padx=10, pady=10)

        # צבעים בדיוק כמו המקור שלך
        tree.tag_configure("TCP", foreground="orange")
        tree.tag_configure("UDP", foreground="darkblue")
        tree.tag_configure("ICMP", foreground="yellow")
        tree.tag_configure("ARP", foreground="lightgreen")
        tree.tag_configure("ALERT", foreground="red")
        tree.tag_configure("Other", foreground="black")

        # פונקציית לחיצה כפולה להצגת RAW
        def on_packet_select(event):
            selection = tree.selection()
            if not selection: return
            item_id = selection[0]
            values = tree.item(item_id, "values")
            tags = tree.item(item_id, "tags")

            raw_hex = tags[1] if len(tags) > 1 else "No raw data available"

            details_win = tk.Toplevel(sniffer_window)
            details_win.title(f"Packet View: {values[0]}")
            details_win.geometry("550x450")
            details_win.configure(bg="#2d2d2d")

            tk.Label(details_win, text=f"Protocol: {values[3]} | {values[0]} -> {values[1]}", fg="white", bg="#2d2d2d",
                     font=("Segoe UI", 10, "bold")).pack(pady=10)
            txt = tk.Text(details_win, bg="#1a1a1a", fg="#00ff00", font=("Consolas", 10))
            txt.pack(expand=True, fill="both", padx=10, pady=10)
            txt.insert(tk.END, f"RAW PACKET DATA (HEX):\n\n{raw_hex}")
            txt.config(state=tk.DISABLED)

        tree.bind("<Double-1>", on_packet_select)

        # --- Packet Processing ---
        def process_packet(packet):
            try:
                raw_payload = bytes(packet)
                client_socket.sendall(raw_payload)
                response = client_socket.recv(4096).decode()

                # פירוק לפי הפורמט החדש (6 שדות)
                parts = response.split("|")
                if len(parts) < 6: return

                proto, src, dst, sport, dport, raw_hex = parts
                port_info = f"{sport} > {dport}" if sport != "-" else "-"

                # הכנסה לטבלה עם שמירת ה-Hex ב-Tags
                tree.insert("", "end", values=(src, dst, port_info, proto), tags=(proto, raw_hex))
                tree.yview_moveto(1)

                # עדכון המחסן לגרפים (התיקון החסר)
                with captured_lock:
                    captured_packets.append({
                        "proto": proto,
                        "src": src,
                        "dst": dst,
                        "ts": time.time()
                    })

            except Exception as e:
                print(f"Transmission error: {e}")

        def sniff_thread():
            global sniffing
            sniffing = True
            while sniffing:
                sniff(count=1, prn=process_packet, store=False)

        # --- Buttons --- (צבעים מקוריים)
        button_frame = tk.Frame(sniffer_window, bg="#1e1e1e")
        button_frame.pack(pady=15)

        tk.Button(button_frame, text="Start Sniffing", font=("Arial", 14), bg="#00b050", fg="white", width=15, height=2,
                  command=lambda: threading.Thread(target=sniff_thread, daemon=True).start()).grid(row=0, column=0,
                                                                                                   padx=10)

        tk.Button(button_frame, text="Stop Sniffing", font=("Arial", 14), bg="#c00000", fg="white", width=15, height=2,
                  command=lambda: globals().update(sniffing=False)).grid(row=0, column=1, padx=10)

        tk.Button(sniffer_window, text="Return to Menu", bg="#c00000", fg="white", width=15, height=2,
                  command=sniffer_window.destroy).place(x=10, y=10)

    def anylaze_problems(self, parent):
        analyze_window = tk.Toplevel(parent)
        analyze_window.title("Analyze Malware — Findings")
        analyze_window.geometry("1000x800")
        analyze_window.configure(bg="#1e1e1e")

        # ... שאר הפונקציה anylaze_problems נשארת כפי שכתבת במקור ...
        # (הגרפים יעבדו עכשיו כי הוספנו את ה-append ב-process_packet)
        tk.Label(analyze_window, text="Analyze Cyber Attacks — Summary", font=("Arial", 18, "bold"), fg="white",
                 bg="#1e1e1e").pack(pady=10)

        with captured_lock:
            snapshot = list(captured_packets)

        if not snapshot:
            tk.Label(analyze_window, text="No captured packets yet.", fg="white", bg="#1e1e1e").pack(pady=20)
            return

        # יצירת הגרף בדומה למקור שלך
        proto_counter = collections.Counter(p["proto"] for p in snapshot)
        fig, ax = plt.subplots(figsize=(6, 6))
        fig.patch.set_facecolor("#1e1e1e")
        ax.pie(proto_counter.values(), labels=proto_counter.keys(), autopct="%1.1f%%", textprops={'color': "w"})
        ax.set_facecolor("#151515")

        canvas = FigureCanvasTkAgg(fig, master=analyze_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)


if __name__ == "__main__":
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, port))
        user = User()
        root = user.create_main_window()
        root.mainloop()
    except Exception as e:
        print(f"Failed to connect: {e}")
