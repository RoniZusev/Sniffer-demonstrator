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

        # --- Filter Section (Updated to be top-center with 3 entries) ---
        filter_frame = tk.Frame(sniffer_window, bg="#2d2d2d", pady=10)
        filter_frame.pack(fill="x")

        center_container = tk.Frame(filter_frame, bg="#2d2d2d")
        center_container.pack(anchor="center")

        def create_entry(parent, label_text):
            container = tk.Frame(parent, bg="#2d2d2d")
            container.pack(side="left", padx=15)
            tk.Label(container, text=label_text, fg="white", bg="#2d2d2d", font=("Segoe UI", 9, "bold")).pack()
            ent = tk.Entry(container, bg="#1a1a1a", fg="#00ff00", insertbackground="white", width=20)
            ent.pack()
            return ent

        ip_filter = create_entry(center_container, "IP Filter")
        port_filter = create_entry(center_container, "Port Filter")
        proto_filter = create_entry(center_container, "Proto Filter")

        # --- Table ---
        columns = ("src_ip", "dst_ip", "port", "protocol")
        tree = ttk.Treeview(sniffer_window, columns=columns, show="headings")
        tree.heading("src_ip", text="Source IP")
        tree.heading("dst_ip", text="Destination IP")
        tree.heading("port", text="Port")
        tree.heading("protocol", text="Protocol")
        tree.pack(expand=True, fill="both", padx=10, pady=10)

        tree.tag_configure("TCP", foreground="orange")
        tree.tag_configure("UDP", foreground="darkblue")
        tree.tag_configure("ICMP", foreground="#D2691E")
        tree.tag_configure("ARP", foreground="lightgreen")
        tree.tag_configure("ALERT", foreground="red")
        tree.tag_configure("Other", foreground="white")

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

                if not ip_filter.winfo_exists(): return

                raw_payload = bytes(packet)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    client_socket.connect((server_ip, port))
                    client_socket.sendall(raw_payload)
                    response = client_socket.recv(8192).decode()

                parts = response.split("|")
                if len(parts) < 6: return

                proto, src, dst, sport, dport, raw_hex = parts
                port_info = f"{sport} > {dport}" if sport != "-" else "-"

                color_tag = "Other"
                if proto.startswith("TCP"):
                    color_tag = "TCP"
                elif proto.startswith("UDP"):
                    color_tag = "UDP"
                elif proto.startswith("ICMP"):
                    color_tag = "ICMP"
                elif proto.startswith("ARP"):
                    color_tag = "ARP"

                # --- NEW Triple Filter Logic ---
                f_ip = ip_filter.get().lower().strip()
                f_port = port_filter.get().lower().strip()
                f_proto = proto_filter.get().lower().strip()

                show_packet = True
                if f_ip and not (f_ip in src.lower() or f_ip in dst.lower()):
                    show_packet = False
                if f_port and not (f_port in port_info.lower()):
                    show_packet = False
                if f_proto and not (f_proto in proto.lower()):
                    show_packet = False

                if show_packet:
                    tree.insert("", "end", values=(src, dst, port_info, proto), tags=(color_tag, raw_hex))
                    tree.yview_moveto(1)

                with captured_lock:
                    captured_packets.append({
                        "proto": proto,
                        "src": src,
                        "dst": dst,
                        "ts": time.time()
                    })

            except Exception as e:
                pass  # Silent error handling for threading/UI close issues

        def sniff_thread():
            global sniffing
            sniffing = True
            while sniffing:
                sniff(count=1, prn=process_packet, store=False)

        # --- Buttons ---
        button_frame = tk.Frame(sniffer_window, bg="#1e1e1e")
        button_frame.pack(pady=15)

        tk.Button(button_frame, text="Start Sniffing", font=("Arial", 14), bg="#00b050", fg="white", width=15, height=2,
                  command=lambda: threading.Thread(target=sniff_thread, daemon=True).start()).grid(row=0, column=0,
                                                                                                   padx=10)

        def stop_sniffing():
            global sniffing
            sniffing = False

        tk.Button(button_frame, text="Stop Sniffing", font=("Arial", 14), bg="#c00000", fg="white", width=15, height=2,
                  command=stop_sniffing).grid(row=0, column=1, padx=10)

        tk.Button(sniffer_window, text="Return to Menu", bg="#c00000", fg="white", width=15, height=2,
                  command=sniffer_window.destroy).place(x=10, y=10)

    def anylaze_problems(self, parent):
        analyze_window = tk.Toplevel(parent)
        analyze_window.title("Analyze Malware — Findings")
        analyze_window.geometry("1000x800")
        analyze_window.configure(bg="#1e1e1e")

        header = tk.Label(analyze_window, text="Analyze Cyber Attacks — Summary", font=("Arial", 18, "bold"),
                          fg="white",
                          bg="#1e1e1e")
        header.pack(pady=10)

        return_btn = tk.Button(analyze_window, text="Return to Menu", font=("Arial", 10), bg="#c00000", fg="white",
                               width=15, height=2, command=analyze_window.destroy)
        return_btn.place(x=10, y=10)

        with captured_lock:
            snapshot = list(captured_packets)

        with arp_lock:
            alerts_snapshot = list(arp_alerts)

        if alerts_snapshot:
            alerts_frame = tk.LabelFrame(analyze_window, text="Threats — ARP Alerts", bg="#1e1e1e", fg="white",
                                         labelanchor="n")
            alerts_frame.pack(fill="x", padx=12, pady=(8, 12))
            acols = ("time", "ip", "old_mac", "new_mac")
            atree = tk.Treeview(alerts_frame, columns=acols, show="headings", height=min(6, len(alerts_snapshot)))
            atree.heading("time", text="Time")
            atree.heading("ip", text="IP")
            atree.heading("old_mac", text="Old MAC")
            atree.heading("new_mac", text="New MAC")
            atree.pack(fill="x", padx=6, pady=6)
            for a in reversed(alerts_snapshot[-50:]):
                ts = time.localtime(a["ts"])
                ts_s = time.strftime("%Y-%m-%d %H:%M:%S", ts)
                atree.insert("", "end", values=(ts_s, a["ip"], a["old_mac"], a["new_mac"]))
        else:
            tk.Label(analyze_window, text="No ARP alerts detected.", fg="white", bg="#1e1e1e",
                     font=("Segoe UI", 11)).pack(pady=6)

        if not snapshot:
            tk.Label(analyze_window, text="No captured packets yet — run the sniffer first.", fg="white", bg="#1e1e1e",
                     font=("Segoe UI", 12)).pack(pady=20)
            return

        proto_counter = collections.Counter(p["proto"] for p in snapshot)
        src_counter = collections.Counter(p["src"] for p in snapshot)
        top_src = src_counter.most_common(8)
        times = [p["ts"] for p in snapshot]
        t0 = min(times)
        bin_size = 10.0
        bins = {}
        for ts in times:
            b = int((ts - t0) // bin_size)
            bins[b] = bins.get(b, 0) + 1
        x_bins = sorted(bins.keys())
        y_counts = [bins[b] for b in x_bins]
        x_times = [t0 + b * bin_size for b in x_bins]
        x_labels = [time.strftime("%H:%M:%S", time.localtime(t)) for t in x_times]

        fig, axes = plt.subplots(3, 1, figsize=(8, 10), constrained_layout=True)
        fig.patch.set_facecolor("#1e1e1e")
        axes[0].pie([v for v in proto_counter.values()], labels=[f"{k} ({v})" for k, v in proto_counter.items()],
                    autopct="%1.1f%%", textprops={"color": "w"})
        axes[0].set_title("Protocol breakdown", color="w")

        ips, counts = zip(*top_src) if top_src else ([], [])
        axes[1].barh(range(len(ips)), counts)
        axes[1].set_yticks(range(len(ips)))
        axes[1].set_yticklabels(ips)
        axes[1].invert_yaxis()
        axes[1].set_title("Top source IPs (by packets)", color="w")
        axes[1].tick_params(axis='both', colors='w')

        axes[2].plot(x_labels, y_counts, marker='o')
        axes[2].set_title(f"Packets over time (bin={int(bin_size)}s)", color="w")
        axes[2].tick_params(axis='x', rotation=45, colors='w')
        axes[2].tick_params(axis='y', colors='w')

        for ax in axes:
            ax.set_facecolor("#151515")
            for spine in ax.spines.values(): spine.set_color("#333333")

        canvas = FigureCanvasTkAgg(fig, master=analyze_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

        summary_frame = tk.Frame(analyze_window, bg="#1e1e1e")
        summary_frame.pack(fill="x", padx=12, pady=(0, 12))
        total = len(snapshot)
        most_proto, most_proto_count = proto_counter.most_common(1)[0]
        tk.Label(summary_frame, text=f"Total: {total}", fg="white", bg="#1e1e1e", font=("Segoe UI", 11)).pack(
            side="left", padx=5)
        tk.Label(summary_frame, text=f"Most: {most_proto} ({most_proto_count})", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 11)).pack(side="left", padx=20)


if __name__ == "__main__":

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print('my ip is ' + local_ip)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, port))

        user = User()
        root = user.create_main_window()
        root.mainloop()
    except Exception as e:
        print(f"Failed to connect: {e}")
