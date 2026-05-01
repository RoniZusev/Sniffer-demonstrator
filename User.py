
import socket
import time
import tkinter as tk
from tkinter import ttk
import threading
import matplotlib
import subprocess
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import collections
from scapy.all import sniff

from tkinter import filedialog, messagebox
from PIL import ImageGrab

import ctypes

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

server_ip = '127.0.0.1'
port = 12345

# Start with no sniffing
sniffing = False


captured_packets = []
captured_lock = threading.Lock()

arp_table = {}  # {ip: mac}
arp_alerts = []
arp_lock = threading.Lock()


class Authentication:
    # מקבלים את השקע כפרמטר
    def __init__(self, persistent_socket):
        self.client_socket = persistent_socket
        self.username = ""
        self.password = ""
        self.authenticated = False

    def authentication_screen(self):
        root = tk.Tk()
        root.title("Authentication for the Sniffer")
        root.configure(bg="#1e1e1e")

        # Window Setup
        window_width, window_height = 600, 650
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = (screen_w - window_width) // 2
        y = (screen_h - window_height) // 2
        root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        root.resizable(False, False)

        user_var = tk.StringVar()
        pass_var = tk.StringVar()

        # UI Elements
        tk.Label(root, text="Access Control", font=("Segoe UI", 24, "bold"), fg="white", bg="#1e1e1e").pack(
            pady=(40, 20))

        tk.Label(root, text="Username", font=("Segoe UI", 10), fg="#bdbdbd", bg="#1e1e1e").pack(anchor="w", padx=50)
        tk.Entry(root, textvariable=user_var, font=("Segoe UI", 12), bg="#2d2d2d", fg="white", borderwidth=0).pack(
            fill="x", padx=50, pady=(5, 15), ipady=8)

        tk.Label(root, text="Password", font=("Segoe UI", 10), fg="#bdbdbd", bg="#1e1e1e").pack(anchor="w", padx=50)
        tk.Entry(root, textvariable=pass_var, font=("Segoe UI", 12), bg="#2d2d2d", fg="white", borderwidth=0,
                 show="●").pack(fill="x", padx=50, pady=(5, 15), ipady=8)

        error_label = tk.Label(root, text="", fg="#ff3333", bg="#1e1e1e", font=("Segoe UI", 9))
        error_label.pack()

        # --- הלוגיקה (Functions) ---
        def on_login():
            self.username = user_var.get()
            self.password = pass_var.get()

            if not self.username or not self.password:
                error_label.config(text="Fields cannot be empty")
                return

            try:
                # משתמשים בחיבור הרציף הקיים! בלי with socket...
                auth_payload = f"AUTH|{self.username}|{self.password}"
                print(f"Sending: {auth_payload}")
                self.client_socket.sendall(auth_payload.encode())

                response = self.client_socket.recv(1024).decode().strip()
                print(f"Server response: {response}")

                if response == "Auth_success":
                    print("Access Granted!")
                    self.authenticated = True
                    root.destroy()
                else:
                    error_label.config(text="Access Denied: Invalid Credentials")
            except Exception as e:
                print(f"Login error: {e}")
                error_label.config(text="Connection Failed: Check if Server is running")

        def on_register():
            self.username = user_var.get()
            self.password = pass_var.get()

            if not self.username or not self.password:
                error_label.config(text="Fields cannot be empty", fg="#ff3333")
                return

            try:
                reg_payload = f"REGISTER|{self.username}|{self.password}"
                self.client_socket.sendall(reg_payload.encode())

                response = self.client_socket.recv(1024).decode().strip()

                if response == "Reg_success":
                    error_label.config(text="Registration Successful! You can now LOGIN.", fg="#00ff00")
                elif response == "Reg_fail_exists":
                    error_label.config(text="Username already taken. Choose another.", fg="#ff3333")
                else:
                    error_label.config(text="Registration Failed.", fg="#ff3333")
            except Exception as e:
                error_label.config(text="Connection Failed: Check if Server is running", fg="#ff3333")

        # --- הכפתורים (Buttons) ---
        tk.Button(root, text="LOGIN", font=("Segoe UI", 12, "bold"), bg="#00a046", fg="white",
                  cursor="hand2", borderwidth=0, command=on_login).pack(fill="x", padx=50, pady=20, ipady=10)

        tk.Button(root, text="REGISTER", font=("Segoe UI", 12, "bold"), bg="#2d2d2d", fg="#00a046",
                  cursor="hand2", borderwidth=1, command=on_register).pack(fill="x", padx=50, pady=(0, 20), ipady=10)

        root.mainloop()
        return self.authenticated

class User:

    def __init__(self, persistent_socket):
            self.analysis_socket = persistent_socket
            self.ip = '127.0.0.1'
            self.local_ip = socket.gethostbyname(socket.gethostname())

    def create_main_window(self):
        root = tk.Tk()
        root.title("Roni's Sniffer")
        root.configure(bg="#1e1e1e")

        window_width, window_height = 1100, 740
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

        only_my_ip_var = tk.BooleanVar(value=False)

        my_ip_toggle = tk.Checkbutton(
            filter_frame,
            text=f"Local Host ({self.local_ip})",
            variable=only_my_ip_var,
            bg="#2d2d2d", fg="#00ff00", selectcolor="#1a1a1a",
            activebackground="#2d2d2d", activeforeground="white",
            font=("Segoe UI", 10, "bold")
        )
        my_ip_toggle.place(relx=0.98, rely=0.5, anchor="e")


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
        tree.tag_configure("DHCP", foreground="#00ffff")
        tree.tag_configure("SMTP", foreground="#FFC107")

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


        def process_packet(packet):
            try:

                if not ip_filter.winfo_exists(): return

                raw_payload = bytes(packet)

                # שולחים את הפאקטה ישירות על הצינור הפתוח!
                self.analysis_socket.sendall(raw_payload)
                response = self.analysis_socket.recv(8192).decode()

                parts = response.split("|")
                if len(parts) < 8: return

                proto, src, dst, sport, dport, src_mac, dst_mac, raw_hex = parts[:8]
                port_info = f"{sport} > {dport}" if sport != "-" else "-"

                #arp_posioning
                if proto.startswith("ARP") and src != "Unknown" and src != "0.0.0.0":
                    if src in arp_table:

                        if arp_table[src] != src_mac:
                            with arp_lock:
                                arp_alerts.append({
                                    "ts": time.time(),
                                    "ip": src,
                                    "old_mac": arp_table[src],
                                    "new_mac": src_mac
                                })
                    else:
                        # אם ה-IP חדש, נלמד ונשמור את ה-MAC החוקי שלו
                        arp_table[src] = src_mac

                color_tag = "Other"
                if proto.startswith("TCP"):
                    color_tag = "TCP"
                elif proto.startswith("UDP"):
                    color_tag = "UDP"
                elif proto.startswith("ICMP"):
                    color_tag = "ICMP"
                elif proto.startswith("ARP"):
                    color_tag = "ARP"
                elif "DHCP" in proto:
                    color_tag = "DHCP"
                elif "SMTP" in proto:
                    color_tag = "SMTP"

                f_ip = ip_filter.get().lower().strip()
                f_port = port_filter.get().lower().strip()
                f_proto = proto_filter.get().lower().strip()

                show_packet = True

                if only_my_ip_var.get():
                    if self.local_ip != src and self.local_ip != dst:
                        show_packet = False

                if show_packet and f_ip and not (f_ip in src.lower() or f_ip in dst.lower()):
                    show_packet = False
                if show_packet and f_port and not (f_port in port_info.lower()):
                    show_packet = False
                if show_packet and f_proto and not (f_proto in proto.lower()):
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
                pass

        def sniff_thread():
            global sniffing
            sniffing = True
            sniff(prn=process_packet, store=False, stop_filter=stop_check)

        def stop_check(packet):
            global sniffing
            return not sniffing

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
        try:
            analyze_window.state('zoomed')
        except:
            analyze_window.geometry("1400x900")

        analyze_window.configure(bg="#1e1e1e")

        # 1. כותרת יחידה
        header = tk.Label(analyze_window, text="Analyze Cyber Attacks — Summary", font=("Arial", 18, "bold"),
                          fg="white", bg="#1e1e1e")
        header.pack(pady=10)

        # 2. כפתור חזור יחיד בצד שמאל
        return_btn = tk.Button(analyze_window, text="Return to Menu", font=("Arial", 10), bg="#c00000", fg="white",
                               width=15, height=2, command=analyze_window.destroy)
        return_btn.place(x=10, y=10)

        # 3. כפתור צילום מסך בצד ימין
        capture_btn = tk.Button(
            analyze_window,
            text="📸 Capture Screenshot",
            font=("Arial", 10, "bold"),
            bg="#00a046", fg="white",
            width=20, height=2,
            command=lambda: User._capture_active_window(analyze_window)
        )
        capture_btn.place(relx=0.98, x=0, y=10, anchor="ne")

        pie_btn = tk.Button(
            analyze_window,
            text="📊 Protocol Chart",
            font=("Arial", 10, "bold"),
            bg="#005088", fg="white",
            width=20, height=2,
            command=lambda: self.show_pie_chart(proto_counter)
        )

        pie_btn.place(relx=0.98, x=-260, y=10, anchor="ne")

        # 1. הגדרת זמן נוכחי וחלון זמן ( 10)
        now = time.time()
        window_size = 10

        with captured_lock:
            # 2. סינון פאקטות שהגיעו רק ב-10 השניות האחרונות
            recent_packets = [p for p in captured_packets if now - p["ts"] <= window_size]

        # 3. ספירת המקורות רק מהפאקטות האחרונות
        src_counter = collections.Counter(p["src"] for p in recent_packets)

        # 4. זיהוי איומים - למשל מעל 100 פאקטות ב-10 שניות
        threat_ips = {ip: count for ip, count in src_counter.items()
                      if count > 100 and ip != self.local_ip}

        if threat_ips:
            threats_frame = tk.LabelFrame(analyze_window, text="🚨 ACTIVE THREATS (Possible DoS) 🚨",
                                          bg="#330000", fg="#ff4444", font=("Segoe UI", 12, "bold"), labelanchor="n")
            threats_frame.pack(fill="x", padx=12, pady=(12, 0))

            for ip, count in threat_ips.items():
                threat_row = tk.Frame(threats_frame, bg="#330000")
                threat_row.pack(fill="x", padx=10, pady=5)

                tk.Label(threat_row, text=f"Suspicious IP: {ip}  |  Packets: {count}",
                         bg="#330000", fg="white", font=("Segoe UI", 11)).pack(side="left")

                tk.Button(threat_row, text="🛡️ BLOCK", bg="#cc0000", fg="white", font=("Segoe UI", 10, "bold"),
                          command=lambda current_ip=ip: User.block_ip_in_firewall(current_ip)).pack(side="right")

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

        fig, axes = plt.subplots(2, 1, figsize=(8, 8), constrained_layout=True)
        fig.patch.set_facecolor("#1e1e1e")

        # גרף 1: Top IPs (שהיה פעם axes[1], עכשיו הוא axes[0])
        ips, counts = zip(*top_src) if top_src else ([], [])
        axes[0].barh(range(len(ips)), counts, color="#00a046")
        axes[0].set_yticks(range(len(ips)))
        axes[0].set_yticklabels(ips)
        axes[0].invert_yaxis()
        axes[0].set_title("Top Source IPs (by packets)", color="w")
        axes[0].tick_params(axis='both', colors='w')

        # גרף 2: Packets over time (שהיה פעם axes[2], עכשיו הוא axes[1])
        axes[1].plot(x_labels, y_counts, marker='o', color="#ff4444")
        axes[1].set_title(f"Packets over time (bin={int(bin_size)}s)", color="w")
        axes[1].tick_params(axis='x', rotation=45, colors='w')
        axes[1].tick_params(axis='y', colors='w')

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

    @staticmethod
    def _save_screenshot_to_file(image_object):
        try:

            current_time = time.strftime("%Y-%m-%d_%H-%M-%S")

            fpath = filedialog.asksaveasfilename(
                defaultextension=".png",  # סיומת ברירת מחדל
                initialfile=f"Packet-Anylize_F{current_time}.png",
                title="Save Packet Analysis Screenshot As...",
                filetypes=[("PNG Image", "*.png"), ("JPG Image", "*.jpg"), ("All Files", "*.*")]
            )

            if fpath:
                image_object.save(fpath)
                # מציג הודעת הצלחה קטנה (TopLevel) מעל מסך הניתוח
                messagebox.showinfo("Success", f"Screenshot saved to:\n{fpath}")
        except Exception as e:

            messagebox.showerror("Error", f"Failed to save screenshot:\n{str(e)}")

    @staticmethod
    def _capture_active_window(window_object):
        """תופסת צילום של החלון הספציפי שקיבלה, פותחת דיאלוג שמירה ושומרת."""
        try:
            x = window_object.winfo_rootx()
            y = window_object.winfo_rooty()
            w = window_object.winfo_width()
            h = window_object.winfo_height()

            bbox = (x, y, x + w, y + h)

            screenshot = ImageGrab.grab(bbox=bbox)
            # ---------------------

            User._save_screenshot_to_file(screenshot)
        except Exception as e:
            messagebox.showerror("Capture Error", f"Could not capture window:\n{str(e)}")

    def show_pie_chart(self, proto_counter):
        # יצירת החלון
        pie_win = tk.Toplevel()
        pie_win.title("Protocol Breakdown Chart")
        pie_win.geometry("650x620")
        pie_win.configure(bg="#1e1e1e")

        #  הוספה: כפתור צילום מסך בתוך חלון העוגה
        capture_btn = tk.Button(
            pie_win,
            text="📸 Capture Diagram",
            font=("Arial", 10, "bold"),
            bg="#00a046", fg="white",
            width=20, height=2,
            command=lambda: User._capture_active_window(pie_win)
        )
        # נמקם אותו בפינה הימנית העליונה עם שוליים
        capture_btn.pack(anchor="ne", padx=10, pady=10)

        fig, ax = plt.subplots(figsize=(6, 5), constrained_layout=True)
        fig.patch.set_facecolor("#1e1e1e")
        ax.set_facecolor("#1e1e1e")

        total_packets = sum(proto_counter.values())
        threshold = total_packets * 0.05
        filtered_protos = {}
        other_count = 0

        for k, v in proto_counter.items():
            if v >= threshold:
                filtered_protos[k] = v
            else:
                other_count += v

        if other_count > 0:
            filtered_protos["Other (<5%)"] = other_count

        wedges, texts, autotexts = ax.pie(
            filtered_protos.values(),
            autopct="%1.1f%%",
            textprops={"color": "w", "weight": "bold"},
            startangle=90
        )

        ax.legend(
            wedges,
            [f"{k} ({v} pkts)" for k, v in filtered_protos.items()],
            title="Protocols",
            loc="center left",
            bbox_to_anchor=(0.9, 0, 0.5, 1),
            labelcolor="white"
        )
        ax.set_title("Protocol Distribution", color="white", fontdict={'fontsize': 16, 'fontweight': 'bold'})

        canvas = FigureCanvasTkAgg(fig, master=pie_win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=(0, 20))

    @staticmethod
    def block_ip_in_firewall(ip_address):
        """חוסם כתובת IP נכנסת ב-Windows Firewall באמצעות פקודת netsh."""
        rule_name = f"Sniffer_Block_{ip_address}"

        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            messagebox.showinfo("Firewall Updated", f"Successfully blocked IP:\n{ip_address}\n\nRule Name: {rule_name}")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to block IP {ip_address}.\nMake sure you are running the IDE/Terminal as Administrator.\n\nError: {e.stderr}"
            messagebox.showerror("Firewall Error", error_msg)


if __name__ == "__main__":
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"My local IP: {local_ip}")

    # פרטי השרת (שנה ל-IP של השרת שלך)
    server_ip = '127.0.0.1'
    server_port = 12345

    # 1. יוצרים את החיבור פעם אחת וזהו!
    main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        main_socket.settimeout(5)
        print("Connecting to server...")
        main_socket.connect((server_ip, server_port))
        main_socket.settimeout(None)
        print("[CONNECTED] Persistent link established.")

        auth = Authentication(main_socket)

        if auth.authentication_screen():
            print("Login successful!")
            user = User(main_socket)
            root = user.create_main_window()
            root.mainloop()
        else:
            print("Authentication failed or window closed.")

    except Exception as e:
        print(f"[FATAL ERROR] Could not connect to the server: {e}")
        messagebox.showerror("Connection Error", "Cannot reach the Analysis Server. Is it running?")

    finally:
        main_socket.close()
        print("[DISCONNECTED] Socket closed safely.")
