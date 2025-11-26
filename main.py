from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff

import tkinter as tk
from tkinter import ttk

import matplotlib
matplotlib.use("Agg")  
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import collections
import threading

# Start with no sniffing
sniffing = False

# Shared storage for captured packet summaries (used by Analyze window)
captured_packets = []
captured_lock = threading.Lock()

arp_table = {}   # {ip: mac}
arp_alerts = []
arp_lock = threading.Lock()

def create_main_window():
    root = tk.Tk()
    root.title("Roni's Sniffer")
    root.configure(bg="#1e1e1e")

    # Window size & center
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
    header.grid(row=0, column=0, sticky="nsew", padx=24, pady=(18,6))
    title = tk.Label(header, text="The Ultimate Sniffer", font=header_font, fg="white", bg="#1e1e1e")
    title.pack(anchor="center")
    subtitle = tk.Label(header, text="Inspect, analyze and debug network traffic", font=sub_font, fg="#bdbdbd", bg="#1e1e1e")
    subtitle.pack(anchor="center", pady=(6,0))

    # Main frame (center)
    main = tk.Frame(root, bg="#151515")
    main.grid(row=1, column=0, sticky="nsew", padx=20, pady=18)
    main.grid_rowconfigure(0, weight=1)
    main.grid_columnconfigure((0,1), weight=1, uniform="col")

    # Left card - Regular Sniffer
    left_card = tk.Frame(main, bg="#1c1c1c", padx=18, pady=18)
    left_card.grid(row=0, column=0, sticky="nsew", padx=(0,10), pady=10)
    lbl1 = tk.Label(left_card, text="Regular Sniffer", font=("Segoe UI", 18, "bold"), fg="white", bg="#1c1c1c")
    lbl1.grid(row=0, column=0, sticky="w")
    desc1 = tk.Label(left_card, text="Capture live traffic from an interface and view packet summaries in realtime.", font=sub_font, fg="#cfcfcf", bg="#1c1c1c", wraplength=380, justify="left")
    desc1.grid(row=1, column=0, sticky="w", pady=(8,18))
    start_btn = ttk.Button(left_card, text="▶ Start Sniffer (Ctrl+S)", style="Big.TButton",
                           command=lambda: start_sniffer(root))
    start_btn.grid(row=2, column=0, sticky="w")

    # Right card - Analyze Malware
    right_card = tk.Frame(main, bg="#1c1c1c", padx=18, pady=18)
    right_card.grid(row=0, column=1, sticky="nsew", padx=(10,0), pady=10)
    lbl2 = tk.Label(right_card, text="Analyze Malware", font=("Segoe UI", 18, "bold"), fg="white", bg="#1c1c1c")
    lbl2.grid(row=0, column=0, sticky="w")
    desc2 = tk.Label(right_card, text="Run deeper analysis on suspicious packets or payloads to detect anomalies.", font=sub_font, fg="#cfcfcf", bg="#1c1c1c", wraplength=380, justify="left")
    desc2.grid(row=1, column=0, sticky="w", pady=(8,18))
    analyze_btn = ttk.Button(right_card, text="⚠ Analyze Malware (Ctrl+A)", style="Big.TButton",
                             command=lambda: anylaze_problems(root))
    analyze_btn.grid(row=2, column=0, sticky="w")

    # Keyboard shortcuts
    root.bind_all("<Control-s>", lambda _e: start_sniffer(root))
    root.bind_all("<Control-S>", lambda _e: start_sniffer(root))
    root.bind_all("<Control-a>", lambda _e: anylaze_problems(root))
    root.bind_all("<Control-A>", lambda _e: anylaze_problems(root))

    # Footer
    footer = tk.Frame(root, bg="#202020")
    footer.grid(row=2, column=0, sticky="ew")
    footer.grid_columnconfigure(0, weight=1)
    author = tk.Label(footer, text="© Roni Zusev", font=footer_font, fg="#bdbdbd", bg="#202020")
    author.grid(row=0, column=0, columnspan=2, sticky="n", pady=8)

    return root

def start_sniffer(parent):
    global sniffing
    sniffer_window = tk.Toplevel(parent)
    
    try: # Used to make the program cross platform, as this command is not supported in Linux\Macos
        sniffer_window.state('zoomed')
    except tk.TclError:
        print("'sniffer_window.state('zoomed')' is not supported, ignored")

    sniffer_window.title("Sniffer Active")
    sniffer_window.geometry("900x600")
    sniffer_window.configure(bg="#1e1e1e")

    # --- Top Label ---
    label = tk.Label(
        sniffer_window,
        text="Sniffer Ready!",
        font=("Arial", 20, "bold"),
        fg="white",
        bg="#1e1e1e"
    )
    label.pack(pady=10)

    # --- Filters ---
    filter_frame = tk.Frame(sniffer_window, bg="#1e1e1e")
    filter_frame.pack(pady=10)

    tk.Label(filter_frame, text="Filter by IP:", fg="white", bg="#1e1e1e").grid(row=0, column=0, padx=5)
    ip_filter_entry = tk.Entry(filter_frame)
    ip_filter_entry.grid(row=0, column=1, padx=10)

    tk.Label(filter_frame, text="Filter by Port:", fg="white", bg="#1e1e1e").grid(row=0, column=2, padx=5)
    port_filter_entry = tk.Entry(filter_frame)
    port_filter_entry.grid(row=0, column=3, padx=10)

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
    tree.tag_configure("ICMP", foreground="yellow")
    tree.tag_configure("ARP", foreground="lightgreen")
    tree.tag_configure("ALERT", foreground="red")
    tree.tag_configure("Other", foreground="black")

    # --- Packet Processing ---
    def process_packet(packet):
        try:
            # decide what kind of packet this is and extract common fields
            proto = "Other"
            src = "-"
            dst = "-"
            port = "-"

            if ARP in packet:
                src = packet[ARP].psrc
                dst = packet[ARP].pdst
                proto = "ARP"
                port = "-"

                src_mac = packet[ARP].hwsrc
                arp_op = int(packet[ARP].op)  # request=1, reply=2

                # update global arp table and detect anomalies
                with arp_lock:
                    prev_mac = arp_table.get(src)
                    if prev_mac is None:
                        arp_table[src] = src_mac
                    else:
                        if prev_mac != src_mac:
                            # record an alert (don't block the GUI)
                            alert = {
                                "ts": time.time(),
                                "ip": src,
                                "old_mac": prev_mac,
                                "new_mac": src_mac
                            }
                            arp_alerts.append(alert)
                            # update mapping to the new observed MAC
                            arp_table[src] = src_mac

                # fall through to add to captured_packets and Treeview (with ARP tag)
            elif IP in packet:
                # skip mDNS
                if UDP in packet and (packet[UDP].sport == 5353 or packet[UDP].dport == 5353):
                    return

                src = packet[IP].src
                dst = packet[IP].dst
                proto = (
                    "TCP" if TCP in packet
                    else "UDP" if UDP in packet
                    else "ICMP" if ICMP in packet
                    else "IPv6" if packet.haslayer("IPv6")
                    else "Ethernet" if Ether in packet
                    else "Other"
                )

                # build port string for TCP/UDP, keep '-' otherwise
                port = "-"
                if TCP in packet:
                    port = f"{packet[TCP].sport}->{packet[TCP].dport}"
                elif UDP in packet:
                    port = f"{packet[UDP].sport}->{packet[UDP].dport}"
            else:
                # we don't handle other types here
                return

            # apply UI filters (if any)
            ip_filter = ip_filter_entry.get().strip()
            port_filter = port_filter_entry.get().strip()
            if ip_filter and ip_filter not in (src, dst):
                return
            if port_filter and port_filter not in port:
                return

            # Thread-safe append to the shared captured_packets list
            with captured_lock:
                # store mac only for ARP to help analysis later
                entry = {
                    "ts": time.time(),
                    "src": src,
                    "dst": dst,
                    "port": port,
                    "proto": proto
                }
                if proto == "ARP":
                    entry["mac"] = packet[ARP].hwsrc
                captured_packets.append(entry)

            # Insert into Treeview
            # If this ARP packet caused a recent alert, tag as ALERT
            tag = proto
            # quick check: tag alert if newest arp_alerts refers to this ip and is recent
            if proto == "ARP":
                with arp_lock:
                    if arp_alerts and arp_alerts[-1]["ip"] == src and (time.time() - arp_alerts[-1]["ts"]) < 2.0:
                        tag = "ALERT"

            tree.insert("", "end", values=(src, dst, port, proto), tags=(tag,))
            tree.yview_moveto(1)

        except Exception as e:
            # keep sniffing alive; optionally log errors for debug
            print("process_packet error:", e)
            return

    def sniff_thread():
        global sniffing
        sniffing = True
        while sniffing:
            sniff(count=1, prn=process_packet, store=False)

    def start_pressed():
        threading.Thread(target=sniff_thread, daemon=True).start()

    def stop_pressed():
        global sniffing
        sniffing = False

    def return_to_menu():
        global sniffing
        sniffing = False
        sniffer_window.destroy()
        create_main_window()

    # --- Buttons ---
    button_frame = tk.Frame(sniffer_window, bg="#1e1e1e")
    button_frame.pack(pady=15)

    start_btn = tk.Button(
        button_frame,
        text="Start Sniffing",
        font=("Arial", 14),
        bg="#00b050",
        fg="white",
        width=15,
        height=2,
        command=start_pressed
    )
    start_btn.grid(row=0, column=0, padx=10)

    stop_btn = tk.Button(
        button_frame,
        text="Stop Sniffing",
        font=("Arial", 14),
        bg="#c00000",
        fg="white",
        width=15,
        height=2,
        command=stop_pressed
    )
    stop_btn.grid(row=0, column=1, padx=10)

    # Return button
    return_btn = tk.Button(
        sniffer_window,
        text="Return to Menu",
        font=("Arial", 10),
        bg="#c00000",
        fg="white",
        width=15,
        height=2,
        command=return_to_menu
    )
    return_btn.place(x=10, y=10)

    sniffer_window.mainloop()

def anylaze_problems(parent):
    
    analyze_window = tk.Toplevel(parent)
    analyze_window.title("Analyze Malware — Findings")
    analyze_window.geometry("1000x800")
    analyze_window.configure(bg="#1e1e1e")

    header = tk.Label(analyze_window, text="Analyze Cyber Attacks — Summary", font=("Arial", 18, "bold"), fg="white", bg="#1e1e1e")
    header.pack(pady=10)

    # Return button
    return_btn = tk.Button(
        analyze_window,
        text="Return to Menu",
        font=("Arial", 10),
        bg="#c00000",
        fg="white",
        width=15,
        height=2,
        command=analyze_window.destroy
    )
    return_btn.place(x=10, y=10)

    with captured_lock:
        snapshot = list(captured_packets)

    # Snapshot of ARP alerts
    with arp_lock:
        alerts_snapshot = list(arp_alerts)

    # ARP Alerts section (shown first)
    if alerts_snapshot:
        alerts_frame = tk.LabelFrame(analyze_window, text="Threats — ARP Alerts", bg="#1e1e1e", fg="white", labelanchor="n")
        alerts_frame.pack(fill="x", padx=12, pady=(8, 12))

        # Treeview for alerts
        acols = ("time", "ip", "old_mac", "new_mac")
        atree = ttk.Treeview(alerts_frame, columns=acols, show="headings", height=min(6, len(alerts_snapshot)))
        atree.heading("time", text="Time")
        atree.heading("ip", text="IP")
        atree.heading("old_mac", text="Old MAC")
        atree.heading("new_mac", text="New MAC")
        atree.pack(fill="x", padx=6, pady=6)

        for a in reversed(alerts_snapshot[-50:]):  # show most recent up to 50
            ts = time.localtime(a["ts"])
            ts_s = time.strftime("%Y-%m-%d %H:%M:%S", ts)
            atree.insert("", "end", values=(ts_s, a["ip"], a["old_mac"], a["new_mac"]))

        # small explanation label
        tk.Label(alerts_frame, text="Entries above indicate IP addresses that were observed with a different MAC address — possible ARP spoofing.",
                 fg="#e6e6e6", bg="#1e1e1e", font=("Segoe UI", 10), wraplength=900, justify="left").pack(padx=6, pady=(0,8))
    else:
        tk.Label(analyze_window, text="No ARP alerts detected.", fg="white", bg="#1e1e1e", font=("Segoe UI", 11)).pack(pady=6)

    if not snapshot:
        tk.Label(analyze_window, text="No captured packets yet — run the sniffer first.", fg="white", bg="#1e1e1e", font=("Segoe UI", 12)).pack(pady=20)
        return

    # Compute protocol counts
    proto_counter = collections.Counter(p["proto"] for p in snapshot)

    # Top source IPs
    src_counter = collections.Counter(p["src"] for p in snapshot)
    top_src = src_counter.most_common(8)  # show top 8

    # Packet time series (per 10-second bins)
    times = [p["ts"] for p in snapshot]
    t0 = min(times)
    # create bins (10-second)
    bin_size = 10.0
    bins = {}
    for ts in times:
        b = int((ts - t0) // bin_size)
        bins[b] = bins.get(b, 0) + 1
    x_bins = sorted(bins.keys())
    y_counts = [bins[b] for b in x_bins]
    x_times = [t0 + b * bin_size for b in x_bins]
    x_labels = [time.strftime("%H:%M:%S", time.localtime(t)) for t in x_times]

    # Create a Matplotlib figure with 3 subplots stacked vertically
    fig, axes = plt.subplots(3, 1, figsize=(8, 10), constrained_layout=True)
    fig.patch.set_facecolor("#1e1e1e")
    # Protocol pie
    axes[0].pie([v for v in proto_counter.values()], labels=[f"{k} ({v})" for k, v in proto_counter.items()],
                autopct="%1.1f%%", textprops={"color": "w"})
    axes[0].set_title("Protocol breakdown", color="w")

    # Top source IPs bar
    ips, counts = zip(*top_src) if top_src else ([], [])
    axes[1].barh(range(len(ips)), counts)
    axes[1].set_yticks(range(len(ips)))
    axes[1].set_yticklabels(ips)
    axes[1].invert_yaxis()
    axes[1].set_title("Top source IPs (by packets)", color="w")
    # color labels white
    axes[1].tick_params(axis='x', colors='w')
    axes[1].tick_params(axis='y', colors='w')

    # Time-series
    axes[2].plot(x_labels, y_counts, marker='o')
    axes[2].set_title(f"Packets over time (bin={int(bin_size)}s)", color="w")
    axes[2].set_ylabel("Packets", color="w")
    axes[2].tick_params(axis='x', rotation=45, colors='w')
    axes[2].tick_params(axis='y', colors='w')

    # Set spines / background colors
    for ax in axes:
        ax.set_facecolor("#151515")
        for spine in ax.spines.values():
            spine.set_color("#333333")
        for label in (ax.get_xticklabels() + ax.get_yticklabels()):
            label.set_color("white")

    # Embed the plot in Tkinter
    canvas = FigureCanvasTkAgg(fig, master=analyze_window)
    canvas.draw()
    widget = canvas.get_tk_widget()
    widget.pack(fill="both", expand=True, padx=10, pady=10)

    # Optional: provide a small textual summary
    summary_frame = tk.Frame(analyze_window, bg="#1e1e1e")
    summary_frame.pack(fill="x", padx=12, pady=(0,12))
    total = len(snapshot)
    most_proto, most_proto_count = proto_counter.most_common(1)[0]
    tk.Label(summary_frame, text=f"Total captured packets: {total}", fg="white", bg="#1e1e1e", font=("Segoe UI", 11)).pack(side="left", padx=5)
    tk.Label(summary_frame, text=f"Most common protocol: {most_proto} ({most_proto_count})", fg="white", bg="#1e1e1e", font=("Segoe UI", 11)).pack(side="left", padx=20)

if __name__ == "__main__":
    app = create_main_window()
    app.mainloop()
