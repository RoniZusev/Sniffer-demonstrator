import tkinter
from tkinter import ttk
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff

sniffing = False  # initial state: not sniffing

import tkinter as tk
from tkinter import ttk, messagebox

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
    parent.destroy()  # close main menu

    sniffer_window = tkinter.Tk()
    sniffer_window.state('zoomed')
    sniffer_window.title("Sniffer Active")
    sniffer_window.geometry("900x600")
    sniffer_window.configure(bg="#1e1e1e")

    # --- Top Label ---
    label = tkinter.Label(
        sniffer_window,
        text="Sniffer Ready!",
        font=("Arial", 20, "bold"),
        fg="white",
        bg="#1e1e1e"
    )
    label.pack(pady=10)

    # --- Filters ---
    filter_frame = tkinter.Frame(sniffer_window, bg="#1e1e1e")
    filter_frame.pack(pady=10)

    tkinter.Label(filter_frame, text="Filter by IP:", fg="white", bg="#1e1e1e").grid(row=0, column=0, padx=5)
    ip_filter_entry = tkinter.Entry(filter_frame)
    ip_filter_entry.grid(row=0, column=1, padx=10)

    tkinter.Label(filter_frame, text="Filter by Port:", fg="white", bg="#1e1e1e").grid(row=0, column=2, padx=5)
    port_filter_entry = tkinter.Entry(filter_frame)
    port_filter_entry.grid(row=0, column=3, padx=10)

    # --- Table ---
    columns = ("src_ip", "dst_ip", "port", "protocol")
    tree = ttk.Treeview(sniffer_window, columns=columns, show="headings")
    tree.heading("src_ip", text="Source IP")
    tree.heading("dst_ip", text="Destination IP")
    tree.heading("port", text="Port")
    tree.heading("protocol", text="Protocol")
    tree.pack(expand=True, fill="both", padx=10, pady=10)

    # --- Packet Processing ---
    def process_packet(packet):
        if IP in packet:
            if UDP in packet and (packet[UDP].sport == 5353 or packet[UDP].dport == 5353):
                return  # skip mDNS packets
            src = packet[IP].src
            dst = packet[IP].dst
            proto = (
                "TCP" if TCP in packet
                else "UDP" if UDP in packet
                else "ICMP" if ICMP in packet
                else "ARP" if ARP in packet
                else "IPv6" if packet.haslayer("IPv6")
                else "Ethernet" if Ether in packet
                else "Other"
            )
            port = "-"
            if TCP in packet:
                port = f"{packet[TCP].sport}->{packet[TCP].dport}"
            elif UDP in packet:
                port = f"{packet[UDP].sport}->{packet[UDP].dport}"

            ip_filter = ip_filter_entry.get().strip()
            port_filter = port_filter_entry.get().strip()

            # Apply filters
            if ip_filter and ip_filter not in (src, dst):
                return
            if port_filter and port_filter not in port:
                return

            tree.insert("", "end", values=(src, dst, port, proto))
            tree.yview_moveto(1)

    # --- Sniff Thread ---
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
    button_frame = tkinter.Frame(sniffer_window, bg="#1e1e1e")
    button_frame.pack(pady=15)

    start_btn = tkinter.Button(
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

    stop_btn = tkinter.Button(
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

    # --- Return Button at top-left ---
    return_btn = tkinter.Button(
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
    parent.destroy()
    analyze_window = tkinter.Tk()
    analyze_window.title("Analyze Malware")
    analyze_window.geometry("900x600")
    analyze_window.configure(bg="#1e1e1e")

    label = tkinter.Label(
        analyze_window,
        text="Analyze Cyber Attacks",
        font=("Arial", 20, "bold"),
        fg="white",
        bg="#1e1e1e"
    )
    label.pack(pady=10)

    # Return button for analyze window
    return_btn = tkinter.Button(
        analyze_window,
        text="Return to Menu",
        font=("Arial", 10),
        bg="#c00000",
        fg="white",
        width=15,
        height=2,
        command=lambda: [analyze_window.destroy(), create_main_window()]
    )
    return_btn.place(x=10, y=10)

    analyze_window.mainloop()


if __name__ == "__main__":
    app = create_main_window()
    app.mainloop()
