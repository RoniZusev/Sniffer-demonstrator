import tkinter
from tkinter import ttk
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff

sniffing = False  # initial state: not sniffing

def app_menu():
    root = tkinter.Tk()
    # Set the window size
    window_width = 800
    window_height = 500

    # Center the window
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    center_x = int(screen_width / 2 - window_width / 2)
    center_y = int(screen_height / 2 - window_height / 2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

    root.title("Roni's Sniffer")
    root.configure(bg="#1e1e1e")

    # --- Title ---
    title_label = tkinter.Label(
        root,
        text="The ultimate Sniffer",
        font=("Arial", 50, "bold"),
        fg="white",
        bg="#202020"
    )
    title_label.pack(pady=40)

    # --- Buttons ---
    start_button = tkinter.Button(
        root,
        text="Regular Sniffer",
        font=("Arial", 14),
        bg="#00b050",
        fg="white",
        width=15,
        height=2,
        command=lambda: start_sniffer(root)
    )
    start_button.pack(pady=10)

    anylaze_button = tkinter.Button(
        root,
        text="Analyze Malware",
        font=("Arial", 14),
        bg="red",
        fg="white",
        width=15,
        height=2,
        command=lambda: anylaze_problems(root)
    )
    anylaze_button.pack(pady=15)

    # --- Footer ---
    honor_label = tkinter.Label(
        root,
        text="Roni Zusev",
        font=("Arial", 18),
        fg="white",
        bg="#202020"
    )
    honor_label.pack(side="left", anchor="s", padx=20, pady=30)

    root.mainloop()


def start_sniffer(parent):
    global sniffing
    parent.destroy()  # close main menu

    sniffer_window = tkinter.Tk()
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
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
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
        app_menu()

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
        command=lambda: [analyze_window.destroy(), app_menu()]
    )
    return_btn.place(x=10, y=10)

    analyze_window.mainloop()


if __name__ == "__main__":
    app_menu()
