import tkinter
from tkinter import ttk
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff

sniffing = False #הגדרה ראשונית לשלילה  כי אנחנו לא מתחילים לסרוק את הפקטות 

def app_menu():
    root = tkinter.Tk()
    root.title("Roni's Sniffer")
    root.geometry("800x500")
    root.configure(bg="#1e1e1e")

    title_label = tkinter.Label(
        root,
        text="The ultimate Sniffer",
        font=("Arial", 50, "bold"),
        fg="white",
        bg="#202020"
    )
    title_label.pack(pady=40)

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
    start_button.pack(pady=50)

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

    #the way this works is by global var - sniffing
    global sniffing
    #this var decides if the app continue to search for packets or not and display them.
    parent.destroy()

    sniffer_window = tkinter.Tk()
    sniffer_window.title("Sniffer Active")
    sniffer_window.geometry("900x600")
    sniffer_window.configure(bg="#1e1e1e")

    label = tkinter.Label(
        sniffer_window,
        text="Sniffer Ready!",
        font=("Arial", 20, "bold"),
        fg="white",
        bg="#1e1e1e"
    )
    label.pack(pady=10)

    # --- FILTER FIELDS ---
    filter_frame = tkinter.Frame(sniffer_window, bg="#1e1e1e")
    filter_frame.pack(pady=10)

    tkinter.Label(filter_frame, text="Filter by IP:", fg="white", bg="#1e1e1e").grid(row=0, column=0, padx=5)
    ip_filter_entry = tkinter.Entry(filter_frame)
    ip_filter_entry.grid(row=0, column=1, padx=10)

    tkinter.Label(filter_frame, text="Filter by Port:", fg="white", bg="#1e1e1e").grid(row=0, column=2, padx=5)
    port_filter_entry = tkinter.Entry(filter_frame)
    port_filter_entry.grid(row=0, column=3, padx=10)

    # --- TABLE ---
    columns = ("src_ip", "dst_ip", "port", "protocol")
    tree = ttk.Treeview(sniffer_window, columns=columns, show="headings")
    tree.heading("src_ip", text="Source IP")
    tree.heading("dst_ip", text="Destination IP")
    tree.heading("port", text="Port")
    tree.heading("protocol", text="Protocol")
    tree.pack(expand=True, fill="both", padx=10, pady=10)

    # --- FUNCTIONS ---
    def process_packet(packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            port = "-"
            if TCP in packet:
                port = f"{packet[TCP].sport}->{packet[TCP].dport}" #display the port from source to arrival
            elif UDP in packet:
                port = f"{packet[UDP].sport}->{packet[UDP].dport}"#display the port from source to arrival

            # Get filter values
            ip_filter = ip_filter_entry.get().strip()
            port_filter = port_filter_entry.get().strip()

            # --- Apply filters ---
            if ip_filter and ip_filter not in (src, dst):
                return
            if port_filter and port_filter not in port:
                return

            tree.insert("", "end", values=(src, dst, port, proto))
            tree.yview_moveto(1)

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

    # --- BUTTONS ---
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

    sniffer_window.mainloop()


if __name__ == "__main__":
    app_menu()

