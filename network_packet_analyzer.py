import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime
import threading
import pandas as pd

# ---------------- GLOBAL VARIABLES ---------------- #

capturing = False
packet_count = 0
packet_data = []

# ---------------- PACKET PROCESSING ---------------- #

def process_packet(packet):
    global packet_count

    try:
        if not packet.haslayer(IP):
            return

        current_time = datetime.now().strftime("%H:%M:%S")

        src = packet[IP].src
        dst = packet[IP].dst
        length = len(packet)

        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        payload = "Unknown"

        # DNS Query
        if packet.haslayer(DNSQR):
            try:
                domain = packet[DNSQR].qname.decode()
                payload = f"DNS Query: {domain}"
            except:
                payload = "DNS Query"

        # DNS Response
        elif packet.haslayer(DNS):
            payload = "DNS Response"

        # ICMP
        elif packet.haslayer(ICMP):
            if packet[ICMP].type == 8:
                payload = "Ping Request"
            elif packet[ICMP].type == 0:
                payload = "Ping Reply"
            else:
                payload = "ICMP Packet"

        # TCP
        elif packet.haslayer(TCP):

            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags

            if sport == 443 or dport == 443:
                payload = "HTTPS/TLS Traffic"

            elif flags == "S":
                payload = "TCP SYN"

            elif flags == "SA":
                payload = "TCP SYN-ACK"

            elif flags == "A":
                payload = "TCP ACK"

            else:
                payload = "TCP Packet"

            if packet.haslayer(Raw):
                try:
                    raw_text = packet[Raw].load.decode(
                        errors="ignore"
                    )

                    if raw_text.startswith("GET"):
                        payload = "HTTP GET Request"

                    elif raw_text.startswith("POST"):
                        payload = "HTTP POST Request"

                    elif "HTTP/" in raw_text:
                        payload = "HTTP Response"

                except:
                    pass

        # UDP
        elif packet.haslayer(UDP):
            payload = "UDP Packet"

        row = (
            current_time,
            src,
            dst,
            protocol,
            length,
            payload
        )

        packet_data.append(row)
        packet_count += 1

        root.after(
            0,
            lambda r=row: tree.insert(
                "",
                "end",
                values=r
            )
        )

        root.after(
            0,
            lambda: count_label.config(
                text=f"Packets Captured: {packet_count}"
            )
        )

    except Exception as e:
        print("Error:", e)

# ---------------- SNIFFING ---------------- #

def sniff_packets():
    sniff(
        prn=process_packet,
        store=False,
        stop_filter=lambda x: not capturing
    )

def start_capture():
    global capturing

    if capturing:
        return

    capturing = True

    status_label.config(
        text="Status: Capturing Packets..."
    )

    thread = threading.Thread(
        target=sniff_packets,
        daemon=True
    )

    thread.start()

def stop_capture():
    global capturing

    capturing = False

    status_label.config(
        text="Status: Capture Stopped"
    )

# ---------------- EXPORT CSV ---------------- #

def export_csv():

    if not packet_data:
        messagebox.showwarning(
            "Warning",
            "No packets captured."
        )
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")]
    )

    if file_path:

        df = pd.DataFrame(
            packet_data,
            columns=[
                "Time",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Length",
                "Payload"
            ]
        )

        df.to_csv(file_path, index=False)

        messagebox.showinfo(
            "Success",
            "CSV exported successfully!"
        )

# ---------------- CLEAR ---------------- #

def clear_packets():
    global packet_count

    tree.delete(*tree.get_children())

    packet_data.clear()

    packet_count = 0

    count_label.config(
        text="Packets Captured: 0"
    )

    status_label.config(
        text="Status: Ready"
    )

# ---------------- GUI ---------------- #

root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("1400x750")

title = tk.Label(
    root,
    text="Network Packet Analyzer",
    font=("Arial", 20, "bold")
)
title.pack(pady=10)

# Buttons Frame

top_frame = tk.Frame(root)
top_frame.pack(pady=10)

tk.Button(
    top_frame,
    text="Start Capture",
    command=start_capture,
    bg="green",
    fg="white",
    width=15
).grid(row=0, column=0, padx=5)

tk.Button(
    top_frame,
    text="Stop Capture",
    command=stop_capture,
    bg="orange",
    fg="white",
    width=15
).grid(row=0, column=1, padx=5)

tk.Button(
    top_frame,
    text="Export CSV",
    command=export_csv,
    bg="blue",
    fg="white",
    width=15
).grid(row=0, column=2, padx=5)

tk.Button(
    top_frame,
    text="Clear",
    command=clear_packets,
    bg="red",
    fg="white",
    width=15
).grid(row=0, column=3, padx=5)

count_label = tk.Label(
    top_frame,
    text="Packets Captured: 0",
    font=("Arial", 12, "bold")
)

count_label.grid(
    row=0,
    column=4,
    padx=20
)

# Table

columns = (
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Length",
    "Payload"
)

tree_frame = tk.Frame(root)
tree_frame.pack(fill="both", expand=True)

tree = ttk.Treeview(
    tree_frame,
    columns=columns,
    show="headings"
)

for col in columns:
    tree.heading(col, text=col)

tree.column("Time", width=100)
tree.column("Source IP", width=180)
tree.column("Destination IP", width=180)
tree.column("Protocol", width=100)
tree.column("Length", width=100)
tree.column("Payload", width=700)

scroll_y = ttk.Scrollbar(
    tree_frame,
    orient="vertical",
    command=tree.yview
)

tree.configure(
    yscrollcommand=scroll_y.set
)

tree.pack(
    side="left",
    fill="both",
    expand=True
)

scroll_y.pack(
    side="right",
    fill="y"
)

# Status Bar

status_label = tk.Label(
    root,
    text="Status: Ready",
    bd=1,
    relief="sunken",
    anchor="w"
)

status_label.pack(
    fill="x",
    side="bottom"
)

root.mainloop()