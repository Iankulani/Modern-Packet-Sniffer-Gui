import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Ether, IP
import threading

class PacketSniffer:
    def __init__(self, ip_filter, mac_filter, gui_callback):
        self.ip_filter = ip_filter
        self.mac_filter = mac_filter
        self.gui_callback = gui_callback
        self.sniffing = False

    def packet_filter(self, packet):
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if self.mac_filter and self.mac_filter.lower() not in [src_mac.lower(), dst_mac.lower()]:
                return False

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if self.ip_filter and self.ip_filter not in [src_ip, dst_ip]:
                return False

        return True

    def start_sniffing(self):
        self.sniffing = True
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        if self.packet_filter(packet):
            info = {
                "src_ip": packet[IP].src if IP in packet else "N/A",
                "dst_ip": packet[IP].dst if IP in packet else "N/A",
                "src_mac": packet[Ether].src if Ether in packet else "N/A",
                "dst_mac": packet[Ether].dst if Ether in packet else "N/A",
                "proto": packet[IP].proto if IP in packet else "N/A"
            }
            self.gui_callback(info)

    def stop_sniffing(self):
        self.sniffing = False


class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity IP/MAC Packet Monitor (Educational Only)")
        self.root.configure(bg="#003300")  # Dark green background

        self.sniffer = None

        label_style = {'bg': '#003300', 'fg': 'white', 'font': ('Helvetica', 10)}
        entry_style = {'bg': '#b3ffb3', 'fg': '#000000'}

        # Input Fields
        tk.Label(root, text="IP Address Filter (Optional):", **label_style).grid(row=0, column=0, pady=5, padx=5, sticky='w')
        self.ip_entry = tk.Entry(root, **entry_style)
        self.ip_entry.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(root, text="MAC Address Filter (Optional):", **label_style).grid(row=1, column=0, pady=5, padx=5, sticky='w')
        self.mac_entry = tk.Entry(root, **entry_style)
        self.mac_entry.grid(row=1, column=1, pady=5, padx=5)

        # Buttons
        self.start_btn = tk.Button(root, text="Start Monitoring", command=self.start_monitoring,
                                   bg="#009900", fg="white", font=("Helvetica", 10, "bold"))
        self.start_btn.grid(row=2, column=0, pady=10)

        self.stop_btn = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring,
                                  bg="#006600", fg="white", font=("Helvetica", 10, "bold"), state=tk.DISABLED)
        self.stop_btn.grid(row=2, column=1, pady=10)

        # Packet Table
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#004d00", foreground="white", rowheight=25, fieldbackground="#004d00")
        style.configure("Treeview.Heading", background="#006600", foreground="white", font=('Helvetica', 10, 'bold'))

        self.tree = ttk.Treeview(root, columns=('Src IP', 'Dst IP', 'Src MAC', 'Dst MAC', 'Protocol'), show='headings')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        self.tree.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def add_packet(self, packet_info):
        self.tree.insert('', 'end', values=(
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["src_mac"],
            packet_info["dst_mac"],
            packet_info["proto"]
        ))

    def start_monitoring(self):
        ip_filter = self.ip_entry.get().strip()
        mac_filter = self.mac_entry.get().strip()

        self.sniffer = PacketSniffer(ip_filter, mac_filter, self.add_packet)
        self.sniff_thread = threading.Thread(target=self.sniffer.start_sniffing, daemon=True)
        self.sniff_thread.start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_monitoring(self):
        if self.sniffer:
            self.sniffer.stop_sniffing()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()
