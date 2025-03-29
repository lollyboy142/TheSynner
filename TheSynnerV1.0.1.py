from scapy.all import IP, TCP, send
import tkinter as tk
from tkinter import messagebox

def send_syn_packet_gui():
    target_ip = entry_ip.get()
    target_port = entry_port.get()
    packet_count = entry_count.get()

    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    if not target_port.isdigit() or int(target_port) <= 0:
        messagebox.showerror("Error", "Please enter a valid port number.")
        return

    if not packet_count.isdigit() or int(packet_count) <= 0:
        messagebox.showerror("Error", "Please enter a valid number of packets.")
        return

    try:
        # Create an IP packet
        ip_packet = IP(dst=target_ip)
        
        # Create a TCP packet with SYN flag set
        tcp_packet = TCP(dport=int(target_port), flags="S")
        
        # Combine IP and TCP packets
        packet = ip_packet / tcp_packet
        
        # Send the packet the specified number of times
        for _ in range(int(packet_count)):
            send(packet, verbose=False)
        
        messagebox.showinfo("Success", f"{packet_count} SYN packet(s) sent to {target_ip}:{target_port}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = tk.Tk()
root.title("TheSynner v.1.0.1")

# Create and place widgets
tk.Label(root, text="Enter target IP:").pack(pady=5)
entry_ip = tk.Entry(root, width=30)
entry_ip.pack(pady=5)

tk.Label(root, text="Enter target port:").pack(pady=5)
entry_port = tk.Entry(root, width=10)
entry_port.pack(pady=5)

tk.Label(root, text="Enter number of packets:").pack(pady=5)
entry_count = tk.Entry(root, width=10)
entry_count.pack(pady=5)

send_button = tk.Button(root, text="Send SYN Packet", command=send_syn_packet_gui)
send_button.pack(pady=10)

# Run the application
root.mainloop()