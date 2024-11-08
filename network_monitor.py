import psutil
import socket
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import threading
import time
from connection_details import ConnectionDetailsWindow

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Monitor")
        self.root.geometry("1200x600")

        style = ttk.Style()
        style.configure("Treeview", font=('Arial', 9))
        style.configure("Alert.Treeview.Item", foreground="red")

        main_frame = ttk.Frame(root, padding="5")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Protocol", "Local Address", "Remote Address", "Status", "Risk", "Notes")
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=25)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        self.tree.bind('<Double-1>', self.on_double_click)

        self.running = True
        self.thread = threading.Thread(target=self.update_connections, daemon=True)
        self.thread.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        connection_data = self.tree.item(item)['values']
        ConnectionDetailsWindow(self.root, connection_data)

    def get_connection_status(self, status):
        states = {
            psutil.CONN_ESTABLISHED: "ESTABLISHED",
            psutil.CONN_SYN_SENT: "SYN_SENT",
            psutil.CONN_SYN_RECV: "SYN_RECV",
            psutil.CONN_FIN_WAIT1: "FIN_WAIT1",
            psutil.CONN_FIN_WAIT2: "FIN_WAIT2",
            psutil.CONN_TIME_WAIT: "TIME_WAIT",
            psutil.CONN_CLOSE: "CLOSE",
            psutil.CONN_CLOSE_WAIT: "CLOSE_WAIT",
            psutil.CONN_LAST_ACK: "LAST_ACK",
            psutil.CONN_LISTEN: "LISTENING",
            psutil.CONN_NONE: "NONE",
        }
        return states.get(status, "UNKNOWN")

    def assess_risk(self, local_port, remote_port, status):
        risk = "LOW"
        notes = []
        
        rat_ports = {
            1234: "Generic RAT",
            5900: "VNC",
            3389: "RDP",
            4444: "Metasploit",
            31337: "Back Orifice",
            12345: "NetBus",
            27374: "SubSeven",
            8080: "Web Proxy/RAT",
            9999: "Generic RAT",
            7777: "Generic RAT"
        }
        
        suspicious_ports = {
            22: "SSH",
            23: "Telnet",
            445: "SMB",
            135: "RPC",
            139: "NetBIOS"
        }
        
        if local_port in rat_ports:
            risk = "HIGH"
            notes.append(f"⚠️ Potential RAT: {rat_ports[local_port]}")
        if remote_port in rat_ports:
            risk = "HIGH"
            notes.append(f"⚠️ Connected to known RAT port: {rat_ports[remote_port]}")
        
        if local_port in suspicious_ports:
            risk = "MEDIUM"
            notes.append(f"Suspicious: {suspicious_ports[local_port]}")
        if remote_port in suspicious_ports:
            risk = "MEDIUM"
            notes.append(f"Connected to suspicious service: {suspicious_ports[remote_port]}")
        
        if status == "LISTENING":
            if local_port not in suspicious_ports and local_port not in rat_ports:
                notes.append("Unusual listening port")
                risk = "MEDIUM"
            else:
                risk = "HIGH"
                notes.append("⚠️ Listening on suspicious port!")
        
        if remote_port > 50000:
            notes.append("High remote port (possible RAT/backdoor)")
            if risk != "HIGH":
                risk = "MEDIUM"
        
        return risk, " | ".join(notes) if notes else "Normal traffic"

    def update_connections(self):
        while self.running:
            try:
                for item in self.tree.get_children():
                    self.tree.delete(item)
                
                connections = psutil.net_connections(kind='inet')
                high_risk_count = 0
                
                for conn in connections:
                    try:
                        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                        status = self.get_connection_status(conn.status)
                        
                        local_port = conn.laddr.port if conn.laddr else 0
                        remote_port = conn.raddr.port if conn.raddr else 0
                        
                        risk, notes = self.assess_risk(local_port, remote_port, status)

                        values = (protocol, local_addr, remote_addr, status, risk, notes)
                        item = self.tree.insert('', 'end', values=values)
              
                        if risk == "HIGH":
                            self.tree.item(item, tags=('high_risk',))
                            high_risk_count += 1
                        
                    except (AttributeError, KeyError):
                        continue
                
       
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                status_text = f"Last updated: {current_time} | High risk connections: {high_risk_count}"
                self.status_var.set(status_text)
                
      
                self.tree.tag_configure('high_risk', foreground='red', font=('Arial', 9, 'bold'))
                
                time.sleep(2)
                
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                time.sleep(2)

    def on_closing(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()