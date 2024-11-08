import tkinter as tk
from tkinter import ttk
import subprocess
import sys
import os

class ConnectionDetailsWindow:
    def __init__(self, parent, connection_data):
        self.window = tk.Toplevel(parent)
        self.window.title("Connection Details")
        self.window.geometry("600x400")
        
    
        self.protocol, self.local_addr, self.remote_addr, self.status, self.risk, self.notes = connection_data
        self.local_ip, self.local_port = self.parse_address(self.local_addr)
        self.remote_ip, self.remote_port = self.parse_address(self.remote_addr)
        
        self.create_widgets()
        
    def parse_address(self, addr):
        if addr == "N/A":
            return "N/A", "N/A"
        try:
            ip, port = addr.split(":")
            return ip, port
        except:
            return addr, "N/A"
            
    def create_widgets(self):
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        

        ttk.Label(main_frame, text="Connection Details", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        details = [
            ("Protocol:", self.protocol),
            ("Status:", self.status),
            ("Risk Level:", self.risk),
            ("Local IP:", self.local_ip),
            ("Local Port:", self.local_port),
            ("Remote IP:", self.remote_ip),
            ("Remote Port:", self.remote_port),
            ("Notes:", self.notes)
        ]
        
        for i, (label, value) in enumerate(details):
            ttk.Label(main_frame, text=label, font=('Arial', 10, 'bold')).grid(row=i+1, column=0, sticky=tk.W, pady=5)
            ttk.Label(main_frame, text=value, font=('Arial', 10)).grid(row=i+1, column=1, sticky=tk.W, pady=5)
        
        ttk.Separator(main_frame, orient='horizontal').grid(row=len(details)+1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=len(details)+2, column=0, columnspan=2, pady=10)
        
        ttk.Button(control_frame, text="Block Port", command=self.block_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Unblock Port", command=self.unblock_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Check Port Status", command=self.check_port_status).pack(side=tk.LEFT, padx=5)
    
    def block_port(self):
        if sys.platform == 'win32':
            self._block_port_windows()
        else:
            self._block_port_linux()
    
    def unblock_port(self):
        if sys.platform == 'win32':
            self._unblock_port_windows()
        else:
            self._unblock_port_linux()
    
    def _block_port_windows(self):
        try:
            port = self.local_port if self.local_port != "N/A" else self.remote_port
            cmd = f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block protocol=TCP localport={port}'
            if os.system(f'runas /user:Administrator "{cmd}"') == 0:
                tk.messagebox.showinfo("Success", f"Port {port} has been blocked")
            else:
                tk.messagebox.showerror("Error", "Failed to block port. Make sure you have administrative privileges.")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to block port: {str(e)}")
    
    def _unblock_port_windows(self):
        try:
            port = self.local_port if self.local_port != "N/A" else self.remote_port
            cmd = f'netsh advfirewall firewall delete rule name="Block Port {port}"'
            if os.system(f'runas /user:Administrator "{cmd}"') == 0:
                tk.messagebox.showinfo("Success", f"Port {port} has been unblocked")
            else:
                tk.messagebox.showerror("Error", "Failed to unblock port. Make sure you have administrative privileges.")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to unblock port: {str(e)}")
    
    def _block_port_linux(self):
        try:
            port = self.local_port if self.local_port != "N/A" else self.remote_port
            cmd = f'sudo iptables -A INPUT -p tcp --dport {port} -j DROP'
            if os.system(cmd) == 0:
                tk.messagebox.showinfo("Success", f"Port {port} has been blocked")
            else:
                tk.messagebox.showerror("Error", "Failed to block port. Make sure you have sudo privileges.")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to block port: {str(e)}")
    
    def _unblock_port_linux(self):
        try:
            port = self.local_port if self.local_port != "N/A" else self.remote_port
            cmd = f'sudo iptables -D INPUT -p tcp --dport {port} -j DROP'
            if os.system(cmd) == 0:
                tk.messagebox.showinfo("Success", f"Port {port} has been unblocked")
            else:
                tk.messagebox.showerror("Error", "Failed to unblock port. Make sure you have sudo privileges.")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to unblock port: {str(e)}")
    
    def check_port_status(self):
        port = self.local_port if self.local_port != "N/A" else self.remote_port
        if sys.platform == 'win32':
            cmd = f'netsh advfirewall firewall show rule name="Block Port {port}"'
        else:
            cmd = 'sudo iptables -L | grep ' + str(port)
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                tk.messagebox.showinfo("Port Status", f"Port {port} is currently BLOCKED")
            else:
                tk.messagebox.showinfo("Port Status", f"Port {port} is currently UNBLOCKED")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to check port status: {str(e)}")