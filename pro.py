import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from queue import Queue, Empty
from datetime import datetime
import time


class NetSecureX:

    def __init__(self, root):
        self.root = root
        self.root.title("NetSecureX - SOC Dashboard")
        self.root.geometry("1000x600")
        self.root.configure(bg="#0f172a")

        # Scan state
        self.target_ip = ""
        self.q = Queue()
        self.results = []
        self.scanned_count = 0
        self.open_port_count = 0
        self.total_ports = 0
        self.start_time = 0
        self.stop_flag = False
        self.lock = threading.Lock()

        self.common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3389: "RDP"
        }

        self.setup_gui()

    # ---------------- Risk Classification ---------------- #

    def get_risk_level(self, port):
        high_risk = [23, 445, 3389, 139]
        medium_risk = [21, 25, 110, 143]

        if port in high_risk:
            return "HIGH"
        elif port in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"

    # ---------------- Banner Grabbing ---------------- #

    def grab_banner(self, port):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((self.target_ip, port))
            try:
                banner = s.recv(1024)
            except:
                banner = b""
            s.close()
            return banner.decode(errors="ignore").strip() if banner else "N/A"
        except:
            return "N/A"

    # ---------------- Port Scan ---------------- #

    def scan_port(self, port):
        if self.stop_flag:
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((self.target_ip, port))
            s.close()

            with self.lock:
                self.scanned_count += 1

            if result == 0:
                service = self.common_services.get(port, "Unknown")
                risk = self.get_risk_level(port)
                banner = self.grab_banner(port)

                with self.lock:
                    self.open_port_count += 1
                    self.results.append((port, service, risk, banner))

                self.root.after(0, lambda:
                    self.tree.insert("", "end",
                                     values=(port, service, risk, banner),
                                     tags=(risk,))
                )
        except:
            pass

    # ---------------- Worker Thread ---------------- #

    def worker(self):
        while not self.stop_flag:
            try:
                port = self.q.get_nowait()
            except Empty:
                break

            try:
                self.scan_port(port)
            finally:
                self.q.task_done()

    # ---------------- Start Scan ---------------- #

    def start_scan(self):
        self.target_ip = self.ip_entry.get()

        if not self.target_ip:
            messagebox.showerror("Error", "Enter target IP")
            return

        try:
            socket.gethostbyname(self.target_ip)
        except:
            messagebox.showerror("Error", "Invalid IP address")
            return

        # Reset
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.scanned_count = 0
        self.open_port_count = 0
        self.stop_flag = False

        scan_type = self.scan_option.get()
        ports = range(1, 1025) if scan_type == "Quick Scan" else range(1, 5001)

        self.total_ports = len(ports)
        self.progress["maximum"] = self.total_ports
        self.progress["value"] = 0

        self.q = Queue()
        for port in ports:
            self.q.put(port)

        thread_count = min(200, self.total_ports)

        for _ in range(thread_count):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()

        self.start_time = time.time()
        self.status_label.config(text="Scanning...")
        self.update_dashboard()

    # ---------------- Stop Scan ---------------- #

    def stop_scan(self):
        self.stop_flag = True
        self.status_label.config(text="Scan Stopped")

    # ---------------- Dashboard Update ---------------- #

    def update_dashboard(self):
        self.progress["value"] = self.scanned_count
        self.scanned_label.config(text=f"Scanned: {self.scanned_count}")
        self.open_label.config(text=f"Open Ports: {self.open_port_count}")

        elapsed = time.time() - self.start_time
        if elapsed > 0:
            speed = int(self.scanned_count / elapsed)
            self.speed_label.config(text=f"Speed: {speed} ports/sec")

        if self.q.unfinished_tasks == 0 or self.stop_flag:
            if not self.stop_flag:
                self.status_label.config(text="Scan Complete")
        else:
            self.root.after(200, self.update_dashboard)

    # ---------------- Save Report ---------------- #

    def save_report(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to save")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt")

        if file_path:
            with open(file_path, "w") as f:
                f.write("NetSecureX SOC Report\n")
                f.write(f"Target: {self.target_ip}\n")
                f.write(f"Scan Date: {datetime.now()}\n\n")

                for r in self.results:
                    f.write(
                        f"Port: {r[0]} | Service: {r[1]} | Risk: {r[2]} | Banner: {r[3]}\n"
                    )

            messagebox.showinfo("Saved", "Report Saved Successfully")

    # ---------------- GUI Setup ---------------- #

    def setup_gui(self):

        top_frame = tk.Frame(self.root, bg="#0f172a")
        top_frame.pack(pady=10)

        tk.Label(top_frame, text="Target IP:",
                 bg="#0f172a", fg="white").grid(row=0, column=0, padx=5)

        self.ip_entry = tk.Entry(top_frame, width=25)
        self.ip_entry.grid(row=0, column=1, padx=5)

        self.scan_option = ttk.Combobox(
            top_frame, values=["Quick Scan", "Full Scan"], width=15)
        self.scan_option.current(0)
        self.scan_option.grid(row=0, column=2, padx=5)

        tk.Button(top_frame, text="Start Scan",
                  command=self.start_scan,
                  bg="#22c55e", fg="white", width=12).grid(row=0, column=3, padx=5)

        tk.Button(top_frame, text="Stop Scan",
                  command=self.stop_scan,
                  bg="#ef4444", fg="white", width=12).grid(row=0, column=4, padx=5)

        tk.Button(top_frame, text="Save Report",
                  command=self.save_report,
                  bg="#3b82f6", fg="white", width=12).grid(row=0, column=5, padx=5)

        self.status_label = tk.Label(self.root, text="Idle",
                                     bg="#0f172a", fg="white")
        self.status_label.pack()

        dashboard = tk.Frame(self.root, bg="#0f172a")
        dashboard.pack(pady=5)

        self.scanned_label = tk.Label(dashboard, text="Scanned: 0",
                                      bg="#0f172a", fg="#38bdf8", font=("Arial", 10, "bold"))
        self.scanned_label.grid(row=0, column=0, padx=20)

        self.open_label = tk.Label(dashboard, text="Open Ports: 0",
                                   bg="#0f172a", fg="#f87171", font=("Arial", 10, "bold"))
        self.open_label.grid(row=0, column=1, padx=20)

        self.speed_label = tk.Label(dashboard, text="Speed: 0 ports/sec",
                                    bg="#0f172a", fg="#facc15", font=("Arial", 10, "bold"))
        self.speed_label.grid(row=0, column=2, padx=20)

        self.progress = ttk.Progressbar(self.root, length=800)
        self.progress.pack(pady=5)

        columns = ("Port", "Service", "Risk", "Banner")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)

        self.tree.pack(expand=True, fill="both", padx=10, pady=10)

        self.tree.tag_configure("HIGH", background="#ef4444")
        self.tree.tag_configure("MEDIUM", background="#facc15")
        self.tree.tag_configure("LOW", background="#4ade80")


# Run Application
if __name__ == "__main__":
    root = tk.Tk()
    app = NetSecureX(root)
    root.mainloop()
