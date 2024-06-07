import requests
import os
import tkinter as tk
from tkinter import filedialog, Label, Button, Frame, Menu, messagebox, Toplevel, ttk, scrolledtext
from PIL import Image, ImageTk
import threading
import time
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import textwrap

API_KEY = 'YOUR_API_KEY'  # Replace with your VirusTotal API key

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.pause_flag = threading.Event()
        self.pause_flag.set()
        self.abort_flag = False

    def scan_file(self, file_path):
        url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': self.api_key}
        try:
            session = requests.session()
            session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
            with open(file_path, 'rb') as file:
                response = session.post(url, headers=headers, files={'file': (os.path.basename(file_path), file)})
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                # Change Tor identity
                self.change_tor_identity()
                # Retry the request
                return self.scan_file(file_path)
            else:
                raise e
        except Exception as e:
            raise RuntimeError(f"Failed to scan file: {e}")
        response.raise_for_status()
        return response.json()

    def change_tor_identity(self):
        try:
            with requests.Session() as s:
                s.proxies = {'http': 'socks5h://localhost:9050', 'https': 'socks5h://localhost:9050'}
                s.post('http://localhost:9051/', data={'signal': 'newnym'})
            messagebox.showinfo("Tor Identity Changed", "Tor identity changed successfully.")
        except Exception as e:
            messagebox.showerror("Tor Error", f"Failed to change Tor identity: {e}")

    def get_scan_report(self, file_id):
        url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
        headers = {'x-apikey': self.api_key}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def check_for_viruses(self, report):
        stats = report['data']['attributes']['stats']
        total_detected = stats['malicious'] + stats['suspicious']
        return total_detected > 0

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            result_label.config(text="No file selected.")
            return
        result_label.config(text="File submitted successfully. Waiting for scan to complete...")
        progress.start()
        scan_thread = threading.Thread(target=self.perform_scan, args=(file_path,))
        scan_thread.start()

    def perform_scan(self, file_path):
        try:
            # Check if the file exists before scanning
            if not os.path.exists(file_path):
                result_label.config(text="File deleted.")
                return
            
            scan_response = self.scan_file(file_path)
            file_id = scan_response['data']['id']
            while True:
                if self.abort_flag:
                    result_label.config(text="Scan aborted.")
                    break
                if not self.pause_flag.is_set():
                    time.sleep(1)
                    continue
                report = self.get_scan_report(file_id)
                if report['data']['attributes']['status'] == 'completed':
                    break
                time.sleep(5)
            else:
                return
            scan_details = json.dumps(report, indent=4)
            with open("scan_history.log", "a") as log_file:
                log_file.write(scan_details + "\n\n")
            if self.check_for_viruses(report):
                result_label.config(text="Virus Detected")
                if messagebox.askyesno("Delete File", "Virus detected. Do you want to delete the file?"):
                    os.remove(file_path)
                    result_label.config(text="File deleted.")
            else:
                result_label.config(text="No Virus")
        except Exception as e:
            result_label.config(text=f"An error occurred: {e}")
        finally:
            progress.stop()
            self.abort_flag = False  # Reset abort flag for future scans


    def real_time_protection(self, path=None):
        self.abort_flag = False
        if path is None:
            path = os.path.join(os.path.expanduser("~"), "Downloads")
        event_handler = RealTimeEventHandler(self)
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()

        progress.start()  # Start the progress bar when real-time protection starts

        def stop_observer():
            observer.stop()
            observer.join()
            progress.stop()  # Stop the progress bar when real-time protection stops

        self.stop_real_time_protection = stop_observer
        result_label.config(text=f"Real-time protection started in: {path}")

    def pause_resume_scan(self):
        if self.pause_flag.is_set():
            self.pause_flag.clear()
            pause_button.config(text="Resume Scan")
        else:
            self.pause_flag.set()
            pause_button.config(text="Pause Scan")

    def abort_scan(self):
        self.pause_flag.set()
        self.abort_flag = True
        if hasattr(self, 'stop_real_time_protection'):
            self.stop_real_time_protection()

    def view_scan_history(self):
        history_window = Toplevel(root)
        history_window.title("Scan History")
        history_window.geometry("600x400")
        history_text = scrolledtext.ScrolledText(history_window, wrap=tk.WORD, font=("Helvetica", 12), bg="#333333", fg="#FFFFFF", insertbackground='white')
        history_text.pack(expand=True, fill='both')
        try:
            with open("scan_history.log", "r") as log_file:
                history_text.insert(tk.END, log_file.read())
        except FileNotFoundError:
            history_text.insert(tk.END, "No scan history available.")
        history_text.config(state=tk.DISABLED)

class RealTimeEventHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner

    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.perform_scan(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.scanner.perform_scan(event.src_path)

# Initialize the scanner
scanner = VirusTotalScanner(API_KEY)

# Create the main window
root = tk.Tk()
root.title("LightDefense")
root.geometry("575x250")
root.config(bg="#2E2E2E")

# Make the window size unchangeable
root.resizable(False, False)

# Create a menu bar
menubar = Menu(root, font=("Helvetica", 16), bg="#2E2E2E", fg="#FFFFFF", tearoff=0)
root.config(menu=menubar)

# Add File Scan option to the menu
scan_menu = Menu(menubar, tearoff=0, bg="#2E2E2E", fg="#FFFFFF")
menubar.add_cascade(label="Scan | ", menu=scan_menu)
scan_menu.add_command(label="File Scan", command=scanner.upload_file)

# Add Real-Time Protection option to the menu
menubar.add_command(label="Real-Time Protection | ", command=scanner.real_time_protection)

# Add Pause/Resume and Abort Scan options
scan_control_menu = Menu(menubar, tearoff=0, bg="#2E2E2E", fg="#FFFFFF")
menubar.add_cascade(label="Control | ", menu=scan_control_menu)
scan_control_menu.add_command(label="Pause/Resume Scan", command=scanner.pause_resume_scan)
scan_control_menu.add_command(label="Abort Scan", command=scanner.abort_scan)

# Add View Scan History option to the menu
menubar.add_command(label="Scan History", command=scanner.view_scan_history)

# Create a frame for the buttons
frame = Frame(root, bg="#2E2E2E")
frame.pack(pady=20)

# Add a progress bar
style = ttk.Style()
style.theme_use('clam')
style.configure("TProgressbar", troughcolor="#333333", background="#4CAF50", thickness=20)

progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="indeterminate", style="TProgressbar")
progress.pack(pady=10)

# Create and place the result label
result_label = Label(root, text="Select file to scan ", font=("Helvetica", 16), bg="#2E2E2E", fg="#FFFFFF", padx=10, pady=5, wraplength=400)
result_label.pack(pady=20)

# Create scan button with text
upload_button = Button(frame, text="Upload File", command=scanner.upload_file, borderwidth=0, highlightthickness=0,
                       bg="#4CAF50", fg="white", font=("Helvetica", 14), padx=10, pady=5)
upload_button.pack(side="left", padx=20)

# Create pause/resume button
pause_button = Button(frame, text="Pause Scan", command=scanner.pause_resume_scan, borderwidth=0, highlightthickness=0,
                      bg="maroon", fg="white", font=("Helvetica", 14), padx=10, pady=5)
pause_button.pack(side="left", padx=20)


# Run the application
root.mainloop()

