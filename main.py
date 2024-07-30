import os
import hashlib
import threading
import time
import tkinter as tk
from tkinter import filedialog, Label, Button, Frame, Menu, messagebox, Toplevel, ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil  # For network monitoring

# Virus Signatures Database
virus_signatures = {
    "eicar_test_file": {
        "name": "EICAR Test File",
        "signature": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    },
    "trojan_win32_agent": {
        "name": "Trojan.Win32.Agent",
        "md5": "f51c6156475edbbd11b7b23d1288276d",
        "sha1": "7a421bb8d855ad0f6d6fd21e6da8398e91fcbd2a"
    },
    "trojan_generic": {
        "name": "Trojan.Generic",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "worm_win32_autorun": {
        "name": "Worm.Win32.AutoRun",
        "md5": "91af2e10f3206cd44baf0a18e82d5e4b",
        "sha256": "b9ae231f45ebd2d283c87fb8d6d1c8c2d736ec4e8dcfb5c110ed83e2c870ab85"
    }
}

# Heuristic Rules (Example)
heuristic_rules = [
    {"name": "PE Header Check", "rule": "check_pe_header"}
]

# Real-Time Protection Flag
real_time_protection_flag = threading.Event()
real_time_protection_flag.clear()

# Global Flags for Control
pause_flag = threading.Event()
abort_flag = threading.Event()

def scan_file_for_signatures(file_path):
    """Scans a file against known virus signatures and heuristic rules."""
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()

        file_md5 = hashlib.md5(file_content).hexdigest()
        file_sha1 = hashlib.sha1(file_content).hexdigest()
        file_sha256 = hashlib.sha256(file_content).hexdigest()

        # Check against known virus signatures
        for virus_name, details in virus_signatures.items():
            if 'signature' in details:
                if details['signature'].encode() in file_content:
                    return True, f"Virus detected: {details['name']}"
            if 'md5' in details and details['md5'] == file_md5:
                return True, f"Virus detected: {details['name']} by MD5"
            if 'sha1' in details and details['sha1'] == file_sha1:
                return True, f"Virus detected: {details['name']} by SHA1"
            if 'sha256' in details and details['sha256'] == file_sha256:
                return True, f"Virus detected: {details['name']} by SHA256"

        # Apply heuristic rules
        for rule in heuristic_rules:
            if rule["rule"] == "check_pe_header":
                if b'MZ' in file_content[:2]:  # Basic check for PE header (Windows executable)
                    return True, "Suspicious PE header detected."

        return False, "File is clean."

    except Exception as e:
        return False, f"Error scanning file: {e}"

def upload_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        result_label.config(text="No file selected.")
        return
    result_label.config(text="File submitted successfully. Waiting for scan to complete...")
    progress.start()
    try:
        scan_thread = threading.Thread(target=perform_scan, args=(file_path,))
        scan_thread.start()
    except Exception as e:
        result_label.config(text=f"An error occurred: {e}")
        progress.stop()

def perform_scan(file_path):
    try:
        has_virus, message = scan_file_for_signatures(file_path)
        if has_virus:
            result_label.config(text=message)
            if messagebox.askyesno("Delete File", "Virus detected. Do you want to delete the file?"):
                os.remove(file_path)
                result_label.config(text="File deleted.")
        else:
            result_label.config(text=message)
    except Exception as e:
        result_label.config(text=f"An error occurred: {e}")
    finally:
        progress.stop()

def full_scan():
    pause_flag.clear()
    abort_flag.clear()

    def scan_and_check_file(file_path):
        try:
            has_virus, message = scan_file_for_signatures(file_path)
            return file_path, has_virus, message, None
        except Exception as e:
            return file_path, False, None, str(e)

    def run_full_scan():
        try:
            result_label.config(text="Full scan started. This may take a while...")
            progress.start()
            executor = ThreadPoolExecutor(max_workers=10)
            futures = []
            for root, dirs, files in os.walk("C:\\"):
                for file in files:
                    file_path = os.path.join(root, file)
                    futures.append(executor.submit(scan_and_check_file, file_path))
                    while not pause_flag.is_set():
                        time.sleep(0.1)
                    if abort_flag.is_set():
                        result_label.config(text="Full scan aborted.")
                        progress.stop()
                        return
            for future in as_completed(futures):
                file_path, has_virus, message, error = future.result()
                if error:
                    result_label.config(text=f"Permission error on file: {file_path}")
                elif has_virus:
                    result_label.config(text=f"Virus Detected in: {file_path}")
                    os.remove(file_path)
                    result_label.config(text="Infected file deleted.")
            result_label.config(text="Full scan complete.")
        except Exception as e:
            result_label.config(text=f"An error occurred: {e}")
        finally:
            progress.stop()

    scan_thread = threading.Thread(target=run_full_scan)
    scan_thread.start()

def pause_resume_scan():
    if pause_flag.is_set():
        pause_flag.clear()
        pause_button.config(text="Pause Scan")
    else:
        pause_flag.set()
        pause_button.config(text="Resume Scan")

def abort_scan():
    pause_flag.set()
    abort_flag.set()

def view_scan_history():
    history_window = Toplevel(root)
    history_window.title("Scan History")
    history_window.geometry("600x400")
    history_text = scrolledtext.ScrolledText(history_window, wrap=tk.WORD, font=("Helvetica", 12))
    history_text.pack(expand=True, fill='both')
    try:
        with open("scan_history.log", "r") as log_file:
            history_text.insert(tk.END, log_file.read())
    except FileNotFoundError:
        history_text.insert(tk.END, "No scan history available.")
    history_text.config(state=tk.DISABLED)

def start_real_time_protection():
    real_time_protection_flag.set()
    result_label.config(text="Real-time protection activated.")
    threading.Thread(target=monitor_system).start()

def stop_real_time_protection():
    real_time_protection_flag.clear()
    result_label.config(text="Real-time protection deactivated.")

def monitor_system():
    scanned_files = set()
    while real_time_protection_flag.is_set():
        for root, dirs, files in os.walk("C:\\"):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path not in scanned_files:
                    has_virus, message = scan_file_for_signatures(file_path)
                    if has_virus:
                        result_label.config(text=f"Real-time protection: {message}")
                        os.remove(file_path)
                        result_label.config(text="Infected file deleted.")
                    scanned_files.add(file_path)
        time.sleep(5)  # Adjust the scanning frequency as needed

# Network Monitoring Feature (Basic Firewall)
def start_network_monitoring():
    network_window = Toplevel(root)
    network_window.title("Network Monitoring")
    network_window.geometry("600x400")
    network_text = scrolledtext.ScrolledText(network_window, wrap=tk.WORD, font=("Helvetica", 12))
    network_text.pack(expand=True, fill='both')

    def monitor_network():
        while True:
            network_text.delete(1.0, tk.END)
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                status = conn.status
                network_text.insert(tk.END, f"Local Address: {laddr} | Remote Address: {raddr} | Status: {status}\n")
            time.sleep(5)  # Refresh every 5 seconds

    threading.Thread(target=monitor_network, daemon=True).start()

# Create the main window
root = tk.Tk()
root.title("LightDefend Antivirus")
root.geometry("800x400")
root.config(bg="#f0f0f0")

# Create a menu bar
menubar = Menu(root, font=("Helvetica", 16), bg="#f0f0f0")
root.config(menu=menubar)

# Add File Scan option to the menu
scan_menu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Scan", menu=scan_menu)
scan_menu.add_command(label="File Scan", command=upload_file)

# Add Full Scan option to the menu
menubar.add_command(label="Full Scan", command=full_scan)

# Add Pause/Resume and Abort Scan options
scan_control_menu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Control", menu=scan_control_menu)
scan_control_menu.add_command(label="Pause/Resume Scan", command=pause_resume_scan)
scan_control_menu.add_command(label="Abort Scan", command=abort_scan)

# Add View Scan History option to the menu
menubar.add_command(label="View Scan History", command=view_scan_history)

# Add Real-Time Protection options to the menu
real_time_menu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Real-Time Protection", menu=real_time_menu)
real_time_menu.add_command(label="Start", command=start_real_time_protection)
real_time_menu.add_command(label="Stop", command=stop_real_time_protection)

# Add Network Monitoring option to the menu
menubar.add_command(label="Network Monitoring", command=start_network_monitoring)

# Create a frame for the buttons
frame = Frame(root, bg="#f0f0f0")
frame.pack(pady=20)

# Create the scan button with text
upload_button = Button(frame, text="Upload File", command=upload_file, borderwidth=0, highlightthickness=0,
                       bg="#4CAF50", fg="white", font=("Helvetica", 14))
upload_button.pack(side="left", padx=20)

# Create the result label
result_label = Label(root, text="Result: ", font=("Helvetica", 16), bg="#f0f0f0", fg="#333333")
result_label.pack(pady=20)

# Add a progress bar
progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="indeterminate")
progress.pack(pady=10)

# Create pause/resume button
pause_button = Button(frame, text="Pause Scan", command=pause_resume_scan, borderwidth=0, highlightthickness=0,
                      bg="#FFA500", fg="white", font=("Helvetica", 14))
pause_button.pack(side="left", padx=20)

# Add contact us label
contact_label = Label(root, text="Contact us: quyanh082013@gmail.com", font=("Helvetica", 10), bg="#f0f0f0", fg="#333333")
contact_label.pack(side="bottom", pady=10)

# Start the main loop
root.mainloop()
