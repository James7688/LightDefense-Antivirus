import requests
import os
import tkinter as tk
from tkinter import filedialog, Label, Button, Frame, Menu, messagebox, Toplevel, ttk, scrolledtext
from PIL import Image, ImageTk
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

API_KEY = 'YOUR_API_KEY'

# Global control flags
pause_flag = threading.Event()
pause_flag.set()
abort_flag = False
real_time_protection_flag = threading.Event()
real_time_protection_flag.clear()


def scan_file(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY,
    }
    files = {
        'file': (os.path.basename(file_path), open(file_path, 'rb')),
    }
    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def get_scan_report(file_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        'x-apikey': API_KEY,
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def check_for_viruses(report):
    stats = report['data']['attributes']['stats']
    total_detected = stats['malicious'] + stats['suspicious']
    return total_detected > 0


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
        scan_response = scan_file(file_path)
        file_id = scan_response['data']['id']
        while True:
            report = get_scan_report(file_id)
            if report['data']['attributes']['status'] == 'completed':
                break
        scan_details = json.dumps(report, indent=4)
        with open("scan_history.log", "a") as log_file:
            log_file.write(scan_details + "\n\n")
        if check_for_viruses(report):
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


def full_scan():
    global pause_flag, abort_flag
    abort_flag = False

    def scan_and_check_file(file_path):
        try:
            scan_response = scan_file(file_path)
            file_id = scan_response['data']['id']
            while True:
                report = get_scan_report(file_id)
                if report['data']['attributes']['status'] == 'completed':
                    break
            return file_path, check_for_viruses(report), None
        except Exception as e:
            return file_path, False, str(e)

    def run_full_scan():
        global abort_flag
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
                    if abort_flag:
                        result_label.config(text="Full scan aborted.")
                        progress.stop()
                        return
            for future in as_completed(futures):
                file_path, has_virus, error = future.result()
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
    global pause_flag
    if pause_flag.is_set():
        pause_flag.clear()
        pause_button.config(text="Resume Scan")
    else:
        pause_flag.set()
        pause_button.config(text="Pause Scan")


def abort_scan():
    global pause_flag, abort_flag
    pause_flag.set()
    abort_flag = True


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


class RealTimeEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"New file detected: {event.src_path}")
            threading.Thread(target=perform_scan, args=(event.src_path,)).start()

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            threading.Thread(target=perform_scan, args=(event.src_path,)).start()


def start_real_time_protection():
    if real_time_protection_flag.is_set():
        result_label.config(text="Real-time protection is already running.")
        return
    real_time_protection_flag.set()
    result_label.config(text="Real-time protection started.")
    observer = Observer()
    event_handler = RealTimeEventHandler()
    observer.schedule(event_handler, path="C:\\", recursive=True)
    observer.start()

    def monitor():
        try:
            while real_time_protection_flag.is_set():
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()
            result_label.config(text="Real-time protection stopped.")

    threading.Thread(target=monitor, daemon=True).start()


def stop_real_time_protection():
    if not real_time_protection_flag.is_set():
        result_label.config(text="Real-time protection is not running.")
        return
    real_time_protection_flag.clear()
    result_label.config(text="Stopping real-time protection...")


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

# Add Real-Time Protection options to the menu
real_time_menu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Real-Time Protection", menu=real_time_menu)
real_time_menu.add_command(label="Start Real-Time Protection", command=start_real_time_protection)
real_time_menu.add_command(label="Stop Real-Time Protection", command=stop_real_time_protection)

# Add Pause/Resume and Abort Scan options
scan_control_menu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Control", menu=scan_control_menu)
scan_control_menu.add_command(label="Pause/Resume Scan", command=pause_resume_scan)
scan_control_menu.add_command(label="Abort Scan", command=abort_scan)

# Add View Scan History option to the menu
menubar.add_command(label="View Scan History", command=view_scan_history)

# Create a frame for the buttons
frame = Frame(root, bg="#f0f0f0")
frame.pack(pady=20)

# Create the scan button with text
upload_button = Button(frame, text="Upload File", command=upload_file, borderwidth=0, highlightthickness=0,
                       bg="#4CAF50", fg="white", font=("Helvetica", 14))
upload_button.pack(side="left", padx=20)

# Create and place the result label
result_label = Label(root, text="Result: ", font=("Helvetica", 16), bg="#f0f0f0", fg="#333333")
result_label.pack(pady=20)

# Add a progress bar
progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="indeterminate")
progress.pack(pady=10)

# Add contact us label
contact_label = Label(root, text="Contact us: quyanh082013@gmail.com", font=("Helvetica", 10), bg="#f0f0f0",
                      fg="#333333")
contact_label.pack(side="bottom", pady=10)

# Create pause/resume button
pause_button = Button(frame, text="Pause Scan", command=pause_resume_scan, borderwidth=0, highlightthickness=0,
                      bg="#FFA500", fg="white", font=("Helvetica", 14))
pause_button.pack(side="left", padx=20)

# Run the application
root.mainloop()
