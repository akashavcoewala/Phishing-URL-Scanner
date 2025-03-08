import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
import requests
import os
import json
import threading
import re
from datetime import datetime

# ---- API CONFIGURATION ----
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "AIzaSyDIEQKkiyBGRjPZrCQOziOmzLY6W07QRDM")
GOOGLE_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

USE_VIRUSTOTAL = True  # Enable VirusTotal scanning if needed
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "b1d06f9ea163bc906f9efc243c541dc2050ce50679c9a1d4a72868eb217cac85")
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"

VIRUSTOTAL_HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "Content-Type": "application/json"
}

LOG_FILE = "scan_results.csv"

def is_valid_url(url):
    pattern = re.compile(r'^(https?:\/\/)?([\w\-]+\.)+[\w]{2,}(\/\S*)?$')
    return bool(pattern.match(url))

def ensure_log_file():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Time", "URL", "Status"])

def scan_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "phishing-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(GOOGLE_API_URL, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return "Phishing Detected" if "matches" in data else "Safe"
        return f"Error: {response.status_code}"
    except requests.RequestException as e:
        return f"Request Failed: {str(e)}"

def log_result(url, status):
    ensure_log_file()
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url, status])

def scan_url(url):
    if not is_valid_url(url):
        return [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url, "Invalid URL"]
    result_msg = scan_google_safe_browsing(url)
    log_result(url, result_msg)
    return [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url, result_msg]

def scan_urls_from_file(file_path):
    results = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            urls = file.read().splitlines()
        for url in urls:
            results.append(scan_url(url))
        update_table(results)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file: {str(e)}")

def update_table(results):
    for row in table.get_children():
        table.delete(row)
    for result in results:
        table.insert("", "end", values=result)

def scan_single_url():
    url = url_entry.get().strip()
    if url:
        result = scan_url(url)
        update_table([result])
        result_label.config(text=result[2], fg="white")
    else:
        result_label.config(text="Please enter a valid URL", fg="red")

def scan_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        threading.Thread(target=scan_urls_from_file, args=(file_path,), daemon=True).start()

# ---- GUI SETUP ----
root = tk.Tk()
root.title("Phishing Scanner")
root.geometry("600x500")
root.configure(bg="#2C2F33")

tk.Label(root, text="Phishing URL Scanner", font=("Arial", 14, "bold"), fg="white", bg="#2C2F33").pack(pady=10)

tk.Label(root, text="Enter URL:", fg="white", bg="#2C2F33").pack()
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

tk.Button(root, text="Scan URL", command=scan_single_url, bg="#4CAF50", fg="white", width=20).pack(pady=5)
tk.Button(root, text="Scan from File", command=scan_from_file, bg="#008CBA", fg="white", width=20).pack(pady=5)

result_label = tk.Label(root, text="", fg="white", bg="#2C2F33", font=("Arial", 10))
result_label.pack(pady=10)

columns = ("Time", "URL", "Status")
table = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    table.heading(col, text=col)
    table.column(col, width=180)
table.pack(pady=10)

root.mainloop()
