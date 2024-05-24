import ipaddress
import netifaces
import os
import json
import threading
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import nmap
import requests

# Remplacez 'YOUR_VULNERS_API_KEY' par votre clé API obtenue sur Vulners
VULNERS_API_KEY = 'YOUR_VULNERS_API_KEY'

def get_local_network():
    """Obtenir la plage d'adresses IP locale à partir de la configuration du réseau."""
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    interface = gateways['default'][netifaces.AF_INET][1]
    addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    network_address = addresses['addr']
    netmask = addresses['netmask']
    cidr = ipaddress.IPv4Network(f"{network_address}/{netmask}", strict=False)
    return cidr

def ping_scan(ip_range):
    """Effectue un ping scan pour trouver les hôtes actifs."""
    def ping(ip):
        response = os.system(f"ping -c 1 {ip} > /dev/null 2>&1")
        if response == 0:
            hosts_up.append(ip)

    hosts_up = []
    threads = []
    for ip in ip_range.hosts():
        t = threading.Thread(target=ping, args=(str(ip),))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return hosts_up

def scan_network(hosts):
    """Scanne une liste d'hôtes actifs pour trouver les services ouverts."""
    scanner = nmap.PortScanner()
    scanner.scan(' '.join(hosts), arguments='-sV')
    return scanner

def search_exploit(service, version, max_results=5):
    """Recherche les exploits disponibles pour un service et une version donnés via Vulners API."""
    url = f"https://vulners.com/api/v3/search/lucene/"
    headers = {
        'Content-Type': 'application/json',
        'X-Vulners-Api-Key': VULNERS_API_KEY
    }
    query = f"{service} {version} exploit"
    payload = {
        "query": query,
        "size": max_results
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Vérifie si la requête a réussi
        results = response.json().get('data', {}).get('search', [])
        readable_result = [f"{result['_source']['title']} - {result['_source']['vhref']}" for result in results]
        return readable_result
    except requests.exceptions.RequestException as e:
        print(f"HTTP error: {e}")
        return [f"Error fetching exploits for {service} {version}"]
    except json.JSONDecodeError:
        print(f"Error decoding JSON response for {service} {version}")
        return [f"No valid JSON response for {service} {version}"]

def exploit_search_from_host(scanner, host, max_exploits=5):
    """Recherche les exploits à partir des résultats de scan Nmap pour un hôte spécifique."""
    exploits = []
    if host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['version']
                exploits.extend(search_exploit(service, version, max_results=max_exploits))
    return exploits

def generate_pdf_for_host(scanner, host, exploits, directory="/home/kali/Documents/ToolsBox/compte_rendu/nmap"):
    """Génère un rapport PDF basé sur les résultats du scan Nmap et des recherches d'exploits pour un hôte."""
    if not os.path.exists(directory):
        os.makedirs(directory)

    filename = f"{directory}/{host}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    text = c.beginText(40, 750)
    text.setFont("Helvetica", 12)
    text.textLine(f"Nmap Scan Report for {host}")
    text.textLine("--------------------------")

    if host in scanner.all_hosts():
        text.textLine(f"Host : {host} ({scanner[host].hostname()})")
        for proto in scanner[host].all_protocols():
            text.textLine(f"Protocol : {proto}")
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['version']
                text.textLine(f"Port : {port}, Service : {service}, Version : {version}")
    else:
        text.textLine("No scan data available for this host.")

    text.textLine("\nExploits Found:")
    text.textLine("---------------")
    if exploits:
        for exploit in exploits:
            text.textLine(exploit)
    else:
        text.textLine("No exploits found.")

    c.drawText(text)
    c.save()

def main():
    network = get_local_network()
    print(f"Scanning local network: {network}")
    hosts_up = ping_scan(network)
    print(f"Active hosts found: {hosts_up}")
    if hosts_up:
        scanner = scan_network(hosts_up)
        for host in hosts_up:
            exploits = exploit_search_from_host(scanner, host, max_exploits=5)
            generate_pdf_for_host(scanner, host, exploits)

if __name__ == "__main__":
    main()
