import os
import subprocess

def run_scan_nmap_vuln():
    os.system('python3 GoldorackPrime6.py')

def run_pyshark():
    os.system('python3 Pyshark.py')

def run_dnsfound():
    os.system('python3 DNSfound.py')

def run_web_vulnerability_scanner():
    os.system('python3 web_vulnerability_scanner.py')

def run_ssh_bruteforce_scanner():
    os.system('python3 ssh_bruteforce_scanner.py')

def menu():
    while True:
        print("\n=== Toolbox Menu ===")
        print("1. Scan Nmap & vulnérabilité")
        print("2. Pyshark - Wireshark")
        print("3. Sublist3r - Find Subdomains")
        print("4. Web Vulnerability Scanner")
        print("5. SSH Bruteforce Scanner")
        print("6. Quit")
        
        choice = input("Enter your choice (1/2/3/4/5/6): ")

        if choice == '1':
            run_scan_nmap_vuln()
        elif choice == '2':
            run_pyshark()
        elif choice == '3':
            run_dnsfound()
        elif choice == '4':
            run_web_vulnerability_scanner()
        elif choice == '5':
            run_ssh_bruteforce_scanner()
        elif choice == '6':
            print("Exiting Toolbox...")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    menu()
