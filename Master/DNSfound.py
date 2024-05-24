import os
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def find_subdomains(domain, output="subdomains.txt"):
    """Trouve les sous-domaines pour un domaine donné en utilisant Sublist3r."""
    sublist3r_path = "/home/kali/Documents/ToolsBox/Master/Sublist3r/sublist3r.py"
    command = ["python3", sublist3r_path, "-d", domain, "-o", output]
    
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            return []
    except subprocess.CalledProcessError as e:
        print(f"Sublist3r execution failed: {e}")
        return []

    if not os.path.exists(output):
        open(output, 'w').close()

    with open(output, 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]
    return subdomains

def recursive_find_subdomains(domain, depth=2, output="subdomains.txt"):
    all_subdomains = set()
    current_subdomains = find_subdomains(domain, output)
    
    for _ in range(depth):
        new_subdomains = set()
        for subdomain in current_subdomains:
            if subdomain not in all_subdomains:
                all_subdomains.add(subdomain)
                found = find_subdomains(subdomain, output)
                new_subdomains.update(found)
        current_subdomains = new_subdomains
    
    return list(all_subdomains)

def generate_pdf(domain, subdomains, directory="/home/kali/Documents/ToolsBox/compte_rendu/subdns"):
    """Génère un rapport PDF avec la liste des sous-domaines trouvés."""
    if not os.path.exists(directory):
        os.makedirs(directory)
    filename = f"{directory}/{domain}_sublist3r_report.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    text = c.beginText(40, 750)
    text.setFont("Helvetica", 12)
    text.textLine(f"Sublist3r Report for {domain}")
    text.textLine("---------------------------")
    for subdomain in subdomains:
        text.textLine(subdomain)

    c.drawText(text)
    c.save()
    return filename

def main():
    domain = input("Enter the domain to find subdomains for: ")
    depth = int(input("Enter the depth for recursive subdomain search: "))
    output_file = f"{domain}_subdomains.txt"
    
    if depth > 1:
        subdomains = recursive_find_subdomains(domain, depth, output=output_file)
    else:
        subdomains = find_subdomains(domain, output=output_file)

    if subdomains:
        print(f"Subdomains found: {len(subdomains)}")
        pdf_path = generate_pdf(domain, subdomains)
        print(f"PDF report generated: {pdf_path}")
    else:
        print("No subdomains found.")

if __name__ == "__main__":
    main()
