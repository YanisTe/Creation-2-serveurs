# Toolbox de Sécurité Réseau sous Kali Linux

## Introduction
La **Toolbox de Sécurité Réseau** est une suite complète d'outils conçue pour renforcer la sécurité de vos systèmes et réseaux. Cette boîte à outils vous permet de détecter les vulnérabilités, d'analyser le trafic réseau, de tester la robustesse des accès SSH, et bien plus encore, le tout via une interface utilisateur intuitive.

## Fonctionnalités
- **Scan Nmap & Détection de Vulnérabilités**
- **ARP Spoofing et Analyse de Trames Wireshark**
- **Brute Force SSH sur une Machine Distante**
- **Scan de Vulnérabilités WEB**
- **Scan Récursif d’Adresse IP et Sous-domaines**

## Prérequis
- Kali Linux
- Python 3.x
- Les outils externes suivants doivent être installés :
  - Sublist3r
  - Wireshark

## Installation

### Cloner le Dépôt
1. Clonez ce dépôt :
    ```bash
    git clone https://github.com/votre-utilisateur/votre-projet.git
    cd votre-projet
    ```

### Installer les Dépendances
2. Installez les dépendances Python :
    ```bash
    pip install -r requirements.txt
    ```

### Configuration des Outils Externes
3. Assurez-vous que les outils externes (Sublist3r, Wireshark) sont installés et configurés correctement.

## Utilisation
1. Lancez la toolbox :
    ```bash
    python toolbox_menu.py
    ```

2. Suivez les instructions à l'écran pour naviguer dans le menu et utiliser les différents outils.

## Détails des Outils
### 1. Scan Nmap & Détection de Vulnérabilités
Utilise Nmap pour scanner les hôtes et ports actifs, détecter les vulnérabilités et générer des rapports PDF détaillés.

### 2. ARP Spoofing et Analyse de Trames Wireshark
Effectue des attaques de spoofing ARP pour intercepter le trafic réseau et utilise Wireshark pour capturer et analyser les paquets.

### 3. Brute Force SSH sur une Machine Distante
Utilise Paramiko pour tenter des connexions SSH par force brute, enregistre les résultats et génère des rapports PDF.

### 4. Scan de Vulnérabilités WEB
Analyse les sites web pour détecter les vulnérabilités courantes comme les injections SQL et XSS, et génère des rapports PDF.

### 5. Scan Récursif d’Adresse IP et Sous-domaines
Utilise Sublist3r pour découvrir des sous-domaines d'un domaine donné, effectue une recherche récursive et génère des rapports PDF.

## License
Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Contact
Pour toute question ou assistance, veuillez contacter (yanis.t77@gmail.com).
