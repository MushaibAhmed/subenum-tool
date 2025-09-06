# 🕵️ Subenum Tool - Cyber Hunters

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-success)

A CLI-based tool for **subdomain enumeration, liveness detection, IP classification, and Shodan integration**, proudly developed by **Cyber Hunters**.  

---

## ✨ Features
- 🔎 **Subdomain Enumeration**
  - Brute-force with wordlists  
  - API-based discovery (VirusTotal, SecurityTrails)  
- 🌍 **Live Subdomain Detection** (filter out dead ones)  
- 🌐 **IP Extraction**
  - Classify **private vs. public IPs**  
  - Identify origin IPs  
- 🛰 **Shodan Integration**
  - Open ports  
  - CVE vulnerabilities  
- 🎨 **ASCII Banner** with team name at startup  

---

## 📦 Installation

Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/subenum-tool.git
cd subenum-tool
```

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ⚙️ Usage

Basic brute-force mode:
```bash
python subenum.py -d example.com -w wordlist.txt
```

API mode (requires API keys):
```bash
python subenum.py -d example.com -w wordlist.txt --team "Cyber Hunters"
```

Customize banner:
```bash
python subenum.py -d example.com --team "Cyber Hunters" --font block --no-color
```

---

## 🔑 API Keys

Create a `.env` file in the project root:

```env
VT_API=your_virustotal_api_key
ST_API=your_securitytrails_api_key
SHODAN_API=your_shodan_api_key
```

(An `.env.example` file is included for reference.)

---

## 🖥 Example Output

```
   ____       _               _   _             
  / ___|_   _| |__   ___ _ __| | | |_   _ _ __  
 | |   | | | | '_ \ / _ \ '__| |_| | | | '_ \ 
 | |___| |_| | |_) |  __/ |  |  _  | |_| | | | 
  \____|\__,_|_.__/ \___|_|  |_| |_|\__,_|_| |_| 

                 [ Cyber Hunters ]
==================================================================

[*] Running brute-force wordlist...
[+] Bruteforce produced 1024 candidates
[*] Querying APIs...
[+] Total candidates after APIs: 1342
[*] Resolving candidate names...
[+] Resolved 267 names to IP(s)
[*] Checking if resolved names are live...
[+] 56 live subdomains
[*] Querying Shodan for public IPs...
[+] Done in 22.3s
```

---

## 🛠 Requirements
- Python 3.8+
- `aiohttp`
- `dnspython`
- `shodan`
- `python-dotenv`
- `pyfiglet`
- `colorama`

Install them with:
```bash
pip install -r requirements.txt
```

---

## 📜 License
This project is licensed under the **MIT License**.  
Feel free to use, modify, and share it with attribution.  

---

## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 🧑‍💻 Developed by
**Cyber Hunters Team** 🔥
