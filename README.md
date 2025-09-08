# 🕵️ Subenum Tool - Cyber Hunters

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-success)

A CLI-based tool for **subdomain enumeration, liveness detection, IP classification, and Shodan integration**, proudly developed by **Cyber Hunters**.  

# Subdomain Enumeration Tool

subenum.py is a high-speed, asynchronous subdomain enumeration tool that uses *async DNS resolution* and integrates with multiple APIs for passive subdomain discovery.  
It is designed to minimize duplicate results and optionally filter subdomains based on their resolved IP addresses.

---

## 🚀 Features

- ⚡ *Asynchronous DNS Resolution*  
  Uses aiodns with *Cloudflare DNS (1.1.1.1 & 1.0.0.1)* for fast, concurrent subdomain resolution.

- 📜 *Wordlist-Based Bruteforce*  
  Supports custom subdomain wordlists for brute-force enumeration.

- 🌐 *Passive API-Based Enumeration* (Optional)  
  Fetches subdomains from:
  - 🧪 VirusTotal API
  - 🔍 SecurityTrails API
  - 🛡 AlienVault OTX API

- 🗂 *Duplicate Filtering* (Default)  
  - Filters subdomains that resolve to the same IP set (default mode).
  - Option to *disable filtering* (-df) to reveal virtual hosts and multiple subdomains pointing to the same IP.

- 🛰 *Private/Public IP Detection*  
  Automatically labels resolved IPs as *Public* or *Private*.

- ♻ *Global Deduplication*  
  Ensures unique subdomain names across both *wordlist* and *API results*.

- 💾 *Customizable Output*  
  - Save results in *TXT* format (-oT)
  - Save results in *JSON* format (-oJ)
  - Includes subdomain → IP mapping and scan metadata.

- 🔑 *Environment File Auto-Creation*  
  - Automatically creates ~/.env with placeholders for API keys if missing.
  - API keys are loaded securely from .env.

---

## 📦 Installation

Clone the repository:
```bash
git clone https://github.com/MushaibAhmed/subenum-tool.git
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
