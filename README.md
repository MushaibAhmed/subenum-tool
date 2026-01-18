
# 🕵️ Subenum Tool - Cyber Hunters

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-success)

A CLI-based tool for **subdomain enumeration, liveness detection, IP classification, and Shodan integration**, proudly developed by **Cyber Hunters**.  

---

## ✨ Features
- 🔎 **Subdomain Enumeration**
  - Brute-force with wordlists  
  - 🌐 **Passive API-Based Enumeration**   
  Fetches subdomains from:
  - 🧪 VirusTotal API
  - 🔍 SecurityTrails API
  - 🛡 AlienVault OTX API

 - ⚡ **Asynchronous DNS Resolution**  
  Uses `aiodns` with **Cloudflare DNS (1.1.1.1 & 1.0.0.1)** for fast, concurrent subdomain resolution.

- 📜 **Wordlist-Based Bruteforce**  
  Supports custom subdomain wordlists for brute-force enumeration.
  
- 🌍 **Live Subdomain Detection** (filter out dead ones)  
- 🌐 **IP Extraction**
  - Classify **private vs. public IPs**  
  - Identify origin IPs  
- 🛰 **Shodan Integration**
  - Open ports  
  - CVE vulnerabilities  
- 🎨 **ASCII Banner** with team name at startup

- 🗂 **Duplicate Filtering** *(Default)*  
  - Filters subdomains that resolve to the same IP set (default mode).
  - Option to **disable filtering** (`-df`) to reveal virtual hosts and multiple subdomains pointing to the same IP.

- 🛰 **Private/Public IP Detection**  
  Automatically labels resolved IPs as **Public** or **Private**.

- ♻ **Global Deduplication**  
  Ensures unique subdomain names across both **wordlist** and **API results**.

- 💾 **Customizable Output**  
  - Save results in **TXT** format (`-oT`)
  - Save results in **JSON** format (`-oJ`)
  - Save results in **HTML** format (`-oH`)
  - Includes subdomain → IP mapping and scan metadata.
 
---

## 📦 Installation

Clone the repository:
```bash
git clone https://github.com/MushaibAhmad/subenum-tool.git
cd subenum-tool
```

---

## ⚙️ Usage

Basic brute-force mode:
```bash
python3 subenum.py example.com -w wordlist.txt
```

API mode (requires API keys):
```bash
python3 subenum.py example.com -w wordlist.txt --api
```

Shodan mode (requires API keys):
```bash
python3 subenum.py example.com -w wordlist.txt --api --shodan
```

To view the full result like open ports and CVE's:
```bash
python3 subenum.py example.com -w wordlist.txt --api --shodan -oH fileName.html
```
And use other flags like -oT for txt format and -oJ for json format.

---

## 🔑 API Keys

While runing the command first time it's automatically generate a `.env` file:

```env
VT_API=your_virustotal_api_key
ST_API=your_securitytrails_api_key
SHODAN_API=your_shodan_api_key
```

(An `.env.example` file is included for reference.)

To Insert the API keys
```bash
nano ~/.env
```

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

---

## 📜 License
This project is licensed under the **MIT License**.  
Feel free to use, modify, and share it with attribution.  

---

## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## ❗ DISCLAIMER
This Tool is Not 100% Accurate so it can fail somtimes. Also this tool is made for educational and research purposes only, we do not assume any kind of responsibility for any imprope use of this tool.

---

## 🧑‍💻 Developed by
**Cyber Hunters Team** 🔥

---
