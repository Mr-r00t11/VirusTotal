# 🛡️ VirusTotal CLI

This Python script allows you to query and analyze Indicators of Compromise (IoCs) using the VirusTotal API. It supports searches for IPs, URLs, domains, file hashes, and the ability to upload files for automatic scanning.

![](https://github.com/Mr-r00t11/VirusTotal/blob/main/img/VirusTotal.png?raw=true)
---
## 🚀 Features

- Query information for:
    - URLs
    - IP addresses
    - Domains
    - Hashes (MD5, SHA1, SHA256)
- File upload for dynamic analysis
- Detailed analysis display:
    - Detection engines
    - Statistics (malicious, suspicious, harmless, etc.)
    - Categories and relevant results
- Console colors for easier reading
- Visual threat identification with keywords (malware, phishing, etc.)

---
## 🧰 Requirements

- Python 3.6 or higher
- Modules:
    - `requests`
    - `argparse`
    - `colorama`
  
Install the required modules with:
```bash
pip install requests colorama
```
___
## 🔑 Configuration

Edit the script and replace the following line with your VirusTotal API Key:
```bash
API_KEY = 'TU_API_KEY_AQUI'
```

You can get a free API key at: [https://www.virustotal.com](https://www.virustotal.com/)

## 🛠️ Usage

```bash
python virustotal.py --ip 8.8.8.8 
python virustotal.py --url https://example.com
python virustotal.py --domain example.com
python virustotal.py --hash d41d8cd98f00b204e9800998ecf8427e 
python virustotal.py --upload suspicious_file.exe
```

## 📦 Parameters

| Parameter  | Description                |
| ---------- | -------------------------- |
| `--ip`     | Query an IP address        |
| `--url`    | Query a URL                |
| `--domain` | Query a domain             |
| `--hash`   | Query a file hash          |
| `--upload` | Upload a file for scanning |
