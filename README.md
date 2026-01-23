# Industrial Pentesting Suite
*Restored, Upgraded, and Authenticated.*

This repository contains a set of **Industrial-Grade** penetration testing tools, designed for high-value audit engagements. These tools have been meticulously restored to preserve their original "legacy" utility (v2.8 era) while being upgraded with modern "Elite" engines (v3.x) for detection and exploitation.

## 🛠️ The Arsenal

### 1. `lfiller.py` v3.6 (Authenticated Edition)
**The Ultimate Local File Inclusion (LFI) Auditor.**

A robust scanner designed to traverse authentication barriers and identify deep system compromises.
*   **Authenticated Audits:** Use `-C` (Cookies) and `-H` (Headers) to scan behind login portals.
*   **Smart Detection:** Signature-based validation for logs (checks `auth.log` for SSH keys, `access.log` for User-Agents) to eliminate false positives.
*   **Verification Engine:** Automatic RFI verification (checks status 200 vs 404) and `knockd.conf` support.
*   **Industrial Logic:** Full support for `php://filter` chains, `/proc/self/fd` brute-forcing, and Log Poisoning -> RCE escalation.

### 2. `sd-qli.py` v3.5 (Ultimate Industrial)
**Professional SQL Injection Auditing & Exfiltration.**

A "Legacy Elite" hybrid that combines the user-friendly CLI of v2.8 with a modern v3.5 exploitation engine.
*   **Legacy Soul:** All your favorite flags are back (`--dbs`, `--tables`, `--dump`) with zero bloat.
*   **Elite Muscle:** Integrated global recursive harvesting (All DBs -> All Tables -> 20-row samples).
*   **Professional Reporting:** Automatically generates HackerOne-standard reports (`bounty_report_X.txt`) and JSON evidence in domain-specific folders.
*   **Safety First:** strictly non-destructive scanning logic (Read-Only).

## 🚀 Usage

### LFI Auditing
```bash
# Basic Scan
python3 lfiller.py -u "http://target.com/page.php?file=" 

# Authenticated Scan (New in v3.6)
python3 lfiller.py -u "http://target.com/admin.php?p=" -C "PHPSESSID=abc12345"

# RCE Exploitation (WebShells)
python3 lfiller.py -u "http://target.com/" -webshell
```

### SQLi Auditing
```bash
# Full Industrial Audit
python3 sd-qli.py -u "http://target.com/news.php?id=1" --dbs --dump-all

# Manual Targeting
python3 sd-qli.py -u "http://target.com/news.php?id=1" -D users -T admin --dump

# Aggressive Login Bypass
python3 sd-qli.py -u "http://target.com/login.php" --data "user=admin&pass=123"
```

## ⚠️ Disclaimer
These tools are developed for **Authorized Penetration Testing** and Educational Purposes only. Usage against systems you do not own or have explicit permission to test is illegal.
