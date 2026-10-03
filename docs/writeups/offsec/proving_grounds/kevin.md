# Kevin

## Enumeration & scanning

- Default scanning
- Find webapp 'HP Power Manager', can login with `admin:admin`

``` sh
# Default scanning
sudo nmap -p- 192.168.143.45   
sudo nmap -p 80,135,139,445,3389,3573 -A 192.168.143.45
```

## Exploitation

- Find [exploit](https://www.exploit-db.com/exploits/18015) for Metasploit, gives shell and the single flag


## References

- https://www.exploit-db.com/exploits/18015

## Rabbit holes

- Multiple exploits available, seems to crash app for a bit when it doesn't work.
