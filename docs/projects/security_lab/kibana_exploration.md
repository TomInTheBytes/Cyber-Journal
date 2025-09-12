https://www.elastic.co/security-labs/a-wretch-client
https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/SuspiciousRUNMRUEntry.md
https://kqlquery.com/posts/investigate-clickfix/
https://github.com/SigmaHQ/sigma/blob/1751ef8673365444ae44eb38887d3025982f4794/rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.yml#L8
https://github.com/SigmaHQ/sigma/blob/1751ef8673365444ae44eb38887d3025982f4794/rules-threat-hunting/windows/registry/registry_set/registry_set_runmru_command_execution.yml#L8
https://www.picussecurity.com/resource/blog/interlock-clickfix-ransomware-healthcare-attack
https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_suspicious_command_shell_execution_via_windows_run.toml
https://github.com/redcanaryco/atomic-red-team/blob/f745504cf0393d8334375d34d30b27e182574fb2/atomics/T1204.002/T1204.002.md#atomic-test-12---clickfix-campaign---abuse-runmru-to-launch-mshta-via-powershell
https://mrd0x.com/filefix-clickfix-alternative/



walk over elastic pages, process, alerts, rules, etc
use clickfix as example

AMSI bypass

what do we see with ClickFix
- Command execution (Elastic agent, Symon, Powershell)
- DNS request (Symon)
- Registry RunMRU value set (Sysmon)

TODO
- Powershell logs detection
- Create fake Clickfix page in Kali VM

!!! info "Atomic Test #12 - ClickFix Campaign - Abuse RunMRU to Launch mshta via PowerShell"
    [Simulates](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md#atomic-test-12---clickfix-campaign---abuse-runmru-to-launch-mshta-via-powershell) a ClickFix-style campaign by adding a malicious entry to the RunMRU registry key that launches mshta.exe with a remote payload.

    ``` ps1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "atomictest" -Value '"C:\Windows\System32\mshta.exe" http://localhost/hello6.hta'
    ```

!!! info "Custom ClickFix-like run dialog payload"
    Simulates a user pasting a potentially malicious Powershell command into the Windows run dialog, following a typical ClickFix structure to deceive users.

    ``` ps1
    powershell Invoke-RestMethod -Uri "https://www.cloudflare.com" -Method GET  # ✅ I am not a robot - Verification ID: 123456 - Press OK
    ```

from Github page, ext thread removed because not populated fields (not sure why)

``` sql linenums="1" title="[Elastic Defend + Symon] Suspicious command shell execution via Windows run"
/* (1)! */ process where (event.action == "start" or event.action == "Process creation") and
/* (2)! */ process.name : ("cmd.exe", "powershell.exe", "curl.exe", "msiexec.exe", "mshta.exe", "wscript.exe", "cscript.exe") and
/* (3)! */ process.parent.name : "explorer.exe" and 
/* (4)! */ process.args_count >= 2 and
/* (5)! */ not (process.name : "cmd.exe" and process.args : ("*.bat*", "*.cmd", "dir", "ipconfig", "C:\\WINDOWS\\system32\\sconfig.cmd ", "Code\\bin\\code.cmd ")) 
/* (6)! */ and not (process.name : "powershell.exe" and process.args : ("Start-Process powershell -Verb RunAs", "C:\\*.ps1", "-SPLAGroup", "\\\\*\\netlogon\\*.ps1"))
/* (7)! */ and not (process.name : "msiexec.exe" and process.args : "?:\\*.msi")
/* (8)! */ and not process.command_line : ("\"C:\\WINDOWS\\system32\\cmd.exe\" /k net use",
                                "\"C:\\WINDOWS\\system32\\cmd.exe\" -a",
                                "\"C:\\Windows\\system32\\msiexec.exe\" /regserver",
                                "\"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe\" -ep bypass")
/* (9)! */ and not (process.name : ("wscript.exe", "cscript.exe") and process.args : ("\\\\*\\MapNetworkDrives.vbs", "?:\\*.js", "?:\\*.vbs"))
```

1. **Event action filter:** Only include process creation events (Elastic Defend and Symon respectively).
2. **Process name filter:** Include high-risk or commonly abused executables.
3. **Parent process filter:** Restrict to processes launched by Explorer (user-initiated).
4. **Argument count filter:** Only include processes with two or more arguments, indicating significant execution.
5. **cmd.exe exclusion**: Filters out typical command prompt scripts and administrative commands.
6. **powershell.exe exclusion**: Filters normal PowerShell scripts and self-elevating commands.
7. **msiexec.exe exclusion**: Ignores standard MSI installer executions.
8. **specific command lines exclusion**: Excludes known safe system commands.
9. **wscript/cscript exclusion**: Ignores standard Windows Script Host scripts such as network drive mapping.


explorer variant





