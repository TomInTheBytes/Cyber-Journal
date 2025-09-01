https://www.elastic.co/security-labs/a-wretch-client
https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/SuspiciousRUNMRUEntry.md
https://kqlquery.com/posts/investigate-clickfix/
https://github.com/SigmaHQ/sigma/blob/1751ef8673365444ae44eb38887d3025982f4794/rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.yml#L8
https://github.com/SigmaHQ/sigma/blob/1751ef8673365444ae44eb38887d3025982f4794/rules-threat-hunting/windows/registry/registry_set/registry_set_runmru_command_execution.yml#L8
https://www.picussecurity.com/resource/blog/interlock-clickfix-ransomware-healthcare-attack
https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_suspicious_command_shell_execution_via_windows_run.toml
https://github.com/redcanaryco/atomic-red-team/blob/f745504cf0393d8334375d34d30b27e182574fb2/atomics/T1204.002/T1204.002.md#atomic-test-12---clickfix-campaign---abuse-runmru-to-launch-mshta-via-powershell

disable MDE

AMSI bypass



powershell Invoke-RestMethod -Uri "https://www.cloudflare.com" -Method GET  # ✅ I am not a robot - Verification ID: 123456 - Press OK

explorer variant


what we see

- RunMRU registry key created (sysmon)