# Execution of Suspicious Commands in Combination with AnyFix Registry Entry

## Query Information

#### Description
This query is a custom Elastic Defend EQL detection that triggers once a suspicious command is executed right before a suspicious registry entry related to a ClickFix or FileFix type of attack is found. Additional command and registry artifacts can be added. 

#### Risk
There is a high likelihood of malicious activity when this alert triggers.

#### OS
Windows

#### Technique
[T1204.002 - User Execution: Malicious File ](https://attack.mitre.org/techniques/T1204/002/)

#### References
- See blog post in this repository.
- https://kqlquery.com/posts/investigate-clickfix/#detection-possibilities

## Elastic Defend
``` EQL
sequence by host.id with maxspan=1m
[ process where (event.action == "start" or event.action == "Process creation") and
process.name : ("cmd.exe", "powershell.exe", "curl.exe", "msiexec.exe", "mshta.exe", "wscript.exe", "cscript.exe") and
process.parent.name : "explorer.exe" and 
process.args_count >= 2 ]
[ registry where event.action == "RegistryEvent (Value Set)" and
    registry.path : ("*RunMRU*", "*TypedPaths*") and
    registry.data.strings : ("*cmd*", "*powershell*", "*curl*", "*mshta*") ]
```