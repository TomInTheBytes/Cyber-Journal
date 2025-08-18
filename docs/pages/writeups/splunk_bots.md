# Splunk Boss of the SOC (BOTS)

## Introduction
Splunk Boss of the SOC (BOTS) was a competitive, capture-the-flag–style event focused on security operations center skills. Participants investigate simulated security incidents using Splunk data to identify threats, analyze attacks, and answer challenge questions. It is designed to test threat detection, incident response, and data analysis capabilities in realistic, hands-on scenarios.

Since most CTFs have an offensive focus, Splunk BOTS is a refreshing alternative. They were organized through 2016 until 2019 (four editions). They still host various challenges on their [website](https://bots.splunk.com/), including the first edition. Edition two and three can be found on GitHub. 

I first learned about Splunk BOTS during a FIRST Technical Colloquium talk given by ex-employees and decided to give it a go myself. 

!!! info
    The answers should adhere to Splunk tips and tricks as listed on my [Splunk cheatsheet](../cheatsheets/splunk.md). 

## BOTS V1 (2015)
An overview of data sourcetypes and download link for the dataset can be found on [GitHub](https://github.com/splunk/botsv1). 

### Scenario 1: Web site defacement


!!! info "Context"
    Today is Alice's first day at the Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprises' IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.

??? success "Question 101"  
    
    !!! question 
        What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" "imreallynotbatman.com"
    ```

    Look for the domain as raw term in the HTTP logs. Using the sidebar we can see that only two source IPs are present in the results. We can quickly identify that one IP is sending suspicious requests: **40.80.148.42**. 

??? success "Question 102"  
    
    !!! question 
        What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" src_ip="40.80.148.42" "imreallynotbatman.com"
    ```

    Look at HTTP requests coming from the malicious IP address. In the headers of the requests (`src_headers`) we find the product: **Acunetix-Product: WVS/10.0 (Acunetix Web Vulnerability Scanner - Free Edition)**. 

??? success "Question 103"  
    
    !!! question 
        What content management system is imreallynotbatman.com likely using?

    Using the same query as that for question 102 we can see that many of the URIs attacked contain `/joomla/`. A Google search reveals that this is a CMS and therefore the answer: **joomla**. 

??? success "Question 104"  
    
    !!! question 
        What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

    ``` query title="Query"
    index=botsv1 sourcetype="fgt_utm" src="192.168.250.70" 
    ```

    The FortiGate firewalls have the unified threat management ([UTM](https://www.fortinet.com/resources/cyberglossary/unified-threat-management)) feature enabled. This index will contain incoming and outgoing analyzed traffic (WAF/IDS-like). We look for events coming from the webserver itself as the attacker likely compromised it before defacing it and pulled the image from somewhere else. We find the webserver IP using the query in question 102. The answer we find is: **poisonivy-is-coming-for-you-batman.jpeg**. 

??? success "Question 105"  
    
    !!! question 
        This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

    Using the same event that provided we answer for 104 we find: **prankglassinebracket.jumpingcrab.com**. 

??? success "Question 106"  
    
    !!! question 
        What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

    Using the same event that provided we answer for 104 and 105 we find: **23.22.63.114**. 

??? success "Question 108"  
    
    !!! question 
        What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="23.22.63.114"
    ```

    From question 101 we know that there are two IPs connecting to the webserver, of which one is a vulnerability scanner. While the attacker could conduct a brute-force attack from this IP, we see the brute-force attempts when analyzing traffing from the other one ('src_content'). Therefore, the answer is: **23.22.63.114**.

??? success "Question 109"  
    
    !!! question 
        What is the name of the executable uploaded by Po1s0n1vy? 

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST "upload" ".exe"
    ```

    Build a query that looks for HTTP traffic with the webserver as destination IP, HTTP method POST, and containing references to uploading and Windows executables. This returns a single event regarding an upload. This executable appears to be: **3791.exe**. 

??? success "Question 110"  
    
    !!! question 
        What is the MD5 hash of the executable uploaded?

    ``` query title="Query"
    index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process="3791.exe" "3791.exe"
    ```

    Sysmon will have recorded this when the executable was launched (event code 1). Look for the executable using both a raw term search as it can appear in multiple fields and in the process field. This query is much quicker than when not supplying the raw term. The hash we find is: **AAE3F5A29935E6ABCC2C2754D12A9AF0**. 

??? success "Question 111"  
    
    !!! question 
        GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

    We leverage VirusTotal to look for relationships of the attacker infrastructure [23.22.63.114](https://www.virustotal.com/gui/ip-address/23.22.63.114/relations). Under 'Communicating Files' there are four likely malicious files listed. One of them has an ominous looking name that could be used in a spearsphing attack called `MirandaTateScreensaver.src.exe`. The SHA256 hash of this file is: **9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8**. 

??? success "Question 112"  
    
    !!! question 
        What special hex code is associated with the customized malware discussed in question 111?

    The VirusTotal page for the malware found in question 111 contains [comments](https://www.virustotal.com/gui/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8/community). The first comment from 'ryan_kovar' contains a hex string: **53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21** 
    
    This translates to `Steve Brant's Beard is a powerful thing. Find this message and ask him to buy you a beer!!!`. 

??? success "Question 114"  
    
    !!! question 
        What was the first brute force password used?

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="23.22.63.114" | tail 1
    ```

    Look for all brute-force attempts and filter out the first one. The password shown in `form_data` is: **12345678**. 

??? success "Question 115"  
    
    !!! question 
        One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="23.22.63.114" 
    | rex field=src_content "(?:^|&)passwd=(?P<password>[^&]+)" 
    | eval length=len(password) 
    | table password, length 
    | where length=6
    ```

    Again look for all brute-force attempts and extract the password used from the `src_content` field using regex. We can filter on the field name `passwd` and take all characters until the next `&` delimiter. We then compute the length of the password and create a table with only password with a length of six. Using some common Coldplay knowledge, we identify the password with the name of a Coldplay song: **yellow**.

    ??? example "AI usage"

        The regex was created with help of ChatGPT and summarized as follows:

        1. `(?:^|&)`
        Non-capturing group. Matches either the beginning of the string (`^`) or an ampersand (`&`). Ensures we only match when `passwd=` is a standalone parameter and not a substring inside another value.

        2. `passwd=`
        Literal match for the field name.

        3. `(?P<password>[^&]+)`
        Named capturing group called `password`. Captures one or more characters (`+`) that are not an ampersand (`[^&]`). This ensures the captured value ends before the next delimiter.

??? success "Question 116"  
    
    !!! question 
        What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

    ``` query title="Query"
    index=botsv1 dest_ip="192.168.250.70" sourcetype="stream:http" http_method=POST form_data="*passwd*" form_data="*username=admin*" src_ip="40.80.148.42"
    ```

    The data from the brute-force IP does not show an obvious candidate. However, when swapping out the IP with the vulnerability scanner we find a single event with the correct password: **batman**. 

??? success "Question 117"  
    
    !!! question 
        What was the average password length used in the password brute forcing attempt?

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="23.22.63.114" 
    | rex field=src_content "(?:^|&)passwd=(?P<password>[^&]+)" 
    | eval length=len(password) 
    | table password, length 
    | stats avg(length)
    ```

    We reuse the query used for question 115 and now compute the average length. This returns (rounded down): **6**. 

??? success "Question 118"  
    
    !!! question 
        How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? 

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST form_data="*batman*" 
    | sort _time 
    | streamstats current=f last(_time) as prev_time 
    | eval diff_seconds=_time - prev_time
    ```

    We look for requests containing the password `batman`. The query returns two events; the brute-force attempt and the actual login. We can compute the time in seconds as `diff_seconds` between these two events: **92.17**. 

    ??? example "AI usage"

        ChatGPT came up with the computation of the difference in time directly in the query using `streamstats`, which it explained as follows:

        `streamstats` processes events as they stream in, maintaining state across rows.

        * `current=f` prevents including the current row in the calculation, so only past rows are referenced.
        * `last(_time) as prev_time` stores the previous event’s `_time` value in a new field `prev_time`.
        * Each event gets paired with the immediately preceding event’s time, enabling `eval` to compute their difference.

??? success "Question 119"  
    
    !!! question 
        How many unique passwords were attempted in the brute force attempt?

    ``` query title="Query"
    index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="23.22.63.114" 
    | rex field=src_content "(?:^|&)passwd=(?P<password>[^&]+)" 
    | stats values(password)
    ```

    We again reuse the query and compute all the unique passwords: **412**.  

### Scenario 2: Ransomware

!!! info "Context"
    After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

    Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...


??? success "Question 200"  
    
    !!! question 
        What was the most likely IPv4 address of we8105desk on 24AUG2016? 

    ``` query title="Query"
    index="botsv1" host="we8105desk"
    ```

    Filter for the hostname using the indexed field and look for the most frequent source IP in the sidebar. This will be: **192.168.250.100**.

??? success "Question 201"  
    
    !!! question 
        Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.

    ``` query title="Query"
    index="botsv1" sourcetype="suricata" src_ip="192.168.250.100" "Cerber"
    ```

    Filter for logs generated by suricata containing the IP mentioned in the last question, and containing the malware name (this query could be optimized by searching in specific fields). Use the sidebar to locate the ID, which will be: **2816763**. 

??? success "Question 202"  
    
    !!! question 
        What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

    We can reuse the query on Suricata data of question 201 to get the time range we need to look for in DNS data. We run the query and click on the time field of the latest result. Splunk will then prompt to set a time range based on that time. We choose to set it to look for events 5 minutes before and after. We can then run this next query to summarize the DNS queries run from the workstation in that timeframe:

    ``` query title="Query"
    index="botsv1" sourcetype="stream:dns" src_ip="192.168.250.100" | stats count by query
    ```
    
    There are six unique DNS queries of which one is the obviously malicious one: **cerberhhyed5frqa.xmfir0.win**.

??? success "Question 203"  
    
    !!! question 
        What was the first suspicious domain visited by we8105desk on 24AUG2016?

    ``` query title="Query"
    index="botsv1" sourcetype="stream:dns" src_ip="192.168.250.100" earliest="08/24/2016:0:0:0" latest="08/24/2016:23:59:59" | reverse | table _time, query
    ```

    Run a query on the DNS data with the correct time range. The IP address is searched with a raw term search as the `host_addr` field needed is an array and thus doesn't search easily. The query formats the output into a table that is sorted on ascending time. On page nine the suspicious domain is found: **solidaritedeproximite.org**.

??? success "Question 204"  
    
    !!! question 
        During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

    ``` query title="Query"
    index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" dvc_nt_host="we8105desk" ".vbs" | eval length=len(cmdline) | table _time, CommandLine,length | reverse
    ```

    Sysmon data will include the VB script. Look for anything related to `.vbs` and compute the cmdline length. We then use a table to display the results in ascending order. Don't forget to reset the time range to all time after answering the questions before.

    We find ten different command lines. The first suspicious one has a length of: **4490**.

??? success "Question 205"  
    
    !!! question 
        What is the name of the USB key inserted by Bob Smith?

    ``` query title="Query"
    index="botsv1" host="we8105desk" sourcetype="winregistry" "usbstor" | stats values(data)
    ```

    The WinEvent logs provided (`application`, `security`, and `system` as per the GitHub repository) lack the needed `operational` channel to look for USB events. We do have the winregistry events at our disposal. USB devices are added to the `USBSTOR` in the registry. We look for this term and look at the unique data values that are being set. The query returns many typical Windows registry terms and IDs except a suspicious name: **MIRANDA_PRI**. 

??? success "Question 206"  
    
    !!! question 
        Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

    ``` query title="Query"
    index="botsv1" sourcetype="stream:smb" src_ip="192.168.250.100" | stats count by dest_ip
    ```

    Look for SMB traffic coming from the workstation and identify the IP connected most often to: **192.168.250.20**. 

??? success "Question 207"  
    
    !!! question 
        How many distinct PDFs did the ransomware encrypt on the remote file server? 

    ``` query title="Query"
    index="botsv1" sourcetype="WinEventLog:Security" host="we9041srv" Accesses=DELETE ".pdf" | stats values(Relative_Target_Name)
    ```

    We can identify the hostname of the file server (`we9041srv`) by reversing the trick used for question 200. Then look for deletion of PDF files and count the unique events: **257**.

??? success "Question 208"  
    
    !!! question 
        The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

    ``` query title="Query"
    index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="we8105desk" EventCode=1 "121214.tmp" ".vbs"
    ```

    Look for process start events with both terms. We find the parent process ID is: **3968**. 

??? success "Question 209"  
    
    !!! question 
        The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

    ``` query title="Query"
    index="botsv1" host="we8105desk" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=2 TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*" TargetFilename="*.txt"
    ```

    Count the Sysmon events that involve file creation with the target including the user profile and the file extension, resulting in the number of encrypted files: **406**.

??? success "Question 210"  
    
    !!! question 
        The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file? 

    ``` query title="Query"
    index="botsv1" sourcetype="suricata" dest_ip="192.168.250.100" | table fileinfo.filename, fileinfo.size | sort -fileinfo.size
    ```

    Look for all file names and sizes with the infected workstation as destination. A ransomware executable will typically be larger than other files so we sort the results by size. The top result immediately stands out as it's a relatively large JPG file with a suspicious name: **mhtr.jpg**. 

??? success "Question 211"  
    
    !!! question 
        Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?

    The technique to hide data in files such as images is typically called: **steganography**. 
