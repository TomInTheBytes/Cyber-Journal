# Splunk Boss of the SOC (BOTS)

## Introduction
Splunk Boss of the SOC (BOTS) was a competitive, capture-the-flag–style event focused on security operations center skills. Participants investigate simulated security incidents using Splunk data to identify threats, analyze attacks, and answer challenge questions. It is designed to test threat detection, incident response, and data analysis capabilities in realistic, hands-on scenarios.

Since most CTFs have an offensive focus, Splunk BOTS is a refreshing alternative. They were organized through 2016 until 2019 (four editions). They still host various challenges on their [website](https://bots.splunk.com/), including the first edition. Edition two and three can be found on GitHub. 

I first learned about Splunk BOTS during a FIRST Technical Colloquium talk given by ex-employees and decided to give it a go myself. 

!!! info
    The answers should adhere to Splunk tips and tricks as listed on my [Splunk cheatsheet](../cheatsheets/splunk.md). 

## BOTS V1 (2015)

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

??? success "Question 103"  
    
    !!! question 
        What content management system is imreallynotbatman.com likely using?

??? success "Question 104"  
    
    !!! question 
        What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

??? success "Question 105"  
    
    !!! question 
        This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

??? success "Question 106"  
    
    !!! question 
        What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

??? success "Question 108"  
    
    !!! question 
        What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

??? success "Question 109"  
    
    !!! question 
        What is the name of the executable uploaded by Po1s0n1vy? 

??? success "Question 110"  
    
    !!! question 
        What is the MD5 hash of the executable uploaded?

??? success "Question 111"  
    
    !!! question 
        GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

??? success "Question 112"  
    
    !!! question 
        What special hex code is associated with the customized malware discussed in question 111?

??? success "Question 114"  
    
    !!! question 
        What was the first brute force password used?

??? success "Question 115"  
    
    !!! question 
        One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

??? success "Question 116"  
    
    !!! question 
        What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

??? success "Question 117"  
    
    !!! question 
        What was the average password length used in the password brute forcing attempt?

??? success "Question 118"  
    
    !!! question 
        How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? 

??? success "Question 119"  
    
    !!! question 
        How many unique passwords were attempted in the brute force attempt?

### Scenario 2: Ransomware

!!! info "Context"
    After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

    Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...


??? success "Question 200"  
    
    !!! question 
        What was the most likely IPv4 address of we8105desk on 24AUG2016? 

    ``` query title="Query"
    index="botsv1" host="we8105desk.waynecorpinc.local"
    ```

    Filter for the hostname and look for the most frequent source IP in the sidebar. This will be: **192.168.250.100**.

??? success "Question 201"  
    
    !!! question 
        Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.

    ``` query title="Query"
    index="botsv1" sourcetype="suricata" src_ip="192.168.250.100" "Cerber"
    ```

    Filter for logs generated by suricata, containing the IP mentioned in the last question, and containing the malware name (this query could be optimized by searching in specific fields). Use the sidebar to locate the ID, which will be: **2816763**. 

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
    index="botsv1" sourcetype="stream:dns" "192.168.250.100" earliest="08/24/2016:0:0:0" latest="08/24/2016:23:59:59" | reverse | table _time, query
    ```

    Run a query on the DNS data with the correct time range. The IP address is searched with a raw term search as the 'host_addr' field needed is an array and thus doesn't search easily. The query formats the output into a table that is sorted on ascending time. On page nine the suspicious domain is found: **solidaritedeproximite.org**.

??? success "Question 204"  
    
    !!! question 
        During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

    ``` query title="Query"
    index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" dvc_nt_host="we8105desk" ".vbs" | eval length=len(cmdline) | table _time, CommandLine,length | reverse
    ```

    Sysmon data will include the VB script. Look for anything related to '.vbs' and compute the cmdline length. We then use a table to display the results in ascending order. Don't forget to reset the time range to all time after answering the questions before.

    We find ten different command lines. The first suspicious one has a length of: **4490**.

??? success "Question 205"  
    
    !!! question 
        What is the name of the USB key inserted by Bob Smith?

??? success "Question 206"  
    
    !!! question 
        Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

??? success "Question 207"  
    
    !!! question 
        How many distinct PDFs did the ransomware encrypt on the remote file server? 

??? success "Question 208"  
    
    !!! question 
        The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

??? success "Question 209"  
    
    !!! question 
        The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

??? success "Question 210"  
    
    !!! question 
        The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file? 

??? success "Question 211"  
    
    !!! question 
        Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?
