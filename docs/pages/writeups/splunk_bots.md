# Splunk Boss of the SOC (BOTS)

## Introduction
Splunk Boss of the SOC (BOTS) was a competitive, capture-the-flag–style event focused on security operations center skills. Participants investigate simulated security incidents using Splunk data to identify threats, analyze attacks, and answer challenge questions. It is designed to test threat detection, incident response, and data analysis capabilities in realistic, hands-on scenarios.

Since most CTFs have an offensive focus, Splunk BOTS is a refreshing alternative. They were organized through 2016 until 2019 (four editions). They still host various challenges on their [website](https://bots.splunk.com/), including the first edition. Edition two and three can be found on GitHub. 

I first learned about Splunk BOTS during a FIRST Technical Colloquium talk given by ex-employees and decided to give it a go myself. 

## BOTS V1

### Scenario 1: Web site defacement


!!! info "Context"
    Today is Alice's first day at the Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprises' IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.

??? success "Question 101"  
    
    !!! question 
        What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

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

###x Scenario 2: Ransomware

!!! info "Context"
    After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

    Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...


??? success "Question 200"  
    
    !!! question 
        What was the most likely IPv4 address of we8105desk on 24AUG2016?

    ``` query title="Query"
    index="botsv1" hostname="we8105desk.waynecorpinc.local"
    ```

    Filter for the hostname and look for the most frequent source IP in the sidebar. This will be **192.168.250.100**.

??? success "Question 201"  
    
    !!! question 
        Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.

    ``` query title="Query"
    index="botsv1" sourcetype="suricata" "192.168.250.100" "Cerber"
    ```

    Filter for logs generated by suricata, containing the IP mentioned in the last question, and containing the malware name (this query could be optimized by searching in specific fields). Use the sidebar to locate the ID, which will be **2816763**. 

??? success "Question 202"  
    
    !!! question 
        What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

??? success "Question 203"  
    
    !!! question 
        What was the first suspicious domain visited by we8105desk on 24AUG2016?

??? success "Question 204"  
    
    !!! question 
        During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

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
