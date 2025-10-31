# 🧪 LAB MUSEUM 


<img width="768" height="281" alt="Screenshot 2025-10-31 at 1 40 05 PM" src="https://github.com/user-attachments/assets/ea4c70d5-40a2-4946-ac6e-26a862b83a87" />

### 1.Web Attack Investigation Lab — LetsDefend 🕵️‍♂️
- **Platform:** [LetsDefend — My Reward](https://app.letsdefend.io/my-rewards/detail/3ee3349b6e5345d885c044e173f017cd)
- **Overview:** Investigated web attacks and analyzed suspicious activity as a SOC analyst. 
  - OWASP  
  - Detecting SQL Injection Attacks  
  - Detecting Cross Site Scripting (XSS) Attacks  
  - Detecting Command Injection Attacks  
  - Detecting Insecure Direct Object Reference (IDOR) Attacks  
  - Detecting RFI & LFI Attacks  

- **Skills:**  
  - Log analysis and attacker activity reconstruction (`access.log`)  
  - Detection of automated web reconnaissance  
  - Directory and brute-force discovery assessment  
  - Code injection identification and payload extraction  
  - Persistency mechanism identification from web logs
 ---

 <img width="525" height="222" alt="Screenshot 2025-10-31 at 2 14 30 PM" src="https://github.com/user-attachments/assets/22d4c1fb-80ef-4aaf-8584-8e40c2d53864" />
  
  ### 2. Threat Hunting Simulation - Supply Chain Compromise
- **Platform:** [TryHackMe — Threat Hunting Simulation](https://tryhackme.com/threat-hunting-sim/public-summary/5fadada12350de7b6000afba6a50546bd30f715cd232db5d62284da9ce8ce11ba4c498d97a7d2e5b843418477fd1d598)  
- **Overview:** Identified initial access via a **compromised third‑party package**, observed silent payload staging, and confirmed persistence mechanisms. Mapped the kill chain end-to-end, validated the hunting hypothesis, and collected actionable IOCs. 🕵🏾‍♀️  

- **Skills Practiced:**  
  - Network threat hunting (supply‑chain compromises)  
  - Malware staging & persistence analysis  
  - IOC collection and SOC reporting  
  - Kill chain mapping and timeline reconstruction  

- **Key Points:**  
  - **Access:** supply‑chain (malicious package)  
  - **Staging:** low‑noise payload deployment  
  - **Persistence:** backdoor/service established  
  - **Outcome:** timeline, IOCs, mitigation-ready detections  
---
  -<img width="357" height="377" alt="Screenshot 2025-10-31 at 2 17 42 PM" src="https://github.com/user-attachments/assets/25173242-ccf8-44d4-b833-9b5e65150e5b" />

### 3. Sherlock — Noxious (LLMNR Poisoning)
- **Platform:** [HackTheBox Sherlock](https://labs.hackthebox.com/achievement/sherlock/2781127/747)  
- **Overview:** Detected and investigated unusual LLMNR traffic on the internal Active Directory VLAN. A rogue host (`(hostname)` at `(IP address)`) captured an NTLMv2 hash from `(username)` due to a typo when navigating a file share (`(typo)`). Extracted NTLM artifacts from the PCAP and successfully cracked the password (`(password)`) to confirm its complexity and verify attacker access.  

- **Skills:**  
  - Network threat hunting (LLMNR poisoning detection)  
  - Packet capture analysis (Wireshark / tshark)  
  - NTLM hash extraction and cracking (Hashcat)  
  - Incident documentation and SOC reporting  

---
<img width="375" height="372" alt="Screenshot 2025-10-31 at 2 05 31 PM" src="https://github.com/user-attachments/assets/0e02e49d-95b1-4916-b2c8-0b8f072418eb" />

### 4. Cuidado (Crypto-Mining / PUAs)
- **Platform:** [HackTheBox Sherlock](https://labs.hackthebox.com/achievement/sherlock/2781127/967)    
- **Overview:** A user triggered multiple alerts after downloading several potentially unwanted applications (PUAs). The SOC team monitored network traffic from the victim workstation (`(victim IP)`) and traced downloads from an external attacker server (`(attacker IP)`). The first malicious file (`(first file)`) was retrieved using the attacker's `(function)` over port `(port)`. The script verified writable directories by creating test files, the second of which was `(second test file size)`. CPU architecture was determined with `(cpu command)`, followed by downloading a specific binary (`(downloaded file)`) and disabling any existing mining service (`(disable command)`). Analysis revealed the malware was packed with version `(packer version)`, and the unpacked malware had an entropy of `(entropy value)`. The malware file (`(malware filename)`) was submitted to VirusTotal. The main malware activity maps to MITRE ATT&CK technique `(MITRE ID)`.  

- **Skills:**  
  - Network traffic monitoring and packet analysis (Wireshark / TCP stream analysis)  
  - Malware behavior analysis (payload identification, unpacking, entropy calculation)  
  - System command inspection (`uname -mp`, `systemctl disable`)  
  - MITRE ATT&CK mapping (T1496 – Compute Hijacking)
 
---

  ### 5. Windows Logging for SOC
- **Platform:** [TryHackMe — Windows Logging for SOC](https://tryhackme.com/room/windowsloggingforsoc)  
- **Overview:** Practiced monitoring and analyzing Windows event logs to detect suspicious activity. The lab focused on key Event Viewer logs (`(log type)`), Sysmon telemetry (`(Sysmon events)`), and PowerShell operational logs (`(PowerShell log type)`) to identify potential malicious activity on a Windows host (`(victim hostname / IP)`). Activities included reconstructing process execution (`(example process)`), extracting IOCs (`(example IOC)`), and mapping observed events to a timeline for SOC reporting. The lab also emphasized translating logs into actionable SIEM alerts and hunting hypotheses.  

- **Skills:**  
  - Windows event log analysis (Application, Security, System, PowerShell, Sysmon)  
  - Sysmon & PowerShell telemetry interpretation  
  - IOC extraction and SIEM-ready alert development  
  - Incident timeline reconstruction and SOC reporting  
  - Threat hunting and detection validation
 ---

<img width="377" height="374" alt="Screenshot 2025-10-31 at 2 02 27 PM" src="https://github.com/user-attachments/assets/c27d5387-f65b-43ef-b737-d234d666e307" />

### 6. PhishNet — Sherlock Scenario 🎣
- **Platform:** [HackTheBox — PhishNet](https://labs.hackthebox.com/achievement/sherlock/2781127/985)  
- **Overview:** Investigated a phishing email containing a suspicious link and a `.zip` attachment. The lab focused on analyzing raw email headers (originating IP `(originating IP)`, relayed by `(mail server)`), verifying sender and `Reply-To` addresses (`(sender email)` / `(reply-to email)`), checking SPF (`(SPF result)`), and safely decoding the base64 ZIP attachment (`(base64 snippet)`) to reveal `(zip filename)` → `(malicious inner filename)`. Activities included computing the SHA‑256 hash (`(SHA-256 hash)`), reviewing VirusTotal detections, identifying phishing URL domain `(phishing URL domain)` and fake company branding `(fake company name)`, and mapping the attack to MITRE ATT&CK (primary: `(MITRE technique)`).

- **Skills:**  
  - Email header analysis and sender verification (Received chain, SPF, Reply-To)  
  - Safe artifact extraction and decoding (base64 → unzip) using CyberChef  
  - File hashing and threat intelligence correlation (SHA‑256 → VirusTotal)  
  - Phishing indicator identification (malicious URLs, fake company names, social engineering cues)  
  - Mapping observed artifacts to MITRE ATT&CK techniques and documenting SOC-relevant findings
 
 ---


  

