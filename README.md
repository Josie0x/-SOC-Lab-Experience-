## 🧪 LABS

### 1. Threat Hunting Simulation - Supply Chain Compromise
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

### 2. Sherlock — Noxious (LLMNR Poisoning)
- **Platform:** [HackTheBox Sherlock](https://labs.hackthebox.com/achievement/sherlock/2781127/747)  
- **Overview:** Detected and investigated unusual LLMNR traffic on the internal Active Directory VLAN. A rogue host (`(hostname)` at `(IP address)`) captured an NTLMv2 hash from `(username)` due to a typo when navigating a file share (`(typo)`). Extracted NTLM artifacts from the PCAP and successfully cracked the password (`(password)`) to confirm its complexity and verify attacker access.  

- **Skills:**  
  - Network threat hunting (LLMNR poisoning detection)  
  - Packet capture analysis (Wireshark / tshark)  
  - NTLM hash extraction and cracking (Hashcat)  
  - Incident documentation and SOC reporting  

---

### 3. Cuidado (Crypto-Mining / PUAs)
- **Platform:** [HackTheBox Sherlock](https://tryhackme.com/room/windowsloggingforsoc)    
- **Overview:** A user triggered multiple alerts after downloading several potentially unwanted applications (PUAs). The SOC team monitored network traffic from the victim workstation (`(victim IP)`) and traced downloads from an external attacker server (`(attacker IP)`). The first malicious file (`(first file)`) was retrieved using the attacker's `(function)` over port `(port)`. The script verified writable directories by creating test files, the second of which was `(second test file size)`. CPU architecture was determined with `(cpu command)`, followed by downloading a specific binary (`(downloaded file)`) and disabling any existing mining service (`(disable command)`). Analysis revealed the malware was packed with version `(packer version)`, and the unpacked malware had an entropy of `(entropy value)`. The malware file (`(malware filename)`) was submitted to VirusTotal. The main malware activity maps to MITRE ATT&CK technique `(MITRE ID)`.  

- **Skills:**  
  - Network traffic monitoring and packet analysis (Wireshark / TCP stream analysis)  
  - Malware behavior analysis (payload identification, unpacking, entropy calculation)  
  - System command inspection (`uname -mp`, `systemctl disable`)  
  - MITRE ATT&CK mapping (T1496 – Compute Hijacking)
 
---

  ### 4. Windows Logging for SOC
- **Platform:** [TryHackMe — Windows Logging for SOC](https://tryhackme.com/room/windowsloggingforsoc)  
- **Overview:** Practiced monitoring and analyzing Windows event logs to detect suspicious activity. The lab focused on key Event Viewer logs (`(log type)`), Sysmon telemetry (`(Sysmon events)`), and PowerShell operational logs (`(PowerShell log type)`) to identify potential malicious activity on a Windows host (`(victim hostname / IP)`). Activities included reconstructing process execution (`(example process)`), extracting IOCs (`(example IOC)`), and mapping observed events to a timeline for SOC reporting. The lab also emphasized translating logs into actionable SIEM alerts and hunting hypotheses.  

- **Skills:**  
  - Windows event log analysis (Application, Security, System, PowerShell, Sysmon)  
  - Sysmon & PowerShell telemetry interpretation  
  - IOC extraction and SIEM-ready alert development  
  - Incident timeline reconstruction and SOC reporting  
  - Threat hunting and detection validation



