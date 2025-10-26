

---

## 🧪 LABS

### 1. Sherlock — Noxious (LLMNR Poisoning)
- **Platform:** [HackTheBox Sherlock](https://labs.hackthebox.com/achievement/sherlock/2781127/747)  
- **Overview:** Detected and investigated unusual LLMNR traffic on the internal Active Directory VLAN. A rogue host (`(hostname)` at `(IP address)`) captured an NTLMv2 hash from `(username)` due to a typo when navigating a file share (`(typo)`). Extracted NTLM artifacts from the PCAP and successfully cracked the password (`(password)`) to confirm its complexity and verify attacker access.  
  
- **Skills:**  
  - Network threat hunting (LLMNR poisoning detection)  
  - Packet capture analysis (Wireshark / tshark)  
  - NTLM hash extraction and cracking (Hashcat)  
  - Incident documentation and SOC reporting
 
  - 
### 2. Threat Hunting Simulation - Supply Chain Compromise
- **Platform:** [TryHackMe — Threat Hunting Simulation](https://tryhackme.com/threat-hunting-sim/public-summary/5fadada12350de7b6000afba6a50546bd30f715cd232db5d62284da9ce8ce11ba4c498d97a7d2e5b843418477fd1d598)  
- **Overview:** Identified initial access via a **compromised third‑party package**, observed silent payload staging, and confirmed persistence mechanisms. Mapped the kill chain end-to-end, validated the hunting hypothesis, and collected actionable IOCs. 🕵🏾‍♀️  
- **Skills Practiced:**  
  - Network threat hunting (supply‑chain compromises)  
  - Malware staging & persistence analysis  
  - IOC collection and SOC reporting  
  - Kill chain mapping and timeline reconstruction  

### 🔑Key Points
- **Access:** supply‑chain (malicious package)  
- **Staging:** low‑noise payload deployment  
- **Persistence:** backdoor/service established  
- **Outcome:** timeline, IOCs, mitigation-ready detections


