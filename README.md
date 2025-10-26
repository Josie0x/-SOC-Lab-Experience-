

---

## 🧪 Labs

### 1. Sherlock — Noxious (LLMNR Poisoning)
- **Platform:** [HackTheBox Sherlock](https://labs.hackthebox.com/achievement/sherlock/2781127/747)  
- **Overview:** Detected and investigated unusual LLMNR traffic on the internal Active Directory VLAN. A rogue host (`kali` at `172.17.79.135`) captured an NTLMv2 hash from `john.deacon` due to a typo when navigating a file share (`DCC01`). Extracted NTLM artifacts from the PCAP and successfully cracked the password (`NotMyPassword0K?`) to confirm its complexity and verify attacker access.  
- **Skills Practiced:**  
  - Network threat hunting (LLMNR poisoning detection)  
  - Packet capture analysis (Wireshark / tshark)  
  - NTLM hash extraction and cracking (Hashcat)  
  - Incident documentation and SOC reporting  

