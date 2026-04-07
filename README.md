# 🔍 SOC Lab: Data Exfiltration Detection – Uncovering Covert Data Theft

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat&logo=tryhackme)](https://tryhackme.com)
[![Path](https://img.shields.io/badge/Path-SOC%20Level%201-blue?style=flat)](https://tryhackme.com/path/outline/soclevel1)
[![Topic](https://img.shields.io/badge/Topic-Data%20Exfiltration%20Detection-007ACC?style=flat)](https://tryhackme.com)
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat)]()
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()

**Hands-on SOC detection lab** focused on identifying and stopping **data exfiltration** — one of the highest-impact objectives for attackers after initial compromise.

In this investigation, I analyzed network traffic (PCAPs) and correlated logs in Splunk to detect multiple covert exfiltration channels, including DNS tunneling, FTP uploads, HTTP POSTs, and ICMP covert communication.

## 📌 Investigation Summary
**Room**: Data Exfiltration Detection  
**Objective**: Detect and analyze real-world data exfiltration techniques across common protocols.

**What I Did**:
- Performed deep packet inspection using Wireshark on multiple PCAP files
- Correlated logs in Splunk to uncover hidden exfiltration attempts
- Identified compromised internal hosts and external destinations
- Classified exfiltration methods and mapped them to MITRE ATT&CK

## 🔎 Key Detections
- **DNS Tunneling**: 315 anomalous DNS queries to `tunnelcorp.net` with long encoded subdomains indicating data chunking.  
  **Why suspicious**: High query volume from multiple internal hosts with unusually long query lengths (>30 characters) and many queries without responses — classic signs of DNS tunneling.

- **FTP Exfiltration**: Cleartext file uploads including `customer_data.xlsx` and `internal_passwords.csv`.  
  **Why suspicious**: Multiple connections from guest/root accounts using `STOR` commands with sensitive filenames and large payloads.

- **HTTP Exfiltration**: Large POST request transferring sensitive internal documents.  
  **Why suspicious**: Abnormal outbound payload size (`bytes_sent > 600`) to an external domain, deviating from normal web traffic patterns.

- **ICMP Covert Channel**: Unusually large ICMP Echo Requests containing encoded data.  
  **Why suspicious**: Packet sizes significantly larger than normal ping traffic (`frame.len > 100`), indicating data smuggling.

## 🛠 Tools & Techniques Used
- Wireshark for protocol analysis and packet carving
- Splunk for log correlation and SPL queries
- Linux CLI tools for log parsing and filtering
- Behavioral analysis across DNS, FTP, HTTP, and ICMP traffic

## 🧪 Detection Logic
- **DNS Tunneling** identified via:
  - High query volume to a single suspicious domain
  - Long query length (`len(query) > 30`)
  - Queries without responses (`dns.flags.response == 0`)

- **FTP Exfiltration** identified via:
  - `STOR` commands for file uploads
  - Cleartext credentials (USER/PASS)
  - Large outbound transfers with sensitive filenames

- **HTTP Exfiltration** identified via:
  - Large POST requests (`bytes_sent > 600`)
  - Abnormal outbound traffic patterns to external domains

- **ICMP Exfiltration** identified via:
  - Large packet sizes (`frame.len > 100`)
  - Repeated echo requests with non-standard payloads

## 🧭 MITRE ATT&CK Mapping

| Tactic              | Technique                          | ID            | Observed Activity |
|---------------------|------------------------------------|---------------|-------------------|
| Exfiltration        | Exfiltration Over Alternative Protocol | **T1048**     | DNS Tunneling & ICMP Covert Channel |
| Exfiltration        | Exfiltration Over C2 Channel       | **T1041**     | HTTP POST-based data transfer |
| Exfiltration        | Automated Exfiltration             | **T1020**     | High-volume automated outbound transfers |
| Command and Control | Application Layer Protocol: Web    | **T1071.001** | HTTP for data exfiltration |
| Command and Control | Application Layer Protocol: FTP    | **T1071.002** | FTP uploads using STOR commands |

## 🔎 Evidence – Investigation Screenshots

### 1. Suspicious Domain Receiving DNS Traffic (`tunnelcorp.net`)
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/24315740-15d5-4c23-9b75-05284f84bdbd" />
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/61ccd713-c460-4a00-8d6a-dfb1e181eda6" />

### 2. DNS Tunneling – 315 Suspicious Packets
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/4b04c1c4-b071-4e3d-a268-301cdc7cb736" />

### 3. DNS Conversations – Multiple Internal Hosts Involved
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/e345c7c7-4a4a-4e2d-b165-11eb6e121435" />

### 4. FTP – 5 Connections from Guest Account
<img width="1366" height="735" alt="image" src="https://github.com/user-attachments/assets/08bbee6c-65ca-43bb-a291-98f2a7f6a719" />

### 5. FTP Stream – `customer_data.xlsx` Exfiltrated
<img width="1366" height="731" alt="image" src="https://github.com/user-attachments/assets/0d1af2d7-d298-4487-8648-54a0daf13ca6" />


### 6. FTP Stream – Flag Hidden Inside CSV File
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/cd1dc485-28e3-4a1d-a851-4eb893aaec87" />
*(Evidence observed in TCP stream: `THM{ftp_exfil_hidden_flag}`)*

### 7. HTTP POST Stream – Sensitive Data Exfiltration + Hidden Flag
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/bb1604ef-99bd-4b74-a144-e2a29a8ba14e" />

### 8. ICMP Covert Channel – Flag Found in Large Echo Request
<img width="1366" height="722" alt="image" src="https://github.com/user-attachments/assets/0faa5430-6611-4590-a574-e26caa7ddc30" />

### 9. FTP – Largest Payload Sent by Internal IP `192.168.1.105`
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/8282d008-ac0d-4510-a7da-493ccd5db034" />


## 📌 SOC Insights
Data exfiltration is particularly dangerous because it often blends with legitimate traffic.  
This lab reinforced the importance of behavioral detection and cross-log correlation in identifying stealthy data exfiltration techniques.

## 📝 Lessons Learned
- Always correlate network and host logs to detect stealthy exfiltration.
- High query volume and long DNS subdomains are strong IoAs.
- FTP and HTTP exfiltration can be identified by file size anomalies and unusual destinations.
- ICMP may be abused for covert channels; monitor payload size and frequency.

**Hands-on experience detecting real-world data exfiltration techniques** — practical skills for SOC Analyst and Threat Hunting roles.

Full investigation with annotated screenshots and analysis is available in this repository.

Feel free to fork, star, or reach out with questions. Open to feedback!

**Completed:** April 2026

MIT License – see the [LICENSE](LICENSE) file for details.
