# Detection Engineering: Lateral Movement via PSEXESVC, WMIC, and PowerShell in Splunk

---

## Overview  
Designed and implemented detection logic in Splunk to identify lateral movement activity within a Windows environment using Windows Security Event Logs.  

The detection focuses on identifying how attackers move across systems after initial access by leveraging built-in administrative tools such as PSExesvc, WMIC, and PowerShell.  

Using log correlation and behavioral analysis, this project detects suspicious authentication patterns, privilege escalation, and remote command execution to support early detection and SOC investigation.

---

## Detection Logic Summary
Correlated authentication (Event ID 4624), privilege escalation (Event ID 4672), and process execution (Event ID 4688) events to identify lateral movement patterns across multiple hosts originating from a single source system.

---

## Attack Scenario  
An attacker gains initial access to a workstation and begins moving laterally across multiple systems in the network.

To achieve this, the attacker:
- Authenticates remotely using valid credentials (Event ID 4624 – Logon Type 3)  
- Gains elevated privileges (Event ID 4672)  
- Executes remote commands using Windows service-based execution (PSEXESVC.exe)  
- Runs reconnaissance commands such as:
  - cmd.exe /c whoami && ipconfig /all  
- Uses WMIC and encoded PowerShell commands to execute processes remotely  
- Repeats activity across multiple hosts (APP-01, DB-01, FILE-01, HR-APP-01, PRINT-01, WEB-01)

The goal of this detection is to identify these behaviors early before full network compromise occurs.

---

## Detection Focus  
- Remote logon activity (Event ID 4624 – Logon Type 3)  
- Privileged logons (Event ID 4672)  
- Process execution (Event ID 4688)  
- Service-based execution using PSEXESVC.exe  
- WMIC-based remote command execution  
- Encoded PowerShell command execution  
- Multi-host lateral movement patterns  
- Abnormal authentication and system access behavior  

---

## Data Source  
- Windows Security Event Logs  
- Sourcetype: Window_log  


---

## Detection Approach  


1. Initial Detection  
   Identified events labeled as lateral movement and reviewed raw logs containing:
   - Event IDs 4624, 4672, and 4688  
   - Process execution (PSEXESVC.exe, cmd.exe)  
   - Command-line activity  

2. Multi-Host Analysis  
   Detected a single source system accessing multiple destination hosts within a short timeframe  

3. Command Execution Analysis  
   Identified suspicious command execution including:
   - WMIC remote process creation  
   - Encoded PowerShell commands (-enc)  
   - Command-line reconnaissance activity  

4. Event Correlation  
   Correlated:
   - Logon events (4624)  
   - Privilege assignment (4672)  
   - Process creation (4688)  
   to reconstruct the attack chain  

5. Behavioral Pattern Identification  
   Observed repeated lateral movement across multiple systems from the same source  

6. Anomaly Detection  
   Applied statistical baseline (average and standard deviation) to identify abnormal activity volumes across hosts  

---

## Key Findings  
- Remote execution via PSEXESVC.exe indicating service-based lateral movement  
- Use of WMIC to execute commands on remote systems  
- Encoded PowerShell commands suggesting obfuscation techniques  
- Repeated authentication and access across multiple systems  
- Clear lateral movement pattern originating from a single source host  
- Abnormal activity detected using statistical anomaly detection  

---

## Alerting & Use Case  
Developed Splunk detection logic to support:

- Early identification of lateral movement activity  
- Detection of compromised systems spreading across the network  
- Correlation of authentication and process execution events  
- Reduction of attacker dwell time  

---

## MITRE ATT&CK Mapping  
- T1021 – Remote Services (Lateral Movement)  
- T1047 – Windows Management Instrumentation (Execution)  
- T1569.002 – Service Execution (PSEXESVC)  
- T1078 – Valid Accounts  

---

## Technologies & Tools  
- Splunk (Search & Reporting)  
- Windows Security Logs  
- SPL (Search Processing Language)  

---

## Skills Demonstrated  
- Detection Engineering  
- Threat Hunting  
- Lateral Movement Analysis  
- Windows Event Log Correlation  
- SIEM Alert Development  
- Behavioral Analytics  

---


## Disclaimer  
This project was conducted in a controlled  environment using simulated data for defensive security and detection engineering purposes.
