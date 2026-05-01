# Exposed VM Investigation

## 1. Preparation

### Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet.

**Description:**

- Some legacy devices are missing account lockout policies, allowing unlimited failed login attempts.
- `windows-target-1` was exposed to the internet for an extended period.

**Task:**

- Identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

**Goal:**

- Investigate whether threat actors brute-force logged into legacy devices while they were unknowingly exposed to the internet, due to missing account lockout controls.

---

### Components, Tools, and Technologies Employed

- **Cloud Environment:** Microsoft Azure (VM-Windows target machine)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
  
----

## 2. Detection & Analysis

### **Device Exposure Detection**

Identified `windows-target-1` exposed to the public internet by filtering internet-facing devices and validating external exposure.
<br><br>
```kql
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing = True
| order by Timestamp desc  
```

<img alt="Image" src="https://github.com/user-attachments/assets/355b2b55-66af-4335-857f-0b4abff580ee" />
<br><br>

Findings: `windows-target-1` was confirmed to be internet-facing as of **`2025-05-07T23:14:33Z`**.

---

### **IOC & Process Activity Analysis**

Reviewed process activity and file system behavior to identify PwnCrypt indicators of compromise (IOCs).
<br><br>
```kql
let PatientZero  = "cyberclaw-vm";
let SpecificTime = datetime(2026-04-26T01:13:33.1636981Z);
DeviceProcessEvents
| where Timestamp between ((SpecificTime - 5m) .. (SpecificTime + 5m))
| where InitiatingProcessCommandLine contains "pwncrypt" or FolderPath contains "pwncrypt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine 
```
<img alt="Image" src="https://github.com/user-attachments/assets/61dc43d5-4aaf-4813-a802-4dd91d92ee8d" />

#### `Timestamp captured: 2026-04-26T01:13:33.1636981Z`

Findings: The attack chain: `cmd.exe` launched `powershell.exe` with execution policy bypass to run `C:\programdata\pwncrypt.ps1`, confirming the ransomware's delivery mechanism.

---

### **MITRE ATT&CK Mapping: Tactics, Techniques, and Procedures (TTPs)**

- [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

- [T1685 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)

- [T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

- [T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

- [T1027 – Obfuscated/Hidden Files and Information](https://attack.mitre.org/techniques/T1027/)

---

## 3. Response

To contain the threat and prevent further encryption, take the following actions:
<br><br>
<img width="635" alt="Image" src="https://github.com/user-attachments/assets/dd5770db-ad54-4a7d-9b25-d727cb5d1d94" />
<br><br>

- Immediately isolate `cyberclaw-vm` from the network to prevent lateral movement or further malicious activity.
- Terminate any active `powershell.exe` processes initiated by `cmd.exe`, as they are tied to the malicious execution chain.
- Remove `C:\ProgramData\pwncrypt.ps1` and all related ransomware artifacts from the system.
- Reimage or rebuild `cyberclaw-vm` to a **known-good baseline** to ensure full eradication and integrity restoration.

---

## 4. Documentation
Findings:

- Ransomware execution confirmed via PowerShell invocation from command shell.
- File staging behavior observed in Desktop and Temp directories.
- Execution chain validated through correlated process and file telemetry.
- System compromise contained and remediated through isolation and reimaging.
  
---

## 5. Improvement

- Implement Ransomware Detection & Blocking (PowerShell execution and `.pwncrypt` file activity)
- Enable Continuous Endpoint Monitoring (`cmd.exe` → `powershell.exe` and abnormal file renaming)
- Restrict PowerShell Execution (block or tightly control -ExecutionPolicy Bypass)
- Enable Detailed Security Logging (process creation, script execution, and file system changes)

---
## 🧾Summary                   
A ransomware variant, **PwnCrypt**, was detected on the host `cyberclaw-vm` using a PowerShell-based payload that encrypted files located in `C:\Users\Public\Desktop`. The investigation revealed files being created on the Desktop and rapidly renamed in the Temp directory with the `.pwncrypt` extension. Telemetry also showed `cmd.exe` launching `powershell.exe` with the **-ExecutionPolicy Bypass** flag to execute a script from `C:\ProgramData\pwncrypt.ps1`. The affected system was immediately isolated, malicious artifacts were removed, and the host was reimaged to restore a clean state.

## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
