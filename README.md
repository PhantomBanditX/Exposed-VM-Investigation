# Internet-Facing Brute Force Activity

<p align="center"> <img height="700" alt="Image" src="https://github.com/user-attachments/assets/26cd523d-2e23-471b-8460-490b982f5f64" /> </p>

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

### **Brute Force Login Attempt Analysis**

Analyzed failed login attempts on `windows-target-1` to identify any brute-force activity from external sources.
<br><br>
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempt = count() by ActionType, RemoteIP, DeviceName
| order by Attempt 
```
<img alt="Image" src="https://github.com/user-attachments/assets/5a89b5c7-b5c1-4ae7-97ad-9f95c0c62e1c" />
<br><br>

Findings: Multiple failed login attempts from remote IP addresses targeting `windows-target-1`.

------

Investigated top five suspicious IP addresses to determine whether any successfully authenticated to the target device.
<br><br>
```kql
// Top 5 IPs with the most logon failures
let RemoteIPsInQuestion = dynamic(["94.26.68.55","94.26.68.54", "103.16.198.50", "61.54.165.97", "103.116.38.114"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img alt="Image" src="https://github.com/user-attachments/assets/5e36339f-0073-4bf0-9f05-3e3f1d045ddf" />
<br><br>

Findings: No successful logons were detected from the top 5 IP addresses associated with the highest failed login activity.

---

### **MITRE ATT&CK Mapping: Tactics, Techniques, and Procedures (TTPs)**

- [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

- [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

- [T1589 - Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)

- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)

- [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

---

## 3. Response

- Review and reset passwords for potentially targeted accounts.
- Block top offending IP addresses across perimeter security controls.
- Enable temporary monitoring alerts for all authentication attempts to the affected system.


---

## 4. Documentation

Findings:

- `windows-target-1` was unintentionally exposed to the public internet for an extended duration.
- 369 failed authentication attempts were observed from multiple external IP addresses.
- No successful logins were detected from the top five most active offending IPs.
- The system lacked an account lockout policy, enabling unrestricted brute-force attempts.
  
---

## 5. Improvement

- Enforce account lockout policies across legacy and high-risk systems to mitigate brute-force attacks.
- Reduce internet exposure by implementing strict network segmentation and hardened firewall rules.
- Apply geo-blocking and conditional access policies to limit unauthorized external traffic.

---
## 🧾Summary                   
Host `windows-target-1` was mistakenly left internet-facing, resulting in sustained brute-force login attempts. While no unauthorized access was confirmed, the absence of lockout protections significantly increased security risk.

## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
