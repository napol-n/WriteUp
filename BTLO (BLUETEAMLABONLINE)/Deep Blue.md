# Deep Blue - Windows Workstation Compromise Investigation

## Executive Summary

A Windows workstation was recently compromised through an attack against internet-facing RDP (Remote Desktop Protocol). Following initial access, Meterpreter was deployed to conduct malicious activities. This investigation analyzes Security.evtx and System.evtx logs to verify the attack findings.

## Investigation Overview

### Scenario
Evidence suggests a multi-stage attack:
1. Initial compromise via internet-facing RDP
2. Deployment of Meterpreter for post-exploitation activities
3. Actions on objectives including persistence mechanisms

### Tools and Data Sources
- **DeepBlueCLI PowerShell Script** - Automated log analysis
- **Windows Event Viewer** - Manual log examination  
- **Security.evtx** - Security event logs from compromised system
- **System.evtx** - System event logs from compromised system

> ⚠️ **Note**: Analysis focused on exported logs from `\Desktop\Investigation`, not live system logs

## Key MITRE ATT&CK Techniques Identified
- **T1133** - External Remote Services
- **T1078.003** - Valid Accounts: Local Accounts  
- **T1136.001** - Create Account: Local Account
- **T1543.003** - Create or Modify System Process: Windows Service

---

## Investigation Findings

### Q1: GoogleUpdate.exe Execution Analysis
**Question**: Which user account ran GoogleUpdate.exe?

**Method**: DeepBlueCLI analysis of Security.evtx
```powershell
.\DeepBlue.ps1 ..\Security.evtx
```

**Findings**:
- **Event ID**: 4688 (Process Creation)
- **Process Path**: `C:\Users\Mike Smith\AppData\Local\Google\Update\GoogleUpdate.exe`
- **User Account**: Mike Smith

**Answer**: `Mike Smith`

---

### Q2: Meterpreter Activity Timeline
**Question**: At what time is there likely evidence of Meterpreter activity?

**Method**: DeepBlueCLI analysis of Security.evtx logs

**Findings**:
- Suspicious process creation activities detected
- Meterpreter-like behavior patterns identified

**Answer**: `4/10/2021 10:48:14`

---

### Q3: Malicious Service Creation
**Question**: What is the name of the suspicious service created?

**Method**: DeepBlueCLI analysis of System.evtx
```powershell
.\DeepBlue.ps1 ..\System.evtx
```

**Findings**:
- **Event ID**: 7045 (Suspicious Service Created)
- **Service Name**: rztbzn
- **Analysis**: Randomly generated service name indicating malicious activity

**Answer**: `rztbzn`

---

### Q4: Initial Payload Identification
**Question**: Identify the malicious executable downloaded for Meterpreter reverse shell (10:30-10:50 AM, April 10, 2021)

**Method**: Manual analysis of Security.evtx using Event Viewer

**Findings**:
- **Event ID**: 4688 (Process Creation)
- **Timestamp**: 4/10/2021 10:32:05 AM
- **User**: Mike Smith
- **Executable**: `serviceupdate.exe`
- **Full Path**: `C:\Users\Mike Smith\Downloads\serviceupdate.exe`

**Answer**: `Mike Smith,serviceupdate.exe`

---

### Q5: Persistence Account Creation
**Question**: What command line was used to create an additional persistence account (11:25-11:40 AM, April 10, 2021)?

**Method**: Event Viewer analysis of Security.evtx

**Findings**:
- **Event ID**: 4688 (Process Creation)
- **Timeframe**: 4/10/2021 11:29:00 - 11:29:15 AM
- **User**: Mike Daniels
- **Process**: `C:\Windows\System32\net.exe`
- **Command**: `net user ServiceAct /add`

**Answer**: `net user ServiceAct /add`

---

### Q6: Privilege Escalation Groups
**Question**: What two local groups was the new account added to?

**Method**: Analysis of group membership events

**Findings**:
- **Event ID 4728**: Member added to global group
- **Event ID 4732**: Member added to local group
- **Account**: ServiceAct
- **Groups Added**:
  - Administrators (full system privileges)
  - Remote Desktop Users (remote access capability)

**Answer**: `Administrators, Remote Desktop Users`

---

## Attack Timeline Summary

| Time | Activity | Details |
|------|----------|---------|
| 10:32:05 AM | Initial Payload | `serviceupdate.exe` downloaded and executed |
| 10:48:14 AM | Meterpreter Activity | Post-exploitation framework deployment |
| 11:29:00 AM | Account Creation | `ServiceAct` user account created |
| 11:29:15 AM | Privilege Escalation | Account added to Administrators and RDP groups |
| Unknown | Service Persistence | Malicious service `rztbzn` installed |

## Threat Assessment

### Attack Sophistication
- **Medium**: Used legitimate Windows tools (net.exe) for persistence
- **Evasive**: Disguised malicious executable as system update
- **Persistent**: Multiple persistence mechanisms (user account + service)

### Impact Analysis
- **High**: Administrative access achieved
- **High**: Remote access capability established  
- **High**: Persistent backdoor mechanisms installed

## Recommendations

1. **Immediate Actions**:
   - Disable/remove ServiceAct account
   - Remove rztbzn service
   - Reset Mike Smith account credentials
   - Audit all administrative accounts

2. **Security Hardening**:
   - Implement RDP access controls
   - Enable advanced audit policies
   - Deploy endpoint detection and response (EDR)
   - Regular security log monitoring

3. **Monitoring**:
   - Monitor for Event IDs 4688, 4728, 4732, 7045
   - Implement behavioral analysis for process creation
   - Alert on suspicious service installations

---

*Investigation completed using DeepBlueCLI and Windows Event Viewer analysis of Security.evtx and System.evtx logs.*
