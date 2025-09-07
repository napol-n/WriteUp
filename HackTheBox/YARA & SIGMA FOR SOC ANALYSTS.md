# YARA & SIGMA for SOC Analysts
> A comprehensive lab guide for threat hunting and malware detection

---

## 🎯 Overview
This guide covers practical labs for SOC analysts to master **YARA** and **Sigma** rules for:
- Malware detection and analysis
- Threat hunting in event logs
- Process memory scanning
- Security orchestration and response

---

# 🔬 YARA Labs

## Lab 1: Developing YARA Rules
**Objective**: Analyze `DirectX.dll` and modify a YARA rule to detect APT17 malware

### 📋 Lab Environment
- **Target File**: `/home/htb-student/Samples/YARASigma/DirectX.dll`
- **YARA Rule**: `/home/htb-student/Rules/yara/apt_apt17_mal_sep17_1.yar`
- **Tools**: `strings`, `grep`, `yara`

### 🔍 Step 1: Review the Original YARA Rule
```yara
rule APT17_Malware_Oct17_1 {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth (Nextron Systems)"
   strings:
      $s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" ascii
      $s2 = "\\spool\\prtprocs\\x64\\localspl.dll" ascii
      $s3 = "\\msvcrt.dll" ascii
      $s4 = "\\X.dll" ascii    // 🎯 Replace this placeholder
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}
```

### 🔍 Step 2: Extract DLL Strings
```bash
strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep -E '\.dll$'
```

**Output Analysis**:
```
KERNEL32.dll
ADVAPI32.dll  
MSVCRT.dll
kernel32.dll
\msvcrt.dll
\spool\prtprocs\w32x86\localspl.dll
\spool\prtprocs\x64\localspl.dll
\TSMSISrv.dll    // 🎯 This is the missing DLL!
```

### ✅ Solution
- **Missing DLL**: `TSMSISrv.dll`
- Replace `$s4 = "\\X.dll"` with `$s4 = "\\TSMSISrv.dll"`

**Answer Format**: `_.dll`  
**Answer**: `TSMSISrv.dll`

---

## Lab 2: Hunting Evil with YARA (Windows Edition)
**Objective**: Configure YARA rule to detect "Sandbox detected" message in process memory

### 📋 Lab Environment  
- **Rule File**: `C:\Rules\yara\shell_detector.yar`
- **Target**: `C:\Samples\MalwareAnalysis\shell.exe`

### 🔍 Original YARA Rule
```yara
rule shell_detected {
    meta:
        description = "Detect Domain & Sandbox Message In Process Memory"
        author = "Dimitrios Bougioukas"
    
    strings:
        $domain = { 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d }
        $sandbox = {  }    // 🎯 Need to fill this
    
    condition:
        $domain and $sandbox
}
```

### 🔍 Converting String to Hex
```python
# Python command to convert string to hex
"Sandbox detected".encode('utf-8').hex()
# Output: 53616e64626f78206465746563746564
```

### ✅ Solution
```yara
$sandbox = { 53616e64626f78206465746563746564 }
```

**Answer Format**: Remove spaces  
**Answer**: `53616e64626f78206465746563746564`

---

## Lab 3: Hunting Evil with YARA (Linux Edition)
**Objective**: Identify WannaCry process responsible for shadow volume deletion

### 📋 Lab Environment
- **Memory Dump**: `/home/htb-student/MemoryDumps/compromised_system.raw`
- **Reference**: [VMware Shadow Volume Deletion Report](https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html)

### 🔍 Understanding Shadow Volume Deletion
WannaCry uses these commands to delete shadow copies:
- `vssadmin delete shadows`
- `vssadmin delete shadows /all`
- `wmic shadowcopy delete`
- `wmic shadowcopy delete /all`

### 🔍 YARA Rule for Detection
```yara
rule ShadowVolumeDeletion {
    meta:
        description = "Detects shadow volume deletion activities"
        author = "Fares Morcy"
        last_modified = "2024-04-03"

    strings:
        $vssadmin_delete = "vssadmin delete shadows"
        $vssadmin_delete_all = "vssadmin delete shadows /all"
        $wmic_shadow_delete = "wmic shadowcopy delete"
        $wmic_shadow_delete_all = "wmic shadowcopy delete /all"
        $cmd_args = "-delete"

    condition:
        any of ($vssadmin_delete, $vssadmin_delete_all, $wmic_shadow_delete, $wmic_shadow_delete_all) or
        any of ($cmd_args)
}
```

### 🔍 Memory Analysis with Volatility
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/shadow_volume_deletion.yar
```

**Expected Output**:
```
Rule: ShadowVolumeDeletion
Owner: Process @WanaDecryptor@ Pid 3200
0x00420fdb 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 vssadmin.delete.
```

### ✅ Solution
**Process Name**: `@WanaDecryptor@`

---

# 📊 Sigma Labs

## Lab 4: Developing Sigma Rules  
**Objective**: Use Sigma rules to detect malicious drivers in Windows Event Logs

### 📋 Lab Environment
- **Target VM**: `10.129.228.137` (RDP)
- **Credentials**: `htb-student` / `HTB_@cademy_stdnt!`
- **Event Log**: `C:\Events\YARASigma\lab_events_4.evtx`
- **Sigma Rule**: `C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml`

### 🔍 Step 1: Convert Sigma to PowerShell
```bash
python sigmac -t powershell 'C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml' > translated.ps1
```

**Generated PowerShell Query**:
```powershell
Get-WinEvent | where {($.ID -eq "1006" -or $.ID -eq "1116" -or $.ID -eq "1015" -or $.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

### 🔍 Step 2: Execute Against Event Log
```powershell
Get-WinEvent -Path "C:\Events\YARASigma\lab_events_4.evtx" | where {($.ID -eq "1006" -or $.ID -eq "1116" -or $.ID -eq "1015" -or $.ID -eq "1117")} | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

**Sample Output**:
```
TimeCreated  : 12/11/2020 4:28:01 AM
Id           : 1116
RecordId     : 171
ProcessId    : 4172
MachineName  : WIN10-client01.offsec.lan
Message      : Microsoft Defender Antivirus has detected malware...
               Detection Source: file:_C:\Users\admmig\Documents\mimidrv.sys
```

### ✅ Solution
**Malicious Driver**: `mimidrv.sys`

---

## Lab 5: Hunting Evil with Sigma (Chainsaw Edition)
**Objective**: Detect suspicious Windows Defender exclusions using Chainsaw

### 📋 Lab Environment
- **Tool**: `C:\Tools\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe`
- **Event Log**: `C:\Events\YARASigma\lab_events_5.evtx`
- **Sigma Rule**: `posh_ps_win_defender_exclusions_added.yml`

### 🔍 Chainsaw Hunt Command
```powershell
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml --mapping .\mappings\sigma-event-logs-all-new.yml
```

### 🔍 Analysis Results
| Timestamp | Detection | Event ID | Script Block Text |
|-----------|-----------|----------|-------------------|
| 2021-10-06 11:14:56 | Windows Defender Exclusions Added | 4104 | `Set-MpPreference -ExclusionPath c:\document\virus\` |
| 2021-10-06 11:15:06 | Windows Defender Exclusions Added | 4104 | `Set-MpPreference -ExclusionExtension '.exe'` |

### ✅ Solution
**Excluded Directory**: `c:\document\virus\`

---

## Lab 6: Hunting Evil with Sigma (Splunk Edition)
**Objective**: Hunt for suspicious archive drops using Splunk search

### 📋 Lab Environment
- **Sigma Rule**: `C:\Rules\sigma\file_event_win_app_dropping_archive.yml`
- **Splunk Instance**: `http://[Target IP]:8000`

### 🔍 Step 1: Convert to Splunk Query
```powershell
python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml -c .\config\splunk-windows.yml
```

**Generated Splunk Query**:
```splunk
( Image="\winword.exe" OR Image="\excel.exe" OR Image="\powerpnt.exe" OR Image="\msaccess.exe" OR Image="\mspub.exe" OR Image="\eqnedt32.exe" OR Image="\visio.exe" OR Image="\wordpad.exe" OR Image="\wordview.exe" OR Image="\certutil.exe" OR Image="\certoc.exe" OR Image="\CertReq.exe" OR Image="\DesktopImgDownldr.exe" OR Image="\esentutl.exe" OR Image="\finger.exe" OR Image="\notepad.exe" OR Image="\AcroRd32.exe" OR Image="\RdrCEF.exe" OR Image="\mshta.exe" OR Image="\hh.exe" OR Image="\SharpHound.exe" ) AND ( TargetFilename=".zip" OR TargetFilename=".rar" OR TargetFilename=".7z" OR TargetFilename=".diagcab" OR TargetFilename=".appx" )
```

### ✅ Solution
**Target Filename**: `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`

---

# 🎓 Skills Assessment

## Question 1: Detecting Seatbelt.exe
**Objective**: Complete YARA rule to detect Seatbelt.exe .NET assembly

### 📋 Lab Setup
- **Sample**: `C:\Samples\YARASigma\Seatbelt.exe`
- **YARA Rule**: `C:\Rules\yara\seatbelt.yar`

### 🔍 Rule Analysis
```yara
strings:
    $class1 = "WMIUtil"
    $class2 = ""           // 🎯 Need to fill this
    $class3 = "SecurityUtil"  
    $class4 = "MiscUtil"
    $dotnetMagic = "BSJB" ascii
```

### 🔍 Finding the Missing Class
```powershell
strings Seatbelt.exe | findstr /R "^L.*r$"
```

**Relevant Matches**:
- `LocalAddr`
- `LsaFreeReturnBuffer`
- **`LsaWrapper`** ← 10 letters, fits format `L________r`
- `LAPSFormatter`
- `LocalComputer`

### ✅ Solution
**Answer Format**: `L________r`  
**Answer**: `LsaWrapper`

---

## Question 2: Shadow Volume Deletion Detection
**Objective**: Identify ScriptBlock ID for shadow volume deletion

### 📋 Lab Environment
- **Tool**: Chainsaw
- **Event Log**: `C:\Events\YARASigma\lab_events_6.evtx`
- **Sigma Rule**: `posh_ps_susp_win32_shadowcopy.yml`

### 🔍 Sigma Rule Detection Logic
The rule detects PowerShell scripts containing **all three strings**:
- `Get-WmiObject`
- `Win32_Shadowcopy`
- `Delete()`

### 🔍 Chainsaw Hunt Command
```powershell
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml --mapping .\mappings\sigma-event-logs-all.yml
```

### 🔍 Expected Output
```
Timestamp: 2021-12-19 15:13:49 
Title: Delete Volume Shadow Copies via WMI with PowerShell 
ScriptBlock ID: faaeba08-01f0-4a32-ba48-bd65b24afd28 
ScriptBlock Text: Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() } 
Event ID: 4104
Computer: FS03.offsec.lan
```

### ✅ Solution
**ScriptBlock ID**: `faaeba08-01f0-4a32-ba48-bd65b24afd28`

---

## 🔗 References & Resources

### Documentation
- [YARA Official Documentation](https://yara.readthedocs.io/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [Florian Roth's Signature Base](https://github.com/Neo23x0/signature-base)

### Tools
- **Chainsaw**: Sigma rule hunting for forensic artifacts
- **Volatility**: Memory analysis framework
- **Sigmac**: Sigma rule converter
- **Splunk**: SIEM platform for log analysis

### Threat Intelligence
- [VMware Security Blog](https://blogs.vmware.com/security/)
- APT17 Malware Analysis Reports
- WannaCry Ransomware Technical Analysis

---

> 💡 **Pro Tips for SOC Analysts**
> - Always validate YARA rules against known samples
> - Use multiple detection layers (file, memory, network)
> - Regularly update Sigma rules for emerging threats  
> - Practice with different log sources and formats
> - Maintain a library of custom detection rules
