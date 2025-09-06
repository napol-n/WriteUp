# Lab: Developing and Hunting with YARA

This repository contains comprehensive lab exercises for developing YARA rules and conducting malware hunting operations using YARA signatures.

---

## Lab 1: Developing YARA Rules
Perform string analysis on the "DirectX.dll" sample that resides in the "/home/htb-student/Samples/YARASigma" directory of this section's target. Then, study the "apt_apt17_mal_sep17_1.yar" YARA rule that resides in the "/home/htb-student/Rules/yara" directory and replace "X.dll" with the correct DLL name to ensure the rule will identify "DirectX.dll". Enter the correct DLL name as your answer. Answer format: _.dll

### 🎯 Objective
- Perform string analysis on a suspicious DLL (`DirectX.dll`)
- Study and modify an existing YARA rule (`apt_apt17_mal_sep17_1.yar`) to correctly detect the malware sample
- Identify the correct DLL string to replace the placeholder `X.dll`

### 🔧 Environment Setup
- **Target File:** `/home/htb-student/Samples/YARASigma/DirectX.dll`
- **YARA Rules Directory:** `/home/htb-student/Rules/yara/`
- **Rule File:** `apt_apt17_mal_sep17_1.yar`

### 📋 Tools Required
- `strings` - Extract printable strings from binary files
- `grep` - Filter and search for specific patterns
- `yara` - Test and execute YARA rules

### Step 1: Review the Original YARA Rule

```yara
rule APT17_Malware_Oct17_1 {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth (Nextron Systems)"
   strings:
      $s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" ascii
      $s2 = "\\spool\\prtprocs\\x64\\localspl.dll" ascii
      $s3 = "\\msvcrt.dll" ascii
      $s4 = "\\X.dll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}
```

> **Note:** `$s4` contains a placeholder `X.dll` that must be replaced with the correct DLL name found in the malware sample.

### Step 2: Extract DLL Strings from the Sample

```bash
strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep -E '\.dll$'
```

**Output:**
```
KERNEL32.dll
ADVAPI32.dll
MSVCRT.dll
kernel32.dll
\msvcrt.dll
\spool\prtprocs\w32x86\localspl.dll
\spool\prtprocs\x64\localspl.dll
\TSMSISrv.dll
```

### Step 3: Identify the Missing DLL

**Analysis:**
- ✅ `localspl.dll` - Already present in rule ($s1, $s2)
- ✅ `msvcrt.dll` - Already present in rule ($s3)
- ❓ `TSMSISrv.dll` - **Missing from rule, candidate for $s4**

### 🎉 Answer
Replace `X.dll` with: **`TSMSISrv.dll`**

**Updated Rule:**
```yara
rule APT17_Malware_Oct17_1 {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth (Nextron Systems)"
   strings:
      $s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" ascii
      $s2 = "\\spool\\prtprocs\\x64\\localspl.dll" ascii
      $s3 = "\\msvcrt.dll" ascii
      $s4 = "\\TSMSISrv.dll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}
```

---

## Lab 2: Hunting Evil with YARA (Windows Edition)
Study the "C:\Rules\yara\shell_detector.yar" YARA rule that aims to detect "C:\Samples\MalwareAnalysis\shell.exe" inside process memory. Then, specify the appropriate hex values inside the "$sandbox" variable to ensure that the "Sandbox detected" message will also be detected. Enter the correct hex values as your answer. Answer format: Remove any spaces

### 🎯 Objective
- Study and configure a YARA rule (`shell_detector.yar`) to detect specific strings in process memory
- Detect hardcoded domains in memory
- Detect the message "Sandbox detected" in memory

### 🔧 Environment Setup
- **YARA Rule Location:** `C:\Rules\yara\shell_detector.yar`
- **Target:** Process memory analysis

### Step 1: Original Rule Structure

```yara
rule shell_detected
{
    meta:
        description = "Detect Domain & Sandbox Message In Process Memory"
        author      = "Dimitrios Bougioukas"
    strings:
        $domain   = { 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d }
        $sandbox  = {  }
    condition:
        $domain and $sandbox
}
```

### Step 2: Convert String to Hexadecimal

**Target String:** `"Sandbox detected"`

**Conversion Process:**
```python
# Convert string to hexadecimal
"Sandbox detected".encode('utf-8').hex()
# Output: 53616e64626f78206465746563746564
```

**Hex Breakdown:**
```
S  a  n  d  b  o  x     d  e  t  e  c  t  e  d
53 61 6e 64 62 6f 78 20 64 65 74 65 63 74 65 64
```

### Step 3: Updated YARA Rule

```yara
rule shell_detected
{
    meta:
        description = "Detect Domain & Sandbox Message In Process Memory"
        author      = "Dimitrios Bougioukas"
    strings:
        $domain   = { 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d }
        $sandbox  = { 53616e64626f78206465746563746564 }
    condition:
        $domain and $sandbox
}
```

### 📝 Rule Explanation

- **`$domain`:** Hexadecimal pattern for `iuqerfsodp9ifjaposdfjhgosurijfaewrrwergwea.com`
- **`$sandbox`:** Hexadecimal pattern for `"Sandbox detected"`
- **`condition`:** Both patterns must be present in memory for the rule to trigger

### 🎉 Answer
The hexadecimal value for `$sandbox`: **`53616e64626f78206465746563746564`**

---

## Tools and Requirements

### Essential Tools
- **YARA** - Pattern matching engine for malware research
- **strings** - Extract printable strings from binary files
- **grep** - Text search utility
- **hexdump/xxd** - Hexadecimal dump utilities

### System Requirements
- Linux environment (Lab 1)
- Windows environment (Lab 2)
- Python 3.x for hex conversions

### Installation Commands

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install yara strings grep
```

**Windows:**
```powershell
# Install via chocolatey
choco install yara
```

## Additional Resources

### YARA Documentation
- [Official YARA Documentation](https://yara.readthedocs.io/)
- [YARA Rule Writing Guide](https://yara.readthedocs.io/en/stable/writingrules.html)

### Malware Analysis Resources
- [Malware Analysis Techniques](https://github.com/rshipp/awesome-malware-analysis)
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)

### Hex Conversion Tools
- [Online Hex Converter](https://www.rapidtables.com/convert/number/ascii-to-hex.html)
- [CyberChef](https://gchq.github.io/CyberChef/) - Swiss Army knife for data transformation

---

## 📄 License
This lab guide is provided for educational purposes. Please ensure you have proper authorization before testing on any systems.

## 🤝 Contributing
Feel free to submit issues and enhancement requests!

---

## Lab 3: Hunting Evil with YARA (Linux Edition)
Study the following resource https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html to learn how WannaCry performs shadow volume deletion. Then, use yarascan when analyzing "/home/htb-student/MemoryDumps/compromised_system.raw" to identify the process responsible for deleting shadows. Enter the name of the process as your answer.

### 🎯 Objective
Identify the process responsible for deleting shadow volumes on a compromised Windows system by:
- Understanding how WannaCry ransomware performs shadow volume deletion
- Using the `ShadowVolumeDeletion` YARA rule to detect shadow deletion commands
- Scanning a memory dump with Volatility to identify the malicious process

### 🔧 Environment Setup
- **Memory Dump:** `/home/htb-student/MemoryDumps/compromised_system.raw`
- **YARA Rules Directory:** `/home/htb-student/Rules/yara/`
- **Reference Article:** [VMware Threat Report - Illuminating Volume Shadow Deletion](https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html)

### 📋 Tools Required
- **Volatility** - Memory analysis framework
- **YARA** - Pattern matching engine

### Step 1: Understanding Shadow Volume Deletion

WannaCry ransomware deletes shadow copies to prevent file recovery using these common commands:

```cmd
vssadmin delete shadows
vssadmin delete shadows /all
wmic shadowcopy delete
wmic shadowcopy delete /all
```

> **💡 Why This Matters:** Shadow copies are Windows' backup mechanism that allows users to recover previous versions of files. By deleting them, ransomware ensures victims cannot easily recover their encrypted data.

### Step 2: Create the YARA Rule

Create `shadow_volume_deletion.yar` in the rules directory:

```yara
rule ShadowVolumeDeletion
{
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

**Rule Components:**
- **`$vssadmin_delete*`:** Detects VSS Admin commands for shadow deletion
- **`$wmic_shadow*`:** Detects WMI commands for shadow copy deletion  
- **`$cmd_args`:** Generic detection for any `-delete` argument
- **`condition`:** Triggers if any shadow deletion command is found

> **📝 Credit:** This rule was adapted from [[Fares Morcy's GitBook on SOC analysis](https://faresmorcy.gitbook.io/cybersecurity-blue-team)](https://faresbltagy.gitbook.io/footprintinglabs/soc-hackthebox-notes-and-labs/yara-and-sigma-for-soc-analysts-module/hunting-evil-with-yara-linux-edition)

### Step 3: Scan Memory with Volatility

Execute the memory analysis command:

```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/shadow_volume_deletion.yar
```

**Command Breakdown:**
- `vol.py` - Volatility framework
- `-f` - Specify memory dump file
- `yarascan` - Use YARA scanning plugin
- `-y` - Specify YARA rule file

### Step 4: Analyze the Output

**Example Output:**
```
Rule: ShadowVolumeDeletion 
Owner: Process @WanaDecryptor@ Pid 3200 
0x00420fdb 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 vssadmin.delete. 
0x00420feb 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 shadows./all./qu 
...
```

**Interpretation:**
- **`Rule: ShadowVolumeDeletion`** - YARA rule that triggered
- **`Owner: Process @WanaDecryptor@`** - The malicious process performing shadow volume deletion
- **`Pid 3200`** - Process ID of the malicious process
- **Hex dump** - Shows the actual command: `vssadmin delete shadows /all /qu`

### Step 5: Understanding the Attack Pattern

**WannaCry's Shadow Deletion Strategy:**
1. **Execute shadow deletion commands** to prevent file recovery
2. **Use `/all` flag** to delete all shadow copies
3. **Use `/quiet` flag** to suppress user prompts
4. **Run from renamed executable** (`@WanaDecryptor@`) to evade basic detection

### 🔍 Advanced Analysis Tips

**Additional Volatility Commands:**
```bash
# Get process information
vol.py -f compromised_system.raw pslist | grep -i wana

# Check process tree
vol.py -f compromised_system.raw pstree | grep -i wana

# Extract process executable
vol.py -f compromised_system.raw procdump -p 3200 --dump-dir ./output/
```

### 🎉 Answer
**Process Name:** `@WanaDecryptor@`

### 📊 Lab Summary

| Component | Value |
|-----------|-------|
| **Malicious Process** | `@WanaDecryptor@` |
| **Process ID** | `3200` |
| **Detection Method** | YARA rule + Volatility yarascan |
| **Command Detected** | `vssadmin delete shadows /all` |
| **Threat Type** | WannaCry Ransomware |

---

## ⚠️ Disclaimer
- These labs focus on configuring YARA rules for educational purposes
- Testing against actual malware should be done in controlled environments
- Always ensure rules are properly tested before deployment in production
