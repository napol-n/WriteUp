# Lab: Developing and Hunting with YARA

This repository contains comprehensive lab exercises for developing YARA rules and conducting malware hunting operations using YARA signatures.

## Table of Contents
- [Lab 1: Developing YARA Rules](#lab-1-developing-yara-rules)
- [Lab 2: Hunting Evil with YARA (Windows Edition)](#lab-2-hunting-evil-with-yara-windows-edition)
- [Tools and Requirements](#tools-and-requirements)
- [Additional Resources](#additional-resources)

---

## Lab 1: Developing YARA Rules

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

## ⚠️ Disclaimer
- These labs focus on configuring YARA rules for educational purposes
- Testing against actual malware should be done in controlled environments
- Always ensure rules are properly tested before deployment in production
