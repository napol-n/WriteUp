# Nonyx

#### Scenario Exorcise Black Energy 2 from Shadowbrook’s digital infrastructure by reverse-engineering the malware’s code. You must dismantle its hooks, identify its payload, and stop its command-and-control mechanisms to restore peace to the town’s network before the Haunted Festival reaches its darkest hour.

### Tools Required

* Volatility Framework 2
* Memory dump file
* Basic command line knowledge
* Text analysis tools (grep, egrep)

### Investigation Methodology

This lab focuses on analyzing a memory dump infected with BlackEnergy 2 malware using Volatility Framework. We'll identify injected code, analyze memory sections, and examine system hooks.

***

### Question 1: Identifying Injected Code

**Task**: Which process most likely contains injected code, providing its name, PID, and memory address?

#### Step-by-Step Analysis

1. **Run Volatility Malfind Plugin**

```bash
volatility -f memory_dump.mem --profile=Win7SP1x86 malfind
```

2. **Analyze Output for Suspicious Processes** The malfind plugin identifies processes with:

* Executable memory regions that are not backed by files
* Unusual memory permissions (RWX)
* Potential code injection indicators

3. **Examine Process Details** Look for processes with suspicious memory allocations, particularly system processes like `svchost.exe` which are commonly targeted for injection.

**Analysis Results:**

* **Process Name**: `svchost.exe`
* **PID**: `856`
* **Memory Address**: `0xc30000`

**Answer**: svchost.exe, 856, 0xc30000

#### Why This Process?

* `svchost.exe` is a legitimate Windows service host process
* PID 856 shows abnormal memory patterns
* Memory address 0xc30000 contains executable code not backed by a legitimate file

***

### Question 2: Memory Dump File Identification

**Task**: What dump file in the malfind output directory corresponds to the memory address identified for code injection?

#### Analysis Process

1. **Understanding Malfind Output Structure** Volatility's malfind plugin generates dump files using this naming convention:

```
process.[process_object_address].[virtual_address].dmp
```

2. **Correlate with Previous Findings** From Q1, we identified:

* Process: svchost.exe (PID 856)
* Memory Address: 0xc30000

3. **Locate Corresponding Dump File** The dump file follows the pattern and corresponds to our identified injection point.

**Answer**: `process.0x80ff88d8.0xc30000.dmp`

#### File Structure Explanation

* `process.`: Prefix indicating process memory dump
* `0x80ff88d8`: Process object address in kernel memory
* `0xc30000`: Virtual memory address where injection was detected
* `.dmp`: Binary dump file extension

***

### Question 3: Referenced Filename Analysis

**Task**: Which full filename path is referenced in the strings output of the memory section identified by malfind as containing a portable executable (PE32/MZ header)?

#### Investigation Steps

1. **Extract Strings from Memory Dump**

```bash
strings process.0x80ff88d8.0xc30000.dmp
```

2. **Analyze PE Header Indicators** Look for:

* MZ header signatures
* PE32 indicators
* File path references
* System file paths

3. **Filter for System Driver References** Focus on paths that indicate:

* System32 directory structure
* Driver files (.sys extension)
* Kernel-level components

**Analysis Result**: `C:\WINDOWS\system32\drivers\str.sys`

**Answer** C:\WINDOWS\system32\drivers\str.sys

#### Significance

* This path indicates malware attempting to mimic or reference legitimate system drivers
* The `.sys` extension suggests kernel-level access
* Location in `system32\drivers` indicates privilege escalation attempts

***

### Question 4: SSDT Hook Analysis

**Task**: How many functions were hooked and by which module after running the ssdt plugin and filtering out legitimate SSDT entries?

#### Methodology

1. **Run SSDT Plugin**

```bash
volatility -f memory_dump.mem --profile=Win7SP1x86 ssdt
```

2. **Filter Legitimate Entries**

```bash
volatility -f memory_dump.mem --profile=Win7SP1x86 ssdt | egrep -v '(ntoskrnl|win32k)'
```

3. **Count Hooked Functions** After filtering out legitimate Windows kernel modules (ntoskrnl and win32k), count remaining entries.

**Results:**

* **Hooked Functions**: `14`
* **Hooking Module**: `00004A2A`

**Answer** 14, 00004A2A

#### SSDT Hooking Explained

* **SSDT**: System Service Descriptor Table
* **Hooking**: Redirecting system calls to malicious code
* **Legitimate modules**: ntoskrnl.exe (NT kernel), win32k.sys (Win32 subsystem)
* **Malicious hooks**: Any entries not pointing to these legitimate modules

***

### Question 5: Module Base Address Identification

**Task**: Using the modules (or modscan) plugin to identify the hooking driver from the ssdt output, what is the base address for the module found in Q4?

#### Investigation Process

1. **Run Modules Plugin**

```bash
volatility -f memory_dump.mem --profile=Win7SP1x86 modules
```

or

```bash
volatility -f memory_dump.mem --profile=Win7SP1x86 modscan
```

2. **Cross-Reference with SSDT Results** Look for the module identifier `00004A2A` from Q4 in the modules output.
3. **Extract Base Address** Find the corresponding base address where this malicious module is loaded.

**Answer**: `0xff0d1000`

#### Module Analysis Context

* Base addresses indicate where modules are loaded in kernel memory
* Malicious drivers often load at non-standard addresses
* This address represents the starting point of the malicious code in memory

***

### Question 6: Malicious Driver Hash Analysis

**Task**: What is the hash for the malicious driver from the virtual memory image?

#### Hash Extraction Process

1. **Dump the Malicious Driver**

```bash
volatility -f memory_dump.mem --profile=Win7SP1x86 moddump -D output_dir -b 0xff0d1000
```

2. **Calculate SHA256 Hash**

```bash
sha256sum driver.0xff0d1000.sys
```

3. **Verify Hash Integrity** Cross-reference with known BlackEnergy 2 samples if available.

**Answer**: `12b0407d9298e1a7154f5196db4a716052ca3acc70becf2d5489efd35f6c6ec8`

#### Hash Analysis Significance

* SHA256 provides unique fingerprint for malware identification
* Can be used for threat intelligence and IOC creation
* Enables detection rule creation for security tools

***

### Lab Summary

#### Key Findings

1. **Injection Target**: BlackEnergy 2 injected code into svchost.exe (PID 856)
2. **Memory Location**: Code injection at address 0xc30000
3. **File Reference**: Malware references system driver path `C:\WINDOWS\system32\drivers\str.sys`
4. **System Hooks**: 14 functions hooked in the SSDT
5. **Driver Location**: Malicious driver loaded at base address 0xff0d1000
6. **Malware Hash**: SHA256 signature identified for threat intelligence

#### Mitigation Strategies

* Implement memory protection mechanisms
* Monitor SSDT modifications
* Deploy endpoint detection and response (EDR) solutions
* Regular memory forensics analysis
* Kernel-level security monitoring

#### Tools Mastered

* Volatility Framework memory analysis
* SSDT hook detection
* Process injection identification
* Malware hash analysis
* Memory dump forensics

***

### Additional Resources

#### Further Reading

* Volatility Framework Documentation
* BlackEnergy Malware Family Analysis
* Windows Kernel Security Architecture
* Memory Forensics Best Practices

#### Practice Recommendations

* Analyze additional malware families
* Practice with different Windows profiles
* Explore advanced Volatility plugins
* Study rootkit detection techniques

<https://blueteamlabs.online/achievement/share/122610/243>

***

*This lab guide is designed for educational purposes within controlled environments. Always follow responsible disclosure and ethical guidelines when working with malware samples.*
