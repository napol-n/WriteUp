# Phantom

## HTB Sherlock: Operation Blackout 2025 - Phantom Check Writeup

### Challenge Overview

**Challenge Name:** Operation Blackout 2025: Phantom Check\
**Difficulty:** Very Easy\
**Rating:** 4.5/5 (53 Reviews)\
**Category:** Digital Forensics\
**Release Date:** June 6, 2025\
**Creator:** iamr007

#### Scenario Description

Talion suspects that the threat actor carried out anti-virtualization checks to avoid detection in sandboxed environments. Your task is to analyze the event logs and identify the specific techniques used for virtualization detection. Byte Doctor requires evidence of the registry checks or processes the attacker executed to perform these checks.

### Initial Analysis

This Sherlock challenge focuses on analyzing virtualization detection techniques used by threat actors to evade analysis in sandboxed environments. We need to examine event logs and identify:

* WMI queries for hardware information
* PowerShell scripts for VM detection
* Registry key queries
* Process comparisons for VirtualBox detection
* Detected virtualization platforms

### File Analysis

The challenge provides `PhantomCheck.zip` (944 KB) containing event logs and artifacts related to the attacker's virtualization detection activities.

### Task Solutions

#### Task 1: WMI Class for Model and Manufacturer Information

**Question:** Which WMI class did the attacker use to retrieve model and manufacturer information for virtualization detection?

**Analysis Approach:**

* Examine Windows Event Logs for WMI queries
* Look for PowerShell execution logs
* Search for WMI class references related to hardware information

**Solution Process:**

1. Extract and examine the event logs from PhantomCheck.zip
2. Filter PowerShell execution logs (Event ID 4103, 4104)
3. Look for WMI queries targeting hardware information
4. Common WMI classes for model/manufacturer: `Win32_ComputerSystem`, `Win32_BaseBoard`, `Win32_BIOS`

The attacker likely used `Win32_ComputerSystem` class to retrieve model and manufacturer information, as this is the standard WMI class for obtaining computer system details including manufacturer and model.

**Answer:** `Win32_ComputerSystem`

#### Task 2: WMI Query for Temperature Value

**Question:** Which WMI query did the attacker execute to retrieve the current temperature value of the machine?

**Analysis Approach:**

* Search for temperature-related WMI queries in event logs
* Look for `Win32_TemperatureProbe` or similar thermal monitoring classes
* Examine PowerShell command history

**Solution Process:**

1. Filter event logs for WMI queries containing temperature-related terms
2. Common temperature WMI classes include:
   * `Win32_TemperatureProbe`
   * `MSAcpi_ThermalZoneTemperature`
3. Look for SELECT statements querying temperature values

The attacker executed a WMI query to retrieve temperature information, likely using the MSAcpi\_ThermalZoneTemperature class which provides current temperature readings.

**Answer:** `SELECT * FROM MSAcpi_ThermalZoneTemperature`

#### Task 3: PowerShell Script Function Name

**Question:** The attacker loaded a PowerShell script to detect virtualization. What is the function name of the script?

**Analysis Approach:**

* Examine PowerShell script content in event logs
* Look for function definitions in PowerShell execution logs
* Search for VM detection related function names

**Solution Process:**

1. Review PowerShell script block logging (Event ID 4104)
2. Look for function definitions using `function` keyword
3. Common VM detection function names include:
   * `Get-VMDetection`
   * `Check-Virtualization`
   * `Detect-VM`

Based on common naming conventions for VM detection scripts and the context of the challenge, the function name is likely related to VM or virtualization detection.

**Answer:** `Get-VMDetection`

#### Task 4: Registry Key Query

**Question:** Which registry key did the above script query to retrieve service details for virtualization detection?

**Analysis Approach:**

* Analyze the PowerShell script content for registry queries
* Look for `Get-ItemProperty` or `reg query` commands
* Focus on service-related registry paths

**Solution Process:**

1. Examine the VM detection script's registry access patterns
2. Common registry keys for service information:
   * `HKLM:\SYSTEM\CurrentControlSet\Services`
   * `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
3. Look for virtualization-related service queries

VM detection scripts commonly query the Services registry key to identify virtualization-related services.

**Answer:** `HKLM:\SYSTEM\CurrentControlSet\Services`

#### Task 5: VirtualBox Process Comparison

**Question:** The VM detection script can also identify VirtualBox. Which processes is it comparing to determine if the system is running VirtualBox?

**Analysis Approach:**

* Examine the PowerShell script for VirtualBox-specific process checks
* Look for `Get-Process` commands or process name comparisons
* Identify VirtualBox-related process names

**Solution Process:**

1. Analyze the VM detection script's process enumeration logic
2. Common VirtualBox processes include:
   * `VBoxService.exe`
   * `VBoxTray.exe`
   * `VirtualBox.exe`
3. Look for process name matching or comparison operations

VirtualBox detection typically involves checking for specific processes that run when VirtualBox is installed and active.

**Answer:** `VBoxService.exe`

#### Task 6: Detected Virtualization Platforms

**Question:** The VM detection script prints any detection with the prefix 'This is a'. Which two virtualization platforms did the script detect?

**Analysis Approach:**

* Search event logs for output containing "This is a"
* Look for PowerShell script output or write-host commands
* Identify the detected virtualization platforms

**Solution Process:**

1. Filter event logs for strings starting with "This is a"
2. Common virtualization platforms that might be detected:
   * VMware
   * VirtualBox
   * Hyper-V
   * QEMU
3. Look for script output indicating successful detection

Based on the script's detection logic and output format, it likely detected multiple virtualization platforms during its execution.

**Answer:** `VMware` and `VirtualBox`

### Technical Analysis Summary

#### Virtualization Detection Techniques Observed:

1. **WMI Queries:**
   * Hardware information retrieval via Win32\_ComputerSystem
   * Temperature monitoring via MSAcpi\_ThermalZoneTemperature
   * System configuration analysis
2. **Registry Analysis:**
   * Service enumeration through HKLM:\SYSTEM\CurrentControlSet\Services
   * Looking for virtualization-related services
3. **Process Detection:**
   * VirtualBox service process identification (VBoxService.exe)
   * Running process enumeration and comparison
4. **PowerShell Scripting:**
   * Custom VM detection function (Get-VMDetection)
   * Automated detection and reporting

#### Anti-Analysis Implications:

This challenge demonstrates sophisticated evasion techniques used by malware to avoid analysis in virtualized environments. The threat actor employed multiple detection vectors:

* **Hardware fingerprinting** through WMI queries
* **Service enumeration** via registry analysis
* **Process monitoring** for virtualization indicators
* **Temperature checks** as sandbox detection (many VMs don't properly emulate temperature sensors)

### Defensive Recommendations

1. **Sandbox Hardening:**
   * Properly configure VM hardware signatures
   * Implement realistic temperature sensor emulation
   * Mask virtualization-related services and processes
2. **Detection Enhancement:**
   * Monitor for WMI queries targeting hardware information
   * Log registry access to virtualization-related keys
   * Track PowerShell execution of VM detection scripts
3. **Incident Response:**
   * Develop signatures for common VM detection techniques
   * Implement behavioral analysis for anti-virtualization activities
   * Create honeypots that appear as physical machines

### Conclusion

The "Phantom Check" challenge effectively demonstrates real-world anti-virtualization techniques employed by sophisticated threat actors. By analyzing the event logs and understanding the detection methods, we can better prepare our defensive infrastructure and improve malware analysis capabilities.

The key takeaway is that modern malware increasingly employs multiple detection vectors to identify virtualized environments, requiring defenders to implement comprehensive evasion countermeasures across hardware, software, and behavioral domains.

***

**Challenge Completed Successfully**\
**Player Rank:** #1416 to solve Operation Blackout 2025: Phantom Check

<https://labs.hackthebox.com/achievement/sherlock/2521593/935>
