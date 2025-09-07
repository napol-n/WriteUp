# YARA & SIGMA FOR SOC ANALYSTS&#x20;

## Lab: Developing YARA Rules

Perform string analysis on the "DirectX.dll" sample that resides in the "/home/htb-student/Samples/YARASigma" directory of this section's target. Then, study the "apt\_apt17\_mal\_sep17\_1.yar" YARA rule that resides in the "/home/htb-student/Rules/yara" directory and replace "X.dll" with the correct DLL name to ensure the rule will identify "DirectX.dll". Enter the correct DLL name as your answer. Answer format: \_.dll

### Objective

* Perform **string analysis** on a suspicious DLL (`DirectX.dll`).
* Study and modify an existing YARA rule (`apt_apt17_mal_sep17_1.yar`) so that it can correctly detect the malware sample.
* Identify the correct DLL string to replace `X.dll`.

***

### Environment

* **Target:** `/home/htb-student/Samples/YARASigma/DirectX.dll`
* **YARA Rules Directory:** `/home/htb-student/Rules/yara/`
* **Rule File:** `apt_apt17_mal_sep17_1.yar`
* **Tools Used:**
  * `strings` (extract printable strings)
  * `grep` (filter `.dll` occurrences)
  * `yara` (test rules)

***

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

Note: `$s4` is a placeholder to be replaced with the correct DLL string.

### Step 2: Extract DLL Strings from the Sample

```bash
strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep -E '\.dll$'
```

## Output

KERNEL32.dll\
ADVAPI32.dll\
MSVCRT.dll\
kernel32.dll\
\msvcrt.dll\
\spool\prtprocs\w32x86\localspl.dll\
\spool\prtprocs\x64\localspl.dll\
\TSMSISrv.dll

### Summary

1. Extracted all DLL strings from `DirectX.dll`.
2. Verified which DLLs were already in the YARA rule.
3. Identified `TSMSISrv.dll` as the missing DLL.



**Observation**

* The sample references multiple DLLs.
* `localspl.dll` and `msvcrt.dll` are already covered in the YARA rule.
* The missing DLL to match is **`TSMSISrv.dll`**.

### 🔗 References

* YARA Documentation
* [Florian Roth’s Signature Base](https://github.com/Neo23x0/signature-base)
* APT17 Malware Reports

## Answer

TSMSISrv.dll



## Lab: Hunting Evil with YARA (Windows Edition)

Study the "C:\Rules\yara\shell\_detector.yar" YARA rule that aims to detect "C:\Samples\MalwareAnalysis\shell.exe" inside process memory. Then, specify the appropriate hex values inside the "$sandbox" variable to ensure that the "Sandbox detected" message will also be detected. Enter the correct hex values as your answer. Answer format: Remove any spaces

### Objective

The objective of this lab is to study and configure a YARA rule (`shell_detector.yar`) to detect specific strings in process memory. The rule focuses on two items:

1. Detecting a hardcoded domain in memory.
2. Detecting the message `"Sandbox detected"` in memory.

### The YARA Rule

The rule file is located at:

```
C:\Rules\yara\shell_detector.yar
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

### Updating the `$sandbox` Variable

The `$sandbox` variable is meant to detect the string `"Sandbox detected"` in process memory. To convert this string into a hexadecimal pattern suitable for YARA:

1. Open a Python terminal.
2. Encode the string into UTF-8 hexadecimal:

"Sandbox detected".encode('utf-8').hex()

Output : 53616e64626f78206465746563746564

Remove spaces and use it as the value for `$sandbox`

```
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

**Explanation of the Rule Components:**

* `$domain`: Hex pattern for the hardcoded domain `iuqerfsodp9ifjaposdfjhgosurijfaewrrwergwea.com`
* `$sandbox`: Hex pattern for the string `"Sandbox detected"`
* `condition`: Requires **both patterns** to be present in memory for a match.

***

### Notes

* Ensure that your YARA environment has access to this rule.
* This rule is designed for **process memory scanning**, not just static files.

#### Answer

53616e64626f78206465746563746564



## Lab: Hunting Evil with YARA (Linux Edition)

Study the following resource https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html to learn how WannaCry performs shadow volume deletion. Then, use yarascan when analyzing "/home/htb-student/MemoryDumps/compromised\_system.raw" to identify the process responsible for deleting shadows. Enter the name of the process as your answer.

### Objective

The goal of this lab is to identify the process responsible for deleting shadow volumes on a compromised Windows system. This involves:

* Understanding how WannaCry ransomware performs shadow volume deletion.
* Using the `ShadowVolumeDeletion` YARA rule to detect shadow deletion commands.
* Scanning a memory dump with Volatility to identify the malicious process.

***

### Resources

* Memory dump: `/home/htb-student/MemoryDumps/compromised_system.raw`
* YARA rules directory: `/home/htb-student/Rules/yara/`
* Reference article: [Illuminating Volume Shadow Deletion](https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html)

***

### Step 1: Understand Shadow Volume Deletion

WannaCry ransomware deletes shadow copies to prevent file recovery. Common commands include:

* `vssadmin delete shadows`
* `vssadmin delete shadows /all`
* `wmic shadowcopy delete`
* `wmic shadowcopy delete /all`

Reference: [VMware Threat Report](https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html)

***

### Step 2: YARA Rule (`ShadowVolumeDeletion`)

Create a YARA rule file named `shadow_volume_deletion.yar`:

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

* **Credit:** This rule was adapted from Fares Morcy's GitBook on SOC analysis: [Hunting Evil with YARA (Linux Edition)](https://faresbltagy.gitbook.io/footprintinglabs/soc-hackthebox-notes-and-labs/yara-and-sigma-for-soc-analysts-module/hunting-evil-with-yara-linux-edition)
* This rule detects typical shadow volume deletion commands.
* `$cmd_args` adds a generic detection for any `-delete` argument.

### Step 3: Scan Memory with Volatility

Run the following command to scan the memory dump:

vol.py -f /home/htb-student/MemoryDumps/compromised\_system.raw yarascan -y /home/htb-student/Rules/yara/shadow\_volume\_deletion.yar

### Step 4: Analyze Output

Example output:

Rule: ShadowVolumeDeletion\
Owner: Process @WanaDecryptor@ Pid 3200\
0x00420fdb 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 vssadmin.delete.\
0x00420feb 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 shadows./all./qu\
...

**Interpretation:**

* `Owner: Process @WanaDecryptor@` → the malicious process performing shadow volume deletion.
* `Pid 3200` → process ID of `WanaDecryptor`.

### Step 5: Conclusion

* WannaCry ransomware deletes shadow volumes to prevent file recovery.
* Using Volatility with the `ShadowVolumeDeletion` YARA rule allows us to detect the process responsible.

#### Answer

@WanaDecryptor@



## Lab: Developing Sigma Rules

Using sigmac translate the "C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win\_defender\_threat.yml" Sigma rule into the equivalent PowerShell command. Then, execute the PowerShell command against "C:\Events\YARASigma\lab\_events\_4.evtx" and enter the malicious driver as your answer. Answer format: \_.sys

### Objective

In this lab, we will use **Sigma rules** to detect malicious activity from Windows Event Logs. Specifically, we will translate a Sigma rule into a PowerShell query using `sigmac` and then run it against provided `.evtx` logs to identify the malicious driver.

***

### Environment

* **Target VM (RDP):**
  * Host: `10.129.228.137`
  * User: `htb-student`
  * Password: `HTB_@cademy_stdnt!`
* **Tools:**
  * `sigmac` (Sigma Converter)
  * PowerShell
  * Event logs: `C:\Events\YARASigma\lab_events_4.evtx`
  * Sigma rule: `C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml`

***

### Step 1: RDP into the target machine

```bash
# From your local machine
rdesktop 10.129.228.137 -u htb-student -p HTB_@cademy_stdnt!
```

Use `sigmac` to convert the Sigma rule into a PowerShell query.

```bash
python sigmac -t powershell 'C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml' > translated.ps1
```

```bash
type translated.ps1
Get-WinEvent | where {($.ID -eq "1006" -or $.ID -eq "1116" -or $.ID -eq "1015" -or $.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

```bash
Get-WinEvent -Path "C:\Events\YARASigma\lab_events_4.evtx" | where {($.ID -eq "1006" -or $.ID -eq "1116" -or $.ID -eq "1015" -or $.ID -eq "1117")} | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

```bash
TimeCreated : 12/11/2020 4:28:01 AM
Id : 1116
RecordId : 171
ProcessId : 4172
MachineName : WIN10-client01.offsec.lan
Message : Microsoft Defender Antivirus has detected malware or other potentially
unwanted software.
...
Detection Source: file:_C:\Users\admmig\Documents\mimidrv.sys
```

Answer

mimidrv.sys



## Lab: Hunting Evil with Sigma (Chainsaw Edition)

Use Chainsaw with the "C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell\_script\posh\_ps\_win\_defender\_exclusions\_added.yml" Sigma rule to hunt for suspicious Defender exclusions inside "C:\Events\YARASigma\lab\_events\_5.evtx". Enter the excluded directory as your answer.

### Objective

In this lab, we will use **Chainsaw** and a Sigma rule to hunt for suspicious **Windows Defender exclusions** in an EVTX event log. The goal is to identify any directories or files that were added to Defender exclusions using PowerShell.

***

### Tools Required

* **Chainsaw**: A tool for Sigma rule hunting on forensic artifacts.
* **Sigma Rules**: Specifically `posh_ps_win_defender_exclusions_added.yml`.
* **EVTX Event Logs**: `lab_events_5.evtx` containing PowerShell events.
* Windows machine with PowerShell access.

***

### Lab Environment

* Chainsaw is installed at `C:\Tools\chainsaw\`
* Event log file is located at `C:\Events\YARASigma\lab_events_5.evtx`
* Sigma rule location: `C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml`

***

### Steps

#### 1. Verify Chainsaw Installation

Open PowerShell or Command Prompt and check Chainsaw version:

```powershell
C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe --version
```

2. Run Chainsaw Hunt
3.  ```powershell
    C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml ` --mapping .\mappings\sigma-event-logs-all-new.yml
    ```



    **Explanation of Parameters:**

    * `hunt`: Runs Chainsaw hunting mode.
    * `C:\Events\YARASigma\lab_events_5.evtx`: The event log file to analyze.
    * `-s <sigma_rule_path>`: Path to the Sigma rule for detecting suspicious Defender exclusions.
    * `--mapping <mapping_file>`: Event log mapping file to interpret Windows Event IDs correctly.

#### 3. Analyze Output

| timestamp           | detections                        | Event ID | Event Data                                                           |
| ------------------- | --------------------------------- | -------- | -------------------------------------------------------------------- |
| 2021-10-06 11:14:56 | Windows Defender Exclusions Added | 4104     | ScriptBlockText: Set-MpPreference -ExclusionPath c:\document\virus\\ |
| 2021-10-06 11:15:06 | Windows Defender Exclusions Added | 4104     | ScriptBlockText: Set-MpPreference -ExclusionExtension '.exe'         |

Key details to notice:

* `Event ID 4104` indicates a PowerShell script executed.
* `ScriptBlockText` shows the exact PowerShell command that modified Defender exclusions.
* Set-MpPreference -ExclusionPath c:\document\virus\\

### Summary

* We used **Chainsaw** with a **Sigma rule** to detect suspicious Windows Defender exclusions.
* Identified **`c:\document\virus\`** as a directory excluded from Defender scans.
* This technique is useful for **detecting stealthy malware** attempting to evade antivirus monitoring via PowerShell.

#### Answer

c:\document\virus\\



## Lab: Hunting Evil with Sigma (Splunk Edition)

Using sigmac translate the "C:\Rules\sigma\file\_event\_win\_app\_dropping\_archive.yml" Sigma rule into the equivalent Splunk search. Then, navigate to http://\[Target IP]:8000, open the "Search & Reporting" application, and submit the Splunk search sigmac provided. Enter the TargetFilename value of the returned event as your answer.

### Objective

In this lab, we will use **Sigma rules** to hunt for suspicious archive file drops from Windows applications like Microsoft Office. We will translate a Sigma rule into a **Splunk search** using `sigmac` and find the `TargetFilename` in the resulting events.

***

### Tools Required

* Windows target machine
* Sigma rules (`C:\Rules\sigma\file_event_win_app_dropping_archive.yml`)
* Sigmac (`C:\Tools\sigma-0.21\tools`)
* Splunk instance (Search & Reporting application)

***

### Step 1: Navigate to Sigmac

Open **Command Prompt** or **PowerShell** on the machine where Sigma is installed:

```powershell
cd C:\Tools\sigma-0.21\tools
```

Run the following command to convert the Sigma rule into a Splunk query

```powershell
python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml -c .\config\splunk-windows.yml
```

```powershell
( Image="\winword.exe" OR Image="\excel.exe" OR Image="\powerpnt.exe" OR Image="\msaccess.exe" OR Image="\mspub.exe" OR Image="\eqnedt32.exe" OR Image="\visio.exe" OR Image="\wordpad.exe" OR Image="\wordview.exe" OR Image="\certutil.exe" OR Image="\certoc.exe" OR Image="\CertReq.exe" OR Image="\DesktopImgDownldr.exe" OR Image="\esentutl.exe" OR Image="\finger.exe" OR Image="\notepad.exe" OR Image="\AcroRd32.exe" OR Image="\RdrCEF.exe" OR Image="\mshta.exe" OR Image="\hh.exe" OR Image="\SharpHound.exe" ) AND ( TargetFilename=".zip" OR TargetFilename=".rar" OR TargetFilename=".7z" OR TargetFilename=".diagcab" OR TargetFilename=".appx" )
```

### Step 2: Run the Splunk Search

* Copy the query from Step 2.
* Paste it into the search bar in Splunk.
* Click **Search**.

### Step 3: Find the TargetFilename

In the search results, locate the **`TargetFilename`** column

```powershell
C:\Users\waldo\Downloads\20221108112718_BloodHound.zip
```

#### Answer

C:\Users\waldo\Downloads\20221108112718\_BloodHound.zip



## Skills Assessment

In this skills assessment section, we'll practice YARA rule development and using Sigma rules to hunt for threats within event logs.

For the initial question, you'll be tasked with developing a YARA rule aimed at identifying the malicious `Seatbelt.exe` file, commonly used by attackers for maintaining operational security.

In the subsequent question, you'll be using a Sigma rule to identify instances of shadow volume deletion - a technique often utilized by ransomware groups.



## Q1&#x20;

The "C:\Rules\yara\seatbelt.yar" YARA rule aims to detect instances of the "Seatbelt.exe" .NET assembly on disk. Analyze both "C:\Rules\yara\seatbelt.yar" and "C:\Samples\YARASigma\Seatbelt.exe" and specify the appropriate string inside the "$class2" variable so that the rule successfully identifies "C:\Samples\YARASigma\Seatbelt.exe". Answer format: L\_\_\_\_\_\_\_\_r

### Objective

In this lab, we aim to create and use a **YARA rule** to detect the `.NET assembly` file `Seatbelt.exe`, commonly used by attackers to maintain operational security. We will analyze the YARA rule, inspect the target file, and correctly populate the `$class2` variable to ensure the rule matches the sample.

***

###

* Sample file: `C:\Samples\YARASigma\Seatbelt.exe`
* YARA rule: `C:\Rules\yara\seatbelt.yar`

***

### Step 1: Access the Target System

1. Download the VPN connection file from the lab portal.
2. Connect to the lab VPN.
3. RDP to the target system:

```powershell
type C:\Rules\yara\seatbelt.yar
```

#### Strings Section

Defines patterns YARA will search for inside the file:

```yara
$class1 = "WMIUtil"
$class2 = ""           // <- Needs proper string
$class3 = "SecurityUtil"
$class4 = "MiscUtil"
$dotnetMagic = "BSJB" ascii
```

### Step 3: Inspect Seatbelt.exe

Use `strings` to find class names

```powershell
strings Seatbelt.exe | findstr /R "^L.*r$"
```

```powershell
LocalAddr
LsaFreeReturnBuffer
LsaWrapper ** 10 letter format **
LAPSFormatter
LolbasFormatter
LocalGroupMembershipTextFormatter
LogonSessionsTextFormatter
LocalSecurityAuthorityFormatter
LocalComputer
LsaNtStatusToWinError
LogMeIn Reporter
```

### Step 5: Test the YARA Rule

Run YARA against the sample file

```powershell
yara64.exe -s C:\Rules\yara\seatbelt.yar C:\Samples\YARASigma\Seatbelt.exe -r 2>null
```

#### Answer

LsaWrapper



## Q2

Use Chainsaw with the "C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell\_script\posh\_ps\_susp\_win32\_shadowcopy.yml" Sigma rule to hunt for shadow volume deletion inside "C:\Events\YARASigma\lab\_events\_6.evtx". Enter the identified ScriptBlock ID as your answer.

### Objective

In this lab, we will use **Chainsaw** and a **Sigma rule** to hunt for PowerShell scripts that delete **Volume Shadow Copies**. This technique is commonly employed by ransomware such as Sodinokibi/REvil.

We aim to identify the **ScriptBlock ID** of the event that matches the detection rule.

***

### Tools & Files

* **Chainsaw executable**: `C:\Tools\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe`
* **Sigma rule**: `C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml`
* **Event log file**: `C:\Events\YARASigma\lab_events_6.evtx`
* **Mapping file**: `C:\Tools\chainsaw\mappings\sigma-event-logs-all.yml`

***

### Step 1: Understand the Sigma Rule

Open the Sigma rule file:

```powershell
type C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml
```

#### Key Details

* **Title**: Delete Volume Shadow Copies via WMI with PowerShell
* **ID**: `e17121b4-ef2a-4418-8a59-12fb1631fa9e`
* **Description**: Detects PowerShell scripts that delete Windows Volume Shadow Copies using `Get-WmiObject`.
* **Detection Condition**

```powershell
ScriptBlockText|contains|all:
'Get-WmiObject'
'Win32_Shadowcopy'
'Delete()'
```

* This captures PowerShell ScriptBlocks that contain **all three strings**.
* **Requirement**: Script Block Logging must be enabled.

### Step 2: Hunting with Chainsaw

Open **PowerShell** or **Command Prompt**, navigate to the Chainsaw folder

```powershell
cd C:\Tools\chainsaw
```

```powershell
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml ` --mapping .\mappings\sigma-event-logs-all.yml
```

Parameters

* `hunt` → search events in the log according to the Sigma rule.
* `-s` → path to the Sigma detection rule.
* `--mapping` → mapping file to normalize log fields for Sigma.

### Step 3: Process Flow

1. **Chainsaw** loads the Sigma rule.
2. Chainsaw parses the event log (`lab_events_6.evtx`).
3. Each **PowerShell ScriptBlock** in the log is checked.
4. Chainsaw selects ScriptBlocks containing **all required strings**:
   * `Get-WmiObject`
   * `Win32_Shadowcopy`
   * `Delete()`
5. Matching events are displayed with their **ScriptBlock ID**.

### Step 4: Review the Output

Example output from Chainsaw

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FlAH86GsktmT5zaejiQBn%2FScreenshot%202025-09-07%20at%2011.43.21%E2%80%AFPM.png?alt=media&#x26;token=3020c2c9-bf51-4835-adba-eaf0f555172d" alt=""><figcaption></figcaption></figure>

```powershell
Timestamp: 2021-12-19 15:13:49 Title: Delete Volume Shadow Copies via WMI with PowerShell ScriptBlock ID: faaeba08-01f0-4a32-ba48-bd65b24afd28 ScriptBlock Text: Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() } Event ID (PowerShell): 4104 Computer: FS03.offsec.lan
```

* **ScriptBlock ID** is the unique identifier for the detected PowerShell ScriptBlock.
* This is the value required as the answer for the lab.

### Notes

* Ensure **Script Block Logging** is enabled in Windows to capture these events.
* This lab demonstrates **Sigma-based hunting** and how Chainsaw maps logs to detection rules.
* You can extend this method to detect other suspicious PowerShell activity by modifying the Sigma rule or using different event logs.

#### Answer

faaeba08-01f0-4a32-ba48-bd65b24afd28
