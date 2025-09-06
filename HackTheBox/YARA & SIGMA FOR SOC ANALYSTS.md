# Lab: Developing and Hunting with YARA

---

## Lab 1: Developing YARA Rules

### Objective
- Perform string analysis on a suspicious DLL (`DirectX.dll`).  
- Study and modify an existing YARA rule (`apt_apt17_mal_sep17_1.yar`) to correctly detect the malware sample.  
- Identify the correct DLL string to replace `X.dll`.

### Environment
- **Target:** `/home/htb-student/Samples/YARASigma/DirectX.dll`  
- **YARA Rules Directory:** `/home/htb-student/Rules/yara/`  
- **Rule File:** `apt_apt17_mal_sep17_1.yar`  
- **Tools Used:**  
  - `strings` (extract printable strings)  
  - `grep` (filter `.dll` occurrences)  
  - `yara` (test rules)  

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
Note: $s4 is a placeholder and must be replaced with the correct DLL name.
Step 2: Extract DLL Strings from the Sample
strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep -E '\.dll$'
KERNEL32.dll
ADVAPI32.dll
MSVCRT.dll
kernel32.dll
\msvcrt.dll
\spool\prtprocs\w32x86\localspl.dll
\spool\prtprocs\x64\localspl.dll
\TSMSISrv.dll

Summary
Extracted all DLL strings from DirectX.dll.
Verified which DLLs were already in the YARA rule (localspl.dll, msvcrt.dll).
Identified TSMSISrv.dll as the missing DLL that should replace X.dll.

Answer
TSMSISrv.dll

Lab 2: Hunting Evil with YARA (Windows Edition)
Objective
Study and configure a YARA rule (shell_detector.yar) to detect specific strings in process memory.
Detect:
Hardcoded domain in memory.
The message "Sandbox detected" in memory.
YARA Rule Location
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


Updating the $sandbox Variable
Purpose: Detect "Sandbox detected" in process memory.
Convert the string to hexadecimal for YARA:
"Sandbox detected".encode('utf-8').hex()
# Output: 53616e64626f78206465746563746564
Update the rule
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

Explanation
$domain: Hex pattern for iuqerfsodp9ifjaposdfjhgosurijfaewrrwergwea.com.
$sandbox: Hex pattern for "Sandbox detected".
condition: Requires both patterns in memory for a match.

Answer
53616e64626f78206465746563746564
