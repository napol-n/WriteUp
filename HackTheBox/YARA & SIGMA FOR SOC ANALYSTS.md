# Lab: YARA String Analysis & Rule Customization

#Perform string analysis on the "DirectX.dll" sample that resides in the "/home/htb-student/Samples/YARASigma" directory of this section's target. Then, study the "apt_apt17_mal_sep17_1.yar" YARA rule that resides in the "/home/htb-student/Rules/yara" directory and replace "X.dll" with the correct DLL name to ensure the rule will identify "DirectX.dll". Enter the correct DLL name as your answer. Answer format: _.dll

## Objective
- Perform string analysis on a suspicious DLL (`DirectX.dll`).
- Study and modify an existing YARA rule (`apt_apt17_mal_sep17_1.yar`) so that it can correctly detect the malware sample.
- Identify the correct DLL string to replace `X.dll`.

---

## Environment
- **Target:** `/home/htb-student/Samples/YARASigma/DirectX.dll`  
- **YARA Rules Directory:** `/home/htb-student/Rules/yara/`  
- **Rule File:** `apt_apt17_mal_sep17_1.yar`  
- **Tools Used:**  
  - `strings` (extract printable strings)  
  - `grep` (filter `.dll` occurrences)  
  - `yara` (test rules)  

---

## Step 1: Review the Original YARA Rule
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

Output
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
Observation
The sample references multiple DLLs.
localspl.dll and msvcrt.dll are already covered in the rule.
The missing DLL is TSMSISrv.dll.

Answer
TSMSISrv.dll
