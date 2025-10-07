# NTFS Forensics

## NTFS Forensics

As a digital forensics analyst with over a decade of experience, you are the go-to person in your organization for Windows disk forensics. Recently, an alert was triggered on a critical server used by administrators as a jump server. This server is frequently accessed for credential management and other sensitive operations, making it a high-value target. It has now been compromised. You are provided with only the Master File Table (MFT) of the endpoint. Your task is to uncover the actions taken by the threat actors on the endpoint.

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\mft.zip

## Q1 Identify the malicious downloaded file. What is the file name?

### Step-by-Step Analysis

#### 1. Load MFT

* Use `MFTExplorer.exe` to open the `$MFT` of the target machine.
* Wait for parsing → you will get a view similar to Windows Explorer.

#### 2. Go to the Downloads folder

**Navigate to:**

```
C:\Users\LetsDefend\Downloads
```

Found 2 suspicious files:

* `scanner98.zip`
* `x.ps1`

#### 3. Inspect the first file `scanner98.zip`

* Extension `.zip` → commonly used as a container for payloads.
* Created timestamp is close to the time the alert reported the compromise.
* File type: archive = initial delivery method (malware was hidden inside the zip).

#### 4. Inspect the second file `x.ps1`

* PowerShell script (`.ps1`) → typically used to execute or stage further actions after the payload is extracted.
* Not the first downloaded file, but plays a role in execution / persistence / lateral movement.

#### 5. Decide which file was the “malicious download”

* From the evidence, the initial delivery was `scanner98.zip`.
* `x.ps1` is a secondary tool the threat actor used after unzip/execute.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FIER9VZssgS3I0umJ5rsL%2FScreenshot%202025-09-30%20at%207.28.19%E2%80%AFPM.png?alt=media&#x26;token=6727e748-6a92-4d15-9671-29e1798c78e2" alt=""><figcaption></figcaption></figure>

#### &#x20;Answer

**Malicious Downloaded File:** `scanner98.zip`

## Q2 What is the source URL of the downloaded file?

### 1. Select the suspicious file

In `MFTExplorer.exe`, click the file `scanner98.zip` located at:

```
C:\Users\LetsDefend\Downloads
```

### 2. View the Data Interpreter pane

In the lower window (or the right-side panel) of MFTExplorer you will see the file's metadata.\
This pane displays Alternate Data Streams (ADS) if present.\
Look for fields named:

* `Zone.Identifier`
* `ReferrerURL`
* `HostURL`

### 3. Understand the Mark of the Web (MoTW)

MoTW stores metadata for files downloaded from the internet.\
It is saved in the file's ADS, for example:

```
scanner98.zip:Zone.Identifier:$DATA
```

Inside this stream you will find:

* `ZoneId=3` (Internet Zone)
* `ReferrerUrl` (the webpage that linked to the file)
* `HostUrl` (the true origin host of the file)

### 4. Locate the Source URL

For this task, scroll down in the Data Interpreter pane for `scanner98.zip` → you will find the `ReferrerURL` field.\
This is the source URL from which the file was downloaded.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FUdcOJ3jYDdybPy0efnpz%2FScreenshot%202025-09-30%20at%207.29.24%E2%80%AFPM.png?alt=media&#x26;token=5e0cbc26-e0d7-4bcf-b709-e73fe9c552ef" alt=""><figcaption></figcaption></figure>

### Answer (Q2)

**Source URL of the downloaded file:**\
`https://drive.usercontent.google.com/download?id=1hqL4dh5i7bzvfY-v_NmsMhCkJbZDEonO&export=download`

## Q3 What was the time of download of the malicious file?&#x20;

(**Answer Forma**t: YYYY-MM-DD HH:MM:SS)

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FVH6Tv3AmENynXFLSkjpp%2FScreenshot%202025-09-30%20at%207.33.52%E2%80%AFPM.png?alt=media&#x26;token=7b758706-8c14-41e4-bd8c-5834de2e1b3c" alt=""><figcaption></figcaption></figure>

#### ANSWER. 2024-04-22 04:00:43

## Q4 A powershell script was created on disk by the malicious file. What is the full path of this script on the system?&#x20;

(**Answer Format**: C:\x\x\x\file.extension)

* **Malicious Downloaded File:** `scanner98.zip`
* **Source URL:** `https://drive.usercontent.google.com/download?id=1hqL4dh5i7bzvfY-v_NmsMhCkJbZDEonO&export=download`
* **Time of Download:** `2024-04-22 04:00:43`
* **Full Path of PowerShell Script:** `C:\Users\LetsDefend\Downloads\x.ps1`

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FDFTO2EV7uB95nezVN7bP%2FScreenshot%202025-09-30%20at%207.38.20%E2%80%AFPM.png?alt=media&#x26;token=490bbff8-b267-46e6-b6ac-b0248d0bb010" alt=""><figcaption></figcaption></figure>

**ANSWER** C:\Users\LetsDefend\Downloads\x.ps1

## What is the file size of the script in bytes?

* Open `MFTExplorer.exe` and select the file `x.ps1`.

### 1. Select the File

Determining the File Size of `x.ps1`

### 2. Navigate to the Overview Section

* Go to the **Overview** panel at the bottom right.
* Review the metadata and attributes to locate the `DATA` attribute.
* Focus on the **Content size** field toward the bottom of the window.

### 4. Convert Hexadecimal to Decimal

* Identify the **Hexadecimal** value of the Content size attribute.
* Convert it to **Decimal** to match the answer format.

<div><figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F1YNMynUzdQ5zrOA6Mu4l%2FScreenshot%202025-09-30%20at%207.44.30%E2%80%AFPM.png?alt=media&#x26;token=534223d4-a90f-45b0-9088-a793c78e7d8d" alt=""><figcaption></figcaption></figure> <figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FYFjAVKnSrDKe3TxCPiIf%2FScreenshot%202025-09-30%20at%207.46.40%E2%80%AFPM.png?alt=media&#x26;token=784962ac-0ac2-4514-b920-5eeeaeb3e9b2" alt=""><figcaption></figcaption></figure></div>

#### ANSWER 152

## Q6 Recover the file contents of this script. What is the URL it reaches out to?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FmwuNZGqXQsV7k6942K4T%2FScreenshot%202025-09-30%20at%207.51.24%E2%80%AFPM.png?alt=media&#x26;token=e25317e4-fa0c-4ba7-b00e-4c8f8e0e8e91" alt=""><figcaption></figcaption></figure>

#### ANSWER [https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Keylogger.ps1 ](https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Keylogger.ps1)

## Q7 Based on the content you recovered, what MITRE Technique is observed? Answer the subtechnique id.

* **Malicious file name:** `scanner98.zip`
* **Source URL (ReferrerURL):** `http://microsoft.com/scanner98.zip`
* **Download time:** value in **SI\_Created On** for `scanner98.zip` (record exact timestamp from MFTExplorer)
* **MITRE subtechnique (observed):** `T1056.001` (Keylogging) — also `T1059.001` for PowerShell usage

ANSWER `T1059.001`

## Q8 Which powershell cmdlet was used to execute the code in the script?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FxW6D1vsPWx72jOxNoBrx%2FScreenshot%202025-09-30%20at%207.55.32%E2%80%AFPM.png?alt=media&#x26;token=ba5e5235-f3c9-4779-9b61-52e480c2c2ab" alt=""><figcaption></figcaption></figure>

easoning: The `x.ps1` script fetched content from the GitHub URL and used **Invoke-Expression (IEX)** to execute it. IEX runs a string as a command, allowing remote PowerShell code to be executed directly.

ANSWER IEX\
\\
