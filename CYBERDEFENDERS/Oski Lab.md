# Oski Lab

Category: [Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

Tactics: [Initial Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=initial-access)[Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)[Credential Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=credential-access)[Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)[Exfiltration](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=exfiltration)

Tools: [VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)[ANY.RUN](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=anyrun)

**Scenario**

The accountant at the company received an email titled "Urgent New Order" from a client late in the afternoon. When he attempted to access the attached invoice, he discovered it contained false order information. Subsequently, the SIEM solution generated an alert regarding downloading a potentially malicious file. Upon initial investigation, it was found that the PPT file might be responsible for this download. Could you please conduct a detailed examination of this file?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fg09pcd5p0fuygHKGf5oc%2FScreenshot%202025-10-04%20at%208.21.41%E2%80%AFPM.png?alt=media&#x26;token=5c716ce1-9e3b-46eb-87a4-212950699891" alt=""><figcaption></figcaption></figure>

`copy to` virustotal `a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb`

#### Q1 Determining the creation time of the malware can provide insights into its origin. What was the time of malware creation?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FRK5NtJBNt2UxQFM2TKWY%2FScreenshot%202025-10-04%20at%208.23.41%E2%80%AFPM.png?alt=media&#x26;token=2ab67efc-a16f-4257-820a-3151966fb819" alt=""><figcaption></figcaption></figure>

Answer `2022-09-28 17:40`

#### Q2 Identifying the command and control (C2) server that the malware communicates with can help trace back to the attacker. Which C2 server does the malware in the PPT file communicate with?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FoYqlscsGz2Beh6zU9zo0%2FScreenshot%202025-10-04%20at%208.28.09%E2%80%AFPM.png?alt=media&#x26;token=f66fdc55-a0d1-459b-9efb-843601fcbeba" alt=""><figcaption></figcaption></figure>

**C2 server:** **`171.22.28.221`**

**Observed URLs contacted by the malware:**

1. `http://171.22.28.221/5c06c05b7b34e8e6.php`
2. `http://171.22.28.221/9e226a84ec50246d/sqlite3.dll`

These indicate that the malware is using **HTTP-based command and control**, likely downloading additional payloads (`sqlite3.dll`) or sending exfiltrated data to the C2.

This IP should be treated as malicious and included in IOC lists for network blocks and monitoring.

Answer  <http://171.22.28.221/5c06c05b7b34e8e6.php>

#### Q3 Identifying the initial actions of the malware post-infection can provide insights into its primary objectives. What is the first library that the malware requests post-infection?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FQIHGbsHhqBhzPYcvPvQP%2FScreenshot%202025-10-04%20at%208.29.47%E2%80%AFPM.png?alt=media&#x26;token=8a17b80c-373d-447a-b286-1fd2f0b5741c" alt=""><figcaption></figcaption></figure>

**First library requested:** `sqlite3.dll` — downloaded from `http://171.22.28.221/9e226a84ec50246d/sqlite3.dll`.

**Purpose:** Likely used to access local browser databases (credentials/cookies) for exfiltration.

**Detection tips:**

* Block IP `171.22.28.221` and URLs.
* Check for `sqlite3.dll` in unexpected folders and the fake `GoogleUpdater` directories.
* Monitor processes accessing Chrome/Edge `Login Data` or `Web Data`.

**MITRE mapping:** T1555.003 (Credentials from Web Browsers), T1041 (Exfiltration over C2).

Answer `sqlite3.dll`

#### Q4 By examining the provided [Any.run report](https://any.run/report/a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb/d55e2294-5377-4a45-b393-f5a8b20f7d44), what RC4 key is used by the malware to decrypt its base64-encoded string?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FebmNPCBPIt7pxM4pu7iM%2FScreenshot%202025-10-04%20at%208.33.11%E2%80%AFPM.png?alt=media&#x26;token=ef1a8459-0270-4cf2-b6d2-69c9ba05eab8" alt=""><figcaption></figcaption></figure>

Answer `5329514621441247975720749009`

#### Q5 By examining the MITRE ATT\&CK techniques displayed in the [Any.run sandbox report](https://app.any.run/tasks/d55e2294-5377-4a45-b393-f5a8b20f7d44), identify the main MITRE technique (not sub-techniques) the malware uses to steal the user’s password.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FEtqHmGFOZmTFsqc89UUD%2FScreenshot%202025-10-04%20at%208.38.54%E2%80%AFPM.png?alt=media&#x26;token=7bcdead2-98d1-48b6-831a-6e7b22e1a43f" alt=""><figcaption></figcaption></figure>

**Main MITRE technique:** **T1555 — Credentials from Password Stores**

**Why:** the sample downloads/loads `sqlite3.dll` and accesses browser SQLite DBs (e.g., `Login Data`, `Web Data`) to harvest stored passwords/cookies.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F11uUBxm3uJuoabnOFdAF%2FScreenshot%202025-10-04%20at%208.38.13%E2%80%AFPM.png?alt=media&#x26;token=b228b512-3473-411b-b2fa-48334d295828" alt=""><figcaption></figcaption></figure>

**Quick detection / response (short):**

* Alert on unexpected `sqlite3.dll` loads or DLLs in non‑standard paths.
* Hunt for processes reading `%LOCALAPPDATA%\Google\Chrome\User Data\**\Login Data`.
* Reset affected credentials and enable MFA; block IP `171.22.28.221`.
* <https://attack.mitre.org/techniques/T1555/>

Answer `T1555`

#### Q6 By examining the child processes displayed in the [Any.run sandbox report](https://app.any.run/tasks/d55e2294-5377-4a45-b393-f5a8b20f7d44), which directory does the malware target for the deletion of all **DLL** files?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FNgFbG15HEBeclyFiWiq2%2FScreenshot%202025-10-04%20at%208.41.10%E2%80%AFPM.png?alt=media&#x26;token=7e328286-87d3-4399-99ad-199d011d7855" alt=""><figcaption></figcaption></figure>

**Target directory for DLL deletion:** **`C:\ProgramData\`** — the command `del "C:\ProgramData\*.dll"` deletes all `*.dll` in that folder.

**Evidence (command line):**\
`"C:\Windows\system32\cmd.exe" /c timeout /t 5 & del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe" & del "C:\ProgramData\*.dll"" & exit`

**Quick detection tip:** alert on `cmd.exe` creations with `del *\.dll` or deletions targeting `C:\ProgramData\` and on unexpected removal of DLL files from that directory.

Answer C:\ProgramData

#### Q7 Understanding the malware's behavior post-data exfiltration can give insights into its evasion techniques. By analyzing the child processes, after successfully exfiltrating the user's data, **how many seconds does** it take for the malware to **self-delete**? **5 seconds.**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F8yshFd5yv5ArofSxqU1H%2FScreenshot%202025-10-04%20at%208.44.29%E2%80%AFPM.png?alt=media&#x26;token=55501f1b-2f05-44f6-8d67-eb51ea710298" alt=""><figcaption></figcaption></figure>

The `cmd.exe` command starts with `timeout /t 5` — a 5-second delay before it deletes `VPN.exe` and DLLs (self-delete).

Answer `5`

[`https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/oski/`](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/oski/)
