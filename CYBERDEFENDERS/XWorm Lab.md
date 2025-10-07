# XWorm Lab

Category: [Malware Analysis](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=malware-analysis)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence)[Privilege Escalation](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=privilege-escalation)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)[Credential Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=credential-access)[Discovery](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=discovery)[Collection](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=collection)

Tools: [Detect It Easy](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=detect-it-easy)[CFF Explorer](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=cff-explorer)[PEStudio](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=pestudio)[dnSpy](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=dnspy)[ProcMon](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=procmon)[RegShot](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=regshot)[Python3](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=python3)

**Scenario**

An employee accidentally downloaded a suspicious file from a phishing email. The file executed silently, triggering unusual system behavior. As a malware analyst, your task is to analyze the sample to uncover its behavior, persistence mechanisms, communication with Command and Control (C2) servers, and potential data exfiltration or system compromise.

#### Q1 What is the compile timestamp (UTC) of the sample?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FqsomKGGEhFwaLwPc9Tsr%2FScreenshot%202025-10-03%20at%208.06.42%E2%80%AFPM.png?alt=media&#x26;token=f7f0088a-e4c1-41a2-b4e7-f438e82688c8" alt=""><figcaption></figcaption></figure>

unload Malware to <https://www.virustotal.com/gui/home/upload>

Answer `2024-02-25 22:53`

#### Q2 Which legitimate company does the malware impersonate in an attempt to appear trustworthy?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fd30ULn4DzJqQrCfVBGG4%2FScreenshot%202025-10-03%20at%208.10.18%E2%80%AFPM.png?alt=media&#x26;token=22e11564-ceb0-434e-858e-09c1e718cae2" alt=""><figcaption></figcaption></figure>

Answer `Adobe`

#### Q3 How many anti-analysis checks does the malware perform to detect/evade sandboxes and debugging environments?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FavfngbJiPmFlJ8LEt2LK%2FScreenshot%202025-10-03%20at%208.14.08%E2%80%AFPM.png?alt=media&#x26;token=0c555f01-4ef1-47b8-9b60-59a9ad9e7302" alt=""><figcaption></figcaption></figure>

Answer `5`

#### Q4 What is the name of the scheduled task created by the malware to achieve execution with elevated privileges?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FjlSeiG33U5eylU8nXwyi%2FScreenshot%202025-10-03%20at%208.24.36%E2%80%AFPM.png?alt=media&#x26;token=8ab17aa9-199d-492c-90b8-927ac407238c" alt=""><figcaption></figcaption></figure>

* `Add-MpPreference -ExclusionPath 'C:\Users\a.monaldo\AppData\Local\Temp\4c9d58c52d73854dfddb3835d603ad64.malware'`\
  → tells Microsoft Defender **not** to scan or block that file path.
* `Add-MpPreference -ExclusionPath 'C:\Users\a.monaldo\AppData\Roaming\WmiPrvSE.exe'`\
  → excludes a dropped executable that mimics `wmiprvse.exe` (likely the malware stub).
* `Add-MpPreference -ExclusionProcess '4c9d58c52d73854dfddb3835d603ad64.malware'`\
  → excludes by process name (real‑time protection will ignore that process).

**Implication:** the malware has elevated privileges or used an elevated process (we saw PowerShell invoked) to whitelist itself in Defender so it can run and persist without being detected. This is a classic evasion step.

Answer `WmiPrvSE`

#### Q5 What is the filename of the malware binary that is dropped in the AppData directory?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FgkFF1cjS1hQGUUD0Anl5%2FScreenshot%202025-10-03%20at%208.28.17%E2%80%AFPM.png?alt=media&#x26;token=7814e731-56da-40a8-9558-3c02cd47363e" alt=""><figcaption></figcaption></figure>

The attacker used elevated PowerShell to call `Add‑MpPreference` and:

* Whitelisted the temp drop:\
  `C:\Users\a.monaldo\AppData\Local\Temp\4c9d58c52d73854dfddb3835d603ad64.malware`
* Whitelisted the persistent drop:\
  `C:\Users\a.monaldo\AppData\Roaming\WmiPrvSE.exe`
* Whitelisted the process name:\
  `4c9d58c52d73854dfddb3835d603ad64.malware`

**Effect:** Defender will not scan or block these files/processes → malware evades AV and persists.

Answer `WmiPrvSE.exe`

#### Q6Which cryptographic algorithm does the malware use to encrypt or obfuscate its configuration data?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FxugCXJSFXBKkS2dzLBcC%2FScreenshot%202025-10-03%20at%208.32.16%E2%80%AFPM.png?alt=media&#x26;token=71df769b-893b-4675-8ee0-c06a03f58daa" alt=""><figcaption></figcaption></figure>

The malware uses **AES (Rijndael)** to encrypt/obfuscate its configuration data — most likely **AES‑128** (16‑byte key).

**Why (evidence from your provided config):**

* The JSON contains an `"Aes key": "<123456789>"` field.
* `extra_data` includes `obfuscated_key_10: "8xTJ0EKPuiQsJVaT"`, a 16‑character string — which is consistent with a 16‑byte AES‑128 key.
* These two indicators together strongly point to AES rather than simple XOR or RC4.

Answer `AES`

#### Q7 To derive the parameters for its encryption algorithm (such as the key and initialization vector), the malware uses a hardcoded string as input. What is the value of this hardcoded string?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FMEGiIWpeBh7qTM715Uxz%2FScreenshot%202025-10-03%20at%208.35.44%E2%80%AFPM.png?alt=media&#x26;token=dc105b87-0ccc-4f08-968e-62892f628abb" alt=""><figcaption></figcaption></figure>

* Length: 16 ASCII characters → **16 bytes** → suitable as an **AES‑128** key.
* Very likely used directly as the AES key (not as an IV) in this XWorm sample.

Answer `8xTJ0EKPuiQsJVaT`

#### Q8 What are the Command and Control (C2) IP addresses obtained after the malware decrypts them?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FF4AhEM3WkrbzhLirwZfy%2FScreenshot%202025-10-03%20at%208.39.27%E2%80%AFPM.png?alt=media&#x26;token=b66a3aa4-984f-4b64-ab36-f993a171e778" alt=""><figcaption></figcaption></figure>

The decrypted C2 endpoints are:

* `185.117.250.169:7000`
* `66.175.239.149:7000`
* `185.117.249.43:7000`

Answer `185.117.250.169,66.175.239.149,185.117.249.43`

#### Q9 What port number does the malware use for communication with its Command and Control (C2) server?

Answer `7000`

#### Q10 The malware spreads by copying itself to every connected removable device. What is the name of the new copy created on each infected device?

the malware’s `"USBNM"` field is set to **`"USB.exe"`**.

* This field tells the malware what filename to use when it copies itself to every connected removable drive (USB sticks, external drives) to propagate.
* So each infected device gets a copy named **USB.exe**, which is consistent with typical removable‑media spreading behavior in this malware family.

Answer **`USB.exe`**

#### Q11 To ensure its execution, the malware creates specific types of files. What is the file extension of these created files?

The malware creates Windows shortcut (`.lnk`) files on removable drives so users clicking the shortcut will execute the dropped payload.

Answer `ink`

#### Q12What is the name of the DLL the malware uses to detect if it is running in a sandbox environment?

**SbieDll.dll** — the sample attempts to load `SbieDll.dll` to detect the presence of Sandboxie (a common sandbox-evasion check).

Answer `SbieDll.dll`

#### Q13What is the name of the registry key manipulated by the malware to control the visibility of hidden items in Windows Explorer?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FKproNQnxQlIjM5V35jjV%2FScreenshot%202025-10-03%20at%209.02.04%E2%80%AFPM.png?alt=media&#x26;token=81ade7e8-c0af-48a9-aadd-40dab4ca2a35" alt=""><figcaption></figcaption></figure>

#### Registry Key: `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden`

* **Location:** Under **HKEY\_CURRENT\_USER**
* **Purpose:** Controls the visibility of advanced hidden files and folders in Windows Explorer

#### `ShowSuperHidden` Values:

| Value | Meaning                                                           |
| ----- | ----------------------------------------------------------------- |
| `0`   | Do **not** show hidden files and folders (including system files) |
| `1`   | Show all hidden files and folders, including system files         |

#### Why Malware Uses This Key

* XWorm and similar RAT malware often **modifies `ShowSuperHidden`** to hide its own files from the user.
* Setting it to `0` prevents the malware’s files or any created artifacts from appearing in Windows Explorer.
* This is a **defense evasion** technique.

**Summary:** The malware uses this key to **hide its files and folders**, making them invisible to the user in Explorer.

Answer `ShowSuperHidden`

#### Q14Which API does the malware use to mark its process as critical in order to prevent termination or interference?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F1nn9xP4vBoxSVVgt2cgZ%2FScreenshot%202025-10-03%20at%209.06.33%E2%80%AFPM.png?alt=media&#x26;token=242ebd0e-fd82-4aa7-bbca-3e43da07abda" alt=""><figcaption></figcaption></figure>

**RtlSetProcessIsCritical** (from **ntdll.dll**).

Short note: this API marks the process as critical so attempts to terminate it can cause a system crash (BSOD).\
Detection/remediation: look for calls to `RtlSetProcessIsCritical` in memory/process dumps or identify process creation events followed by unexpected `ExitProcess`/BSODs; remove persistence and reboot into safe mode to kill the process, or terminate via a kernel debugger if necessary.

Answer `RtlSetProcessIsCritical`

#### Q15Which API does the malware use to insert keyboard hooks into running processes in order to monitor or capture user input?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fo4w4hqaBvqrxUlrx2Mj4%2FScreenshot%202025-10-03%20at%209.08.40%E2%80%AFPM.png?alt=media&#x26;token=b76f07a3-c78a-4bb1-b685-926e88385ec3" alt=""><figcaption></figcaption></figure>

Answer `SetWindowsHookEx`

#### Q16Given the malware’s ability to insert keyboard hooks into running processes, what is its primary functionality or objective?

installing keyboard hooks (via `SetWindowsHookEx`) lets the malware **capture keystrokes and related context** directly from the user’s input stream — which is exactly what a keylogger does. Concretely:

* **Technical mechanism:** a keyboard hook intercepts keyboard events before the target application sees them, so the malware receives every keystroke (including passwords, OTPs, chat messages).
* **Context enrichment:** combined with APIs like `GetForegroundWindow` / `GetWindowText` the malware can associate keystrokes with the active application or window (so stolen data is more useful).
* **Complementary capabilities:** clipboard listeners, screenshot calls, and network exfiltration send captured data to C2 (you already found C2 IPs and persistence), turning raw keystrokes into actionable credentials/data for the attacker.
* **Purpose alignment:** in RATs/stealers the goal is credential/theft, fraud, or espionage — keylogging is a high‑value capability for those objectives.

Answer `Keylogger`

[`https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/xworm/` ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/xworm/)
