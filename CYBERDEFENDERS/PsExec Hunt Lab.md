# PsExec Hunt Lab

Category: [Network Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=network-forensics)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)[Discovery](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=discovery)[Lateral Movement](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=lateral-movement)

ool: [Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=wireshark)

**Scenario**

An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicates potential unauthorized access and movement across the network. As a SOC Analyst, your task is to investigate the provided PCAP file to trace the attacker’s activities. Identify their entry point, the machines targeted, the extent of the breach, and any critical indicators that reveal their tactics and objectives within the compromised environment.

#### Q1 To effectively trace the attacker's activities within our network, can you identify the IP address of the machine from which the attacker initially gained access?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FWK07ffz2xcut3Ktxrq7P%2FScreenshot%202025-10-05%20at%2011.23.45%E2%80%AFPM.png?alt=media&#x26;token=c8e6122a-c14c-42d4-b2b1-8be5f7fc638f" alt=""><figcaption></figcaption></figure>

**10.0.0.130** is identified as the likely attacker’s initial access because it is the source of the first SMB session (Negotiate Protocol Request, Frame 126) to other hosts. It initiates communication before any other machine, showing classic lateral movement behavior via SMB. Full confirmation requires checking for `ADMIN$` access, `PSEXESVC` upload, and `CreateService/StartService` RPC calls from this IP.

**`Answer 10.0.0.130`**

#### Q2 To fully understand the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FNyzuQ3zKjKZxQBk9GEfO%2FScreenshot%202025-10-05%20at%2011.29.42%E2%80%AFPM.png?alt=media&#x26;token=8f207758-8237-4dc2-b115-5e5df109820e" alt=""><figcaption></figcaption></figure>

Why: the NTLMSSP blocks in your paste include repeated strings like `S.A.L.E.S.-.P.C` and `S.a.l.e.s.-.P.C` — that’s the encoded workstation name decoded as **SALES-PC**.

**`Answer SALES-PC`**

#### Q3 Knowing the username of the account the attacker used for authentication will give us insights into the extent of the breach. What is the username utilized by the attacker for authentication?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FTKsrweyeTCFzJzP0Fcva%2FScreenshot%202025-10-05%20at%2011.33.23%E2%80%AFPM.png?alt=media&#x26;token=92c16030-68de-48ab-9b0c-6bd85fe1b9e0" alt=""><figcaption></figcaption></figure>

authenticated as **Issales** — seen in the NTLMSSP Session Setup (e.g. the SMB2 Session Setup / NTLMSSP\_AUTH exchange around **frames 132–133**, user shown as `Issales`).

**`Answer ssales`**

#### Q4 After figuring out how the attacker moved within our network, we need to know what they did on the target machine. What's the name of the service executable the attacker set up on the target?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FkczLfutFhlFRC53yN2z8%2FScreenshot%202025-10-05%20at%2011.36.41%E2%80%AFPM.png?alt=media&#x26;token=15b94212-c7d1-4339-91db-3d69f0c7133e" alt=""><figcaption></figcaption></figure>

The attacker installed a service binary named **PSEXESVC.exe** (shown as `PSEXESVC` in the SMB/service activity).

Evidence:

* SMB file create/write for `PSEXESVC.exe` appears in the stream (Create Request / Create Response around **frames 144–145** of `tcp.stream == 24`).
* RPC/service activity (svcctl CreateService / StartService) follows the upload — classic PsExec behavior that installs/runs `PSEXESVC`.

**`Answer PSEXESVC`**

#### Q5 We need to know how the attacker installed the service on the compromised machine to understand the attacker's lateral movement tactics. This can help identify other affected systems. Which network share was used by PsExec to install the service on the target machine?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FsxE8aVGq0cLXnZtZ2UJi%2FScreenshot%202025-10-05%20at%2011.40.50%E2%80%AFPM.png?alt=media&#x26;token=ea3f6a7c-be89-4860-810d-dbcd4ba278d0" alt=""><figcaption></figcaption></figure>

* **Frame 138** — Tree Connect Request: `\\10.0.0.133\ADMIN$`.
* **Frames 144–145** — Create Request / Create Response for `PSEXESVC.exe` written to that share.

Evidence from the capture (tcp.stream == 24):

**ADMIN$** — PsExec uploaded `PSEXESVC.exe` to the administrative share and used it to install the service.

**`Answer ADMIN$`** \\

#### &#x20;Q6 We must identify the network share used to communicate between the two machines. Which network share did PsExec use for communication?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fw8fx5KlmRM3FzcDgJVt2%2FScreenshot%202025-10-05%20at%2011.42.31%E2%80%AFPM.png?alt=media&#x26;token=cc1a9fb5-05c7-41cd-af20-cdb43c1dfa5a" alt=""><figcaption></figcaption></figure>

channel used **`IPC$`**.

Why: in the SMB stream (`tcp.stream == 24`) the attacker first performs a **Tree Connect to `\\10.0.0.133\IPC$`** (Frame **136**), which is where RPC named-pipe traffic (e.g., `\PIPE\svcctl`) is carried. PsExec uses `ADMIN$` to upload the `PSEXESVC.exe`binary and `IPC$` (named pipes / RPC) to talk to the Service Control Manager (svcctl) to **create/start the service**.

**`Answer IPC$`**\
\\

#### Q7 Now that we have a clearer picture of the attacker's activities on the compromised machine, it's important to identify any further lateral movement. What is the hostname of the second machine the attacker targeted to pivot within our network?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FO6KzoMtzXQf7vDvSZlTJ%2FScreenshot%202025-10-05%20at%2011.57.16%E2%80%AFPM.png?alt=media&#x26;token=8c43ba16-1434-48f8-ab34-4fa9013fa1d5" alt=""><figcaption></figcaption></figure>

The LLMNR packet you pasted is a **name query** from `10.0.0.131` asking for `Marketing-PC` (Protocol = LLMNR, Info shows `Marketing-PC`). That means the host identifies itself / advertises that name on the network — so `10.0.0.131` = `Marketing-PC`.

\
**`Answer MARKETING-PC`**

[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/psexec-hunt/ ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/psexec-hunt/)\
\\

\
\
\
\\
