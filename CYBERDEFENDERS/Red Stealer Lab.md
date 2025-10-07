# Red Stealer Lab

Category: [Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence)[Privilege Escalation](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=privilege-escalation)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)[Discovery](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=discovery)[Collection](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=collection)[Impact](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=impact)

Tools: [Whois](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=whois)[VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)[MalwareBazaar](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=malwarebazaar)[ThreatFox](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=threatfox)[ANY.RUN](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=anyrun)

**Scenario**

You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.\
Your task is to investigate this executable by analyzing its hash. The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.

#### Q1 Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FPhTq6Q4a3JPdsJfFDF4b%2FScreenshot%202025-10-06%20at%2012.44.04%E2%80%AFPM.png?alt=media&#x26;token=15feadad-f2c6-4829-b3e7-b235de35ce4d" alt=""><figcaption></figcaption></figure>

Microsoft has categorized the malware on VirusTotal as **Trojan:Win32/Crifi.Niktol**.

Answer **`trojan`**

#### Q2 Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FZuaYVckNg5r6m6lpuS93%2FScreenshot%202025-10-06%20at%2012.46.09%E2%80%AFPM.png?alt=media&#x26;token=6bc66fe4-ae89-41a1-b3f4-3d59c03e667c" alt=""><figcaption></figcaption></figure>

Answer **`Wextract`**

#### Q3 Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware's first submission to VirusTotal?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F5QeMyvxS7Ly7IKmNxs2I%2FScreenshot%202025-10-06%20at%2012.47.57%E2%80%AFPM.png?alt=media&#x26;token=3415e723-8338-4ee3-91c9-ece81f7bcce4" alt=""><figcaption></figcaption></figure>

Answer **`2023-10-06 04:41`**

#### Q4 Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT\&CK technique ID for the malware's data collection from the system before exfiltration?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fe5LJiGjQf1pe1rovmD7v%2FScreenshot%202025-10-06%20at%2012.51.09%E2%80%AFPM.png?alt=media&#x26;token=f65375b0-6d02-4580-ad71-df0c66ce510e" alt=""><figcaption></figcaption></figure>

**collection behavior** is mapped to:**Tactic:** Collection (**TA0009**)

**Technique:** Data from Local System (**T1005**)

**Example observed behavior:** `(Process #14) applaunch.exe searches for sensitive data of web browser "Comodo IceDragon" by file.`

**Severity:** Low (but still indicates credential or sensitive data harvesting).

**T1005 — Data from Local System**.

Brief explanation: this refers to collecting files and data stored on the compromised host (e.g., browser credentials, wallet files, documents, configuration files) prior to exfiltration to a C2.

\
Answer **`T1005`**

#### Q5 Following execution, which social media-related domain names did the malware resolve via DNS queries?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FLtYRyDVelZRD14HsdE6q%2FScreenshot%202025-10-06%20at%2012.55.45%E2%80%AFPM.png?alt=media&#x26;token=a908621b-3be3-4518-b00a-c4a81ef63280" alt=""><figcaption></figcaption></figure>

**`Answer  facebook.com`**

#### Q6 Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?

\
Answer **`77.91.124.55:19071`**\\

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FRKlThEdJU4cxfIax2HMW%2FScreenshot%202025-10-06%20at%2012.56.48%E2%80%AFPM.png?alt=media&#x26;token=f2a3e65e-bfb4-4c7c-9773-1b55dac2f3e4" alt=""><figcaption></figcaption></figure>

decoded configuration reveals **Command & Control (C2) infrastructure** as follows:

**Primary C2 IP and Port:**

* `77.91.124.55:19071`

**Bot Identifier:**

* `frant`

**Authorization Header:**

* `c4d5190ca0f8fbee04183f426d6719eb`

**Additional C2 URLs:**

* `http://77.91.68.29/fks/` (listed twice)

💡 **Actionable notes for SOC/IR:**

* Block outbound traffic to **77.91.124.55:19071** and **77.91.68.29** on perimeter firewall and EDR.
* Hunt for connections using the `Authorization Header` value in network logs or HTTP headers.
* Monitor any process initiating connections to these C2 IPs/URLs.
* Correlate with host artifacts (files, scheduled tasks, mutexes) to identify infected endpoints.

#### Q7 YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "`Varp0s`" that detects the identified malware?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fqy2wOXZV9dSE2voQdPex%2FScreenshot%202025-10-06%20at%201.06.58%E2%80%AFPM.png?alt=media&#x26;token=5c544093-cb25-41e1-a5b7-0024a89194c3" alt=""><figcaption></figcaption></figure>

* **Author:** Varp0s
* **Purpose:** Detects RedLine Stealer payloads by matching unique strings, patterns, and behaviors associated with the malware.
* This rule is publicly listed in MalwareBazaar and can be downloaded or copied for local testing and threat hunting.

**Rule Name:** `detect_Redline_Stealer` ✅

Based on the MalwareBazaar entry you provided for SHA256 `248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b`, the **YARA rule created by Varp0s** that detects this malware&#x20;

Answer **`detect_Redline_Stealer`**\\

#### Q8 Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to **ThreatFox**?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FHShd92jbEPP6Yna5tm1e%2FScreenshot%202025-10-06%20at%201.09.48%E2%80%AFPM.png?alt=media&#x26;token=9cf28dbc-b5c2-4fd7-a8ef-19d23fe322c3" alt=""><figcaption></figcaption></figure>

According to ThreatFox, the malicious IP address **77.91.124.55** is associated with the malware family **RedLine Stealer**. This family is also known by the alias **RECORDSTEALER**. The **confidence level** for this association is reported as **high (100%)**, indicating a strong correlation between the IP address and the malware family.

Answer **`RECORDSTEALER`**

#### Q9 By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FdTWUfLKwwYTSkl3zDKRU%2FScreenshot%202025-10-06%20at%201.13.16%E2%80%AFPM.png?alt=media&#x26;token=f1541434-bdcb-4084-8e9e-38336c25670b" alt=""><figcaption></figcaption></figure>

**DLL used for privilege escalation:** **`ADVAPI32.dll`**

**Why:** The imported functions you listed — `AdjustTokenPrivileges`, `LookupPrivilegeValueA`, `OpenProcessToken`, `GetTokenInformation`, `AllocateAndInitializeSid`, `EqualSid`, `FreeSid` — are Windows API calls exposed by **ADVAPI32.dll** and are commonly used to manipulate access tokens and privileges (e.g., enable SeDebugPrivilege, adjust token rights, query token info). Malware that imports and calls these functions is attempting to escalate privileges, impersonate accounts, or perform actions requiring elevated rights.

Answer **`ADVAPI32.dll`**

\
[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/red-stealer/ \
](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/red-stealer/)\\

\\
