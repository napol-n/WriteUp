# 3CX Supply Chain Lab

Category: [Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

Tactics: [Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence)[Privilege Escalation](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=privilege-escalation)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)[Discovery](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=discovery)

Tool: [VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)

**Scenario**

A large multinational corporation heavily relies on the 3CX software for phone communication, making it a critical component of their business operations. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations while others remain unaffected. Dismissing this as a false positive, the IT team overlooks the alerts, only to notice degraded performance and strange network traffic to unknown servers. Employees report issues with the 3CX app, and the IT security team identifies unusual communication patterns linked to recent software updates.

As the threat intelligence analyst, it's your responsibility to examine this possible supply chain attack. Your objectives are to uncover how the attackers compromised the 3CX app, identify the potential threat actor involved, and assess the overall extent of the incident.&#x20;

#### Q1 Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX **running on Windows** have been flagged as malware?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FGoXWVAZI9y4jvywPBUHB%2FScreenshot%202025-10-06%20at%202.48.55%E2%80%AFPM.png?alt=media&#x26;token=8004eb75-48e3-402c-9547-3da714c216e8" alt=""><figcaption></figcaption></figure>

**There are 2 Windows versions of 3CX that were flagged as malware:**\
**18.12.407** and **18.12.416**

Answer **`2`**

#### Q2 Determining the age of the malware can help assess the extent of the compromise and track the evolution of malware families and variants. What's the UTC creation time of the `.msi` malware?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FvOpDXSyQRWlTWI4rZCGe%2FScreenshot%202025-10-06%20at%202.51.12%E2%80%AFPM.png?alt=media&#x26;token=ebfe1e33-8496-41d5-a62a-b73a44337602" alt=""><figcaption></figcaption></figure>

\
Answer **`2023-03-13 06:33`**

#### Q3 Executable files (`.exe`) are frequently used as primary or secondary malware payloads, while dynamic link libraries (`.dll`) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (`.msi`) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the `.msi` file?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FI8uPZ1BF9cIpgMZkrqis%2FScreenshot%202025-10-06%20at%202.56.09%E2%80%AFPM.png?alt=media&#x26;token=0c144e99-7be8-456c-8b54-58ea36b57f9a" alt=""><figcaption></figcaption></figure>

\\

DLLs dropped by the `.msi` file are:

> **ffmpeg.dll** and **d3dcompiler\_47.dll**

Answer **`ffmpeg.dll, d3dcompiler_47.dll`**

#### Q4 Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE Technique ID employed by the `.msi` files to load the malicious DLL?

> **MITRE Technique ID:** **T1574.002 – Hijack Execution Flow: DLL Side-Loading**

Answer **`T1574.002`**\\

#### Q5 Recognizing the malware type (`threat category`) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the threat category of the two malicious DLLs?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F6uCvBaUPFyaMMDKgxxvS%2FScreenshot%202025-10-06%20at%203.04.09%E2%80%AFPM.png?alt=media&#x26;token=542ea0f1-310a-4cc5-bbe7-df22a1003602" alt=""><figcaption></figcaption></figure>

> **Trojan**

The **threat category** of the two malicious DLLs (`ffmpeg.dll` and `d3dcompiler_47.dll`) is:

Answer **`Trojan`**

#### Q6 As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?

* alware uses **T1497** to detect virtual machines or sandbox environments.
* This prevents execution or alters behavior to evade detection by analysts or automated systems.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F8jQafMzWxV5CoQa3RXDT%2FScreenshot%202025-10-06%20at%203.08.30%E2%80%AFPM.png?alt=media&#x26;token=c05ccb05-7d43-44ba-b132-62b8949563f2" alt=""><figcaption></figcaption></figure>

Answer **`T1497`**

#### Q7 When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the `ffmpeg.dll`file?

\
Answer **`VMware`**

#### Q8 Identifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What encryption algorithm is used by the `ffmpeg.dll` file?

Answer **RC4**\\

#### Q9 As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?

Answer **Lazarus**

\
[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/3cx-supply-chain/ ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/3cx-supply-chain/)\
\\
