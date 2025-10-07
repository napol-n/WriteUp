# Amadey Lab

Category: [Endpoint Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=endpoint-forensics)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence)[Privilege Escalation](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=privilege-escalation)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)[Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)[Exfiltration](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=exfiltration)

Tool: [Volatility 3](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=volatility-3)

**Scenario**

An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer. Your job is to analyze the presented memory dump and create a detailed report for actions taken by the malware.

#### Q1 In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?

Answer **`lssass.exe`**

#### Q2 Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?

Answer **`C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe`**

#### Q3 Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?

Answer **`41.75.84.12`**

#### Q4 Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?

Answer **`2`**

#### Q5 Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?

Answer **`C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`**

#### &#x20;Q6 Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?

Answer **`rundll32.exe`**

#### Q7 Understanding the full range of Amadey's persistence mechanisms can help in an effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?

Answer **`C:\Windows\System32\Tasks\lssass.exe`**

[**`https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/amadey/`** ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/amadey/)
