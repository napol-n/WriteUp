# XLMRat Lab

Category: [Network Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=network-forensics)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion)

Tools: [CyberChef](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=cyberchef)[Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=wireshark)[VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)[Python3](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=python3)[PowerShell](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=powershell)

### **Scenario**

A compromised machine has been flagged due to suspicious network traffic. Your task is to analyze the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

#### Q1 The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

<div><figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FQVi1gxhZNtearawpmlTr%2FScreenshot%202025-10-02%20at%208.48.53%E2%80%AFPM.png?alt=media&#x26;token=fd4a22ac-1b88-4324-9738-768e80910fb9" alt=""><figcaption></figcaption></figure> <figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FSG1PNWQoBQqQULs5IfNN%2FScreenshot%202025-10-02%20at%208.49.00%E2%80%AFPM.png?alt=media&#x26;token=6536ed95-a9cd-4517-a666-544fd7ed2c94" alt=""><figcaption></figcaption></figure></div>

ANSWER <http://45.126.209.4:222/mdm.jpg>

#### Q2 Which hosting provider owns the associated IP address?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FC8kd7qQeuREEnrzumAhu%2FScreenshot%202025-10-02%20at%208.52.59%E2%80%AFPM.png?alt=media&#x26;token=aa181048-53db-4fbc-9131-58c5b5a81c77" alt=""><figcaption></figcaption></figure>

The IP address **45.126.209.4** belongs to **ReliableSite.Net LLC** (ASN AS23470) as the hosting provider.

ANSWER reliableSite.net

#### Q3 By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

ANSWER&#x20;

1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798

#### Q4What is the malware family label based on Alibaba?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FR9bnNEPskC8qhqvvbR7c%2FScreenshot%202025-10-02%20at%209.05.31%E2%80%AFPM.png?alt=media&#x26;token=64d92474-c340-4fc3-a3ea-e6667e3d112b" alt=""><figcaption></figcaption></figure>

ANSWER asyncrat

#### Q5 What is the timestamp of the malware's creation?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FvZFkLDdOmFa5hHtCICKd%2FScreenshot%202025-10-02%20at%209.11.58%E2%80%AFPM.png?alt=media&#x26;token=8832eceb-105b-4536-ab33-bb8f4ac8f52b" alt=""><figcaption></figcaption></figure>

ANSWER 2023-10-30 15:08

#### Q6 Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

ANSWER ***C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe***

#### Q7 The script is designed to drop several files. List the names of the files dropped by the script.

Conted.vbs,Conted.ps1,Conted.bat

[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/xlmrat/ ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/xlmrat/)
