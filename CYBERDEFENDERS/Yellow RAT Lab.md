# Yellow RAT Lab

Category: [Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

Tools: [VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)[Red /Canary](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=red-canary)

**Scenario**

During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation. Your task is to investigate this incident and gather as much information as possible.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FtUGAlAMZkZgTcv1LHx7m%2FScreenshot%202025-10-04%20at%209.32.23%E2%80%AFPM.png?alt=media&#x26;token=3fc2c35f-b9a2-443a-97f0-ce2aec80092c" alt=""><figcaption></figcaption></figure>

`30E527E45F50D2BA82865C5679A6FA998EE0A1755361AB01673950810D071C85`

#### Q1 Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FdkqLJDSDybd57bDaruMj%2FScreenshot%202025-10-04%20at%209.36.56%E2%80%AFPM.png?alt=media&#x26;token=5e3e4fda-3e27-4cf5-8561-5a9eaa0fd471" alt=""><figcaption></figcaption></figure>

Answer `Yellow Cockatoo RAT`

#### Q2 As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FIdfN5aSp6GdKemjqGfXF%2FScreenshot%202025-10-04%20at%209.38.35%E2%80%AFPM.png?alt=media&#x26;token=a15caba9-4fc5-4d35-a53f-215328137b22" alt=""><figcaption></figcaption></figure>

Answer `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`

#### Q3 Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F7IeDs7XzohzzWqr5veKn%2FScreenshot%202025-10-04%20at%209.39.44%E2%80%AFPM.png?alt=media&#x26;token=9248d980-54bc-48b2-b4e9-3db57f8791b5" alt=""><figcaption></figcaption></figure>

Answer `2020-09-24 18:26`

#### Q4 Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FQF13lOdZcLV5kbmeJGcW%2FScreenshot%202025-10-04%20at%209.42.07%E2%80%AFPM.png?alt=media&#x26;token=48a1b323-ecc6-4566-ae6d-72df6e0f8eab" alt=""><figcaption></figcaption></figure>

Answer `2020-10-15 02:47`

#### Q5 To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the **.dat** file that the malware dropped in the **AppData** folder?

Answer `solarmarker.dat`

#### Q6 It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FTYHKr5Jbi0QeqXpeqWwT%2FScreenshot%202025-10-04%20at%209.48.40%E2%80%AFPM.png?alt=media&#x26;token=1c4edc4c-1567-4da3-b5a7-c6983d7d9341" alt=""><figcaption></figcaption></figure>

**`https://gogohid.com`**

Malware communicates with this domain to receive commands and exfiltrate data. In an enterprise environment, this domain should be **blocked at the firewall or DNS level**, and any connections to it should be logged and investigated.

Answer **`https://gogohid.com`**\\

<https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/yellow-rat/>\\
