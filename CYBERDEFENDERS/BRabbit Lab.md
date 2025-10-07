# BRabbit Lab

Category: [Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence)[Privilege Escalation](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=privilege-escalation)[Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)[Impact](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=impact)

Tools: [malpedia](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=malpedia)[VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)[ANY.RUN](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=anyrun)[Email Header Analyzer](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=email-header-analyzer)[MalwareURL](https://www.malwareurl.com/)

### **Scenario**

You are an investigator assigned to assist Drumbo, a company that recently fell victim to a ransomware attack. The attack began when an employee received an email that appeared to be from the boss. It featured the company’s logo and a familiar email address. Believing the email was legitimate, the employee opened the attachment, which compromised the system and deployed ransomware, encrypting sensitive files. Your task is to investigate and analyze the artifacts to uncover information about the attacker.

### Q1 The phishing email used to deliver the malicious attachment showed several indicators of a potential social engineering attempt. Recognizing these indicators can help identify similar threats in the future. What is the suspicious email address that sent the attachment?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FT41HVUhcFANgG0uKm7qp%2FScreenshot%202025-10-02%20at%2010.04.13%E2%80%AFPM.png?alt=media&#x26;token=877184a0-b543-4c68-b1e4-e09e2a4b3e0d" alt=""><figcaption></figcaption></figure>

ANSWER <theceojamessmith@Drurnbo.com>

### Q2 The ransomware was identified as part of a known malware family. Determining its family name can provide critical insights into its behavior and remediation strategies. What is the family name of the ransomware identified during the investigation?

630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F81PG2T4DTK6lMGEYzV2t%2FScreenshot%202025-10-02%20at%2010.12.27%E2%80%AFPM.png?alt=media&#x26;token=5ff21ee4-c82d-4095-8284-8646ca322920" alt=""><figcaption></figcaption></figure>

The ransomware was identified as part of the **BadRabbit** malware family.

**Explanation:**

* After extracting the malicious attachment from the phishing email, analysts computed its hash (SHA-256) and submitted it to platforms like **VirusTotal**.
* VirusTotal and other threat intelligence sources confirmed that the file was malicious and linked it to **BadRabbit**, a ransomware known for drive-by attacks, encrypting files, and modifying the Master Boot Record (MBR).
* Identifying the malware family helps understand its behavior, infection vectors, and remediation strategies.

ANSWER **BadRabbit**

***

### Q3Upon execution, the ransomware dropped a file onto the compromised system to initiate its payload. Identifying this file is essential for understanding its infection process. What is the name of the first file dropped by the ransomware?

The first file dropped by the ransomware is **`infpub.dat`**.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FWqsfBbSDmTZpMBGL18aa%2FScreenshot%202025-10-02%20at%2010.19.44%E2%80%AFPM.png?alt=media&#x26;token=b65f7e2c-16e9-4c62-88d3-8f68aca5a2fa" alt=""><figcaption></figcaption></figure>

**Explanation:**

* When the BadRabbit ransomware executes, it immediately creates `infpub.dat` on the system.
* This file acts as a key component of the malware’s payload, often containing encoded instructions or data necessary for subsequent malicious actions.
* Dynamic analysis in a sandbox (e.g., ANY.RUN) or examining VirusTotal’s “Dropped Files” section confirms that `infpub.dat` is the initial file created and used by processes like `rundll32.exe` to continue the attack.
* Identifying this file is critical as it serves as an **indicator of compromise (IOC)** for detection and mitigation efforts.
* <https://app.any.run/tasks/9e1daf92-0cfc-422b-a0c2-14f11ee169d4>

ANSWER **`infpub.dat`**

***

### Q4 Inside the dropped file, the malware contained hardcoded artifacts, including usernames and passwords that could provide clues about its origins or configuration. What is the only person's username found within the dropped file?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FAdU5Jdedyb9v0DgpIECD%2FScreenshot%202025-10-02%20at%2010.27.39%E2%80%AFPM.png?alt=media&#x26;token=573dbedd-9322-47aa-a7f7-c36f7eb1e56f" alt=""><figcaption></figcaption></figure>

ANSWER alex

***

### Q5 After execution, the ransomware communicated with a C2 server. Recognizing its communication techniques can assist in mitigation. What MITRE ATT\&CK sub-technique describes the ransomware’s use of web protocols for sending and receiving data?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FNrEzQba3WLW6QeAfN3UR%2FScreenshot%202025-10-02%20at%2010.51.52%E2%80%AFPM.png?alt=media&#x26;token=831b229c-f4c5-4050-869f-e9588ee736fa" alt=""><figcaption></figcaption></figure>

The MITRE ATT\&CK **sub-technique** used by the ransomware to communicate with its C2 server over web protocols is:

**T1071.001 — Application Layer Protocol: Web Protocols**

ANSWER **T1071.001**&#x20;

***

### Q6Persistence mechanisms are a hallmark of sophisticated ransomware. Identifying how persistence was achieved can aid in recovery and prevention of reinfection. What is the MITRE ATT\&CK Sub-Technique ID associated with the ransomware’s persistence technique?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FMfkh7e18Bg9SQHm3soQR%2FScreenshot%202025-10-02%20at%2010.52.20%E2%80%AFPM.png?alt=media&#x26;token=18596b83-845e-4cb5-8d7e-755560258ed8" alt=""><figcaption></figcaption></figure>

**T1053.005 — Scheduled Task/Job**

#### Explanation

1. **Observation of ransomware behavior**
   * BadRabbit creates scheduled tasks on the victim system to ensure that its malicious payload executes automatically, even after a reboot.
   * Example tasks: `rhaegal` (executes `dispci.exe`) and `drogon` (forces system shutdown to facilitate encryption).
2. **Technique classification**
   * Malware uses **Windows Task Scheduler** to automate execution.
   * This allows it to maintain persistence without relying on the user running the file manually.
3. **Mapping to MITRE ATT\&CK**
   * **T1053 — Scheduled Task/Job:** General technique for creating automated tasks.
   * **T1053.005 — Scheduled Task/Job (Sub-Technique):** Specifically refers to using scheduled tasks for malicious persistence.
4. **Defensive relevance**

   * Inspect the Task Scheduler for unauthorized tasks (`schtasks /Query`)
   * Remove malicious tasks to stop reinfection
   * Monitor for suspicious task creation by unexpected processes

   ANSWER **T1053.005**

ANSWER  T1053.005

***

### Q7As part of its infection chain, the ransomware created specific tasks to ensure its continued operation. Recognizing these tasks is crucial for system restoration. What are the names of the tasks created by the ransomware during execution?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FKKxZsYCzGJGOUv38Rq9v%2FScreenshot%202025-10-02%20at%2010.36.56%E2%80%AFPM.png?alt=media&#x26;token=ef893785-5f39-47c8-95dc-7847cc23605b" alt=""><figcaption></figcaption></figure>

ANSWER rhaegal, drogon

***

### Q8the malicious binary `dispci.exe` displayed a **suspicious message** upon execution, urging users to disable their defenses. This tactic aimed to evade detection and enable the ransomware's full execution. What suspicious message was displayed in the Console upon executing this binary?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FJMXi87hvC5OCl6L8biTa%2FScreenshot%202025-10-02%20at%2010.45.08%E2%80%AFPM.png?alt=media&#x26;token=62ea694e-24da-4ce4-8e7e-00a74b2358bd" alt=""><figcaption></figcaption></figure>

The suspicious message displayed in the console when executing `dispci.exe` was:

**"Disable your anti-virus and anti-malware programs"**

#### Explanation

1. **Observation of ransomware behavior**
   * `dispci.exe` is executed via the scheduled task `rhaegal`.
   * Dynamic analysis (e.g., ANY.RUN) shows the console output when the binary runs.
2. **Purpose of the message**
   * The ransomware attempts to **evade detection** by instructing or coercing the user to turn off security software.
   * This ensures that its encryption and malicious payload can run **unimpeded**.
3. **Implications for defense**
   * Presence of this message is a strong **Indicator of Compromise (IOC)**.
   * Endpoint protection should prevent or alert on processes trying to modify or bypass antivirus programs.

ANSWER Disable your anti-virus and anti-malware programs

***

### Q9To modify the Master Boot Record (MBR) and encrypt the victim’s hard drive, the ransomware utilized a specific driver. Recognizing this driver is essential for understanding the encryption mechanism. What is the name of the driver used to encrypt the hard drive and modify the MBR?

<https://blog.qualys.com/vulnerabilities-threat-research/2017/10/24/bad-rabbit-ransomware>

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FK3K724cYa1RSScZIYK2q%2FScreenshot%202025-10-02%20at%2010.56.00%E2%80%AFPM.png?alt=media&#x26;token=0a370e5e-37e0-4971-9473-7f69e569c0e8" alt=""><figcaption></figcaption></figure>

**DiskCryptor** (the DiskCryptor driver was used to encrypt the disk and modify the MBR).

* BadRabbit leverages the legitimate open‑source full‑disk encryption project **DiskCryptor** (references such as `diskcryptor.net` appear in the malicious binary metadata/strings).
* Sandboxed reports (ANY.RUN / VirusTotal) and static analysis of the ransomware binary reveal DiskCryptor-related strings and that the malware installs/uses a DiskCryptor driver to write to the MBR and perform full‑disk encryption.

ANSWER diskcryptor

***

### Q10Attribution is key to understanding the threat landscape. The ransomware was tied to a known attack group through its tactics, techniques, and procedures (TTPs). What is the name of the threat actor responsible for this ransomware campaign?

ansomware campaign is the APT group **Sandworm**, also known as **TeleBots**.

**Explanation:**

* BadRabbit and related ransomware variants (like EternalPetya / NotPetya / Diskcoder.C) share tactics, techniques, and procedures (TTPs) that match Sandworm’s historical attacks.
* Sandworm is known for cyber sabotage, often targeting critical infrastructure and large organizations.
* Attribution comes from analyzing malware behavior, infection methods, persistence mechanisms, and network communications, which align with Sandworm’s known operations.

Recognizing Sandworm as the actor helps organizations anticipate potential targets, understand likely attack patterns, and strengthen defensive measures against similar ransomware campaigns.

ANSWER **Sandworm**

***

### Q11The ransomware rendered the system unbootable by corrupting critical system components. Identifying the technique used provides insight into its destructive capabilities. What is the MITRE ATT\&CK ID for the technique used to corrupt the system firmware and prevent booting?

**T1495 – Firmware Corruption**

**Explanation:**

* BadRabbit modifies the Master Boot Record (MBR) using the DiskCryptor driver (`cscc.dat`), preventing the system from booting.
* T1495 describes adversaries overwriting or corrupting firmware or system-level components to make the system inoperable.
* This destructive action increases the likelihood of ransom payment and demonstrates high-impact ransomware behavior.

ANSWER **T1495**

***

### [https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/brabbit/ ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/brabbit/)
