# DanaBot Lab

Category: [Network Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=network-forensics)

Tactics: [Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution)[Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)

Tools: [Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=wireshark), [VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal), [ANY.RUN](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=anyrun), [Network Miner](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=network-miner)

**Scenario**

The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

#### Q1 Which IP address was used by the attacker during the initial access?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fy4qXGrFTEXcAafgPyqBT%2FScreenshot%202025-10-06%20at%206.19.42%E2%80%AFPM.png?alt=media&#x26;token=37333fe8-7acc-4747-bc03-f9d6e2959ede" alt=""><figcaption></figcaption></figure>

attacker’s IP during initial access is **62.173.142.148** — it appears in the DNS response for `portfolio.serveirc.com` (packet 2).

Answer `62.173.142.148`

#### Q2 What is the name of the malicious file used for initial access?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FgRoXgiG96bn1f4z15SJw%2FScreenshot%202025-10-06%20at%206.25.53%E2%80%AFPM.png?alt=media&#x26;token=883a46bd-0391-43df-bba6-d6432e0e4242" alt=""><figcaption></figcaption></figure>

* `HTTP/1.1 200 OK` — the request succeeded.
* `Content-Type: application/octet-stream` + `Content-disposition: attachment;filename=allegato_708.js` — the server returned a downloadable file and set the download filename to **allegato\_708.js** (i.e., the initial access payload).
* `Transfer-Encoding: chunked` — payload was sent in chunks (normal for large/streamed responses).
* The GET was to `/login.php` on host `portfolio.serveirc.com` — attacker is (ab)using that endpoint to serve the JS.

Answer **`allegato_708.js`**

#### Q3 What is the SHA-256 hash of the malicious file used for initial access?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FVRQ3plFEu4H9blAVRDS6%2FScreenshot%202025-10-06%20at%206.36.49%E2%80%AFPM.png?alt=media&#x26;token=28df1914-a2c8-4931-ba12-dca473ae3ba7" alt=""><figcaption></figcaption></figure>

\
Answer **`847B4AD90B1DABA2D9117A8E05776F3F902DDA593FB1252289538ACF476C4268`**

#### Q4 Which process was used to execute the malicious file?

\\

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Foh5BYMz4XElTliRtcmMt%2FScreenshot%202025-10-06%20at%206.40.34%E2%80%AFPM.png?alt=media&#x26;token=9c48fef3-a54b-420b-be80-409585da483c" alt=""><figcaption></figcaption></figure>

Answer **`wscript.exe`**

#### Q5 What is the file extension of the second malicious file utilized by the attacker?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fbyf1gcKT7wLeJeCnkuuU%2FScreenshot%202025-10-06%20at%206.45.57%E2%80%AFPM.png?alt=media&#x26;token=6496794d-b400-426c-bce2-11baa027f5ef" alt=""><figcaption></figcaption></figure>

The file extension is **`.dll`** — the second malicious file is `resources.dll`.

Answer .dll

#### Q6 What is the MD5 hash of the second malicious file?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FK1KjEooEfoA3Ggvu3jej%2FScreenshot%202025-10-06%20at%206.53.57%E2%80%AFPM.png?alt=media&#x26;token=ad7d7ca0-d093-4031-adb4-08689b51b3cb" alt=""><figcaption></figcaption></figure>

Answer **`758e07113016aca55d9eda2b0ffeebe`**

[**`https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/danabot/`** ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/danabot/)
