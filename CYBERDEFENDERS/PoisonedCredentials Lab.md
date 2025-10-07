# PoisonedCredentials Lab

Category: [Network Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=network-forensics)

Tactics: [Credential Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=credential-access)[Collection](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=collection)

Tool: [Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=wireshark)

**Scenario**

Your organization's security team has detected a surge in suspicious network activity. There are concerns that LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning attacks may be occurring within your network. These attacks are known for exploiting these protocols to intercept network traffic and potentially compromise user credentials. Your task is to investigate the network logs and examine captured network traffic.

#### Q1 In the context of the incident described in the scenario, the attacker initiated their actions by taking advantage of benign network traffic from legitimate machines. Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F31QTco9SP2jUIEqI89B4%2FScreenshot%202025-10-04%20at%209.01.36%E2%80%AFPM.png?alt=media&#x26;token=5fab822d-3b56-4150-851d-0e267473ba07" alt=""><figcaption></figcaption></figure>

**`fileshaare`**\
(seen as `fileshaare.local` / `fileshaare` in NBNS, LLMNR, and mDNS queries)

* **Victim machine:** 192.168.232.162
* **Mistyped query:** `fileshaare`
* **Protocol used:** NBNS / LLMNR / mDNS
* **Significance:** The attacker exploited this typo (name resolution request) to intercept credentials through **LLMNR/NBT-NS poisoning**.

Answer `fileshaare`

#### Q2 We are investigating a network security incident. To conduct a thorough investigation, We need to determine the IP address of the rogue machine. What is the IP address of the machine acting as the rogue entity?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FRYC1k4NjESemxNld13EV%2FScreenshot%202025-10-04%20at%209.05.23%E2%80%AFPM.png?alt=media&#x26;token=b77685a0-3f6e-46be-962b-9e6ccdcca691" alt=""><figcaption></figcaption></figure>

The **rogue machine IP** is:

> **192.168.232.215**

**Evidence in Wireshark:**

* LLMNR/NBNS responses to victim **192.168.232.162** come from **192.168.232.215**.
* Response packets contain the queried name `fileshaare` / `fileshaare.local`.

Answer `192.168.232.215`

#### Q3 As part of our investigation, identifying all affected machines is essential. What is the IP address of the second machine that received poisoned responses from the rogue machine?

Answer `192.168.232.176`

#### Q4 We suspect that user accounts may have been compromised. To assess this, we must determine the username associated with the compromised account. What is the username of the account that the attacker compromised?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fgb1ChuVqhymD3sD9QIoq%2FScreenshot%202025-10-04%20at%209.09.47%E2%80%AFPM.png?alt=media&#x26;token=f94a5eff-7feb-4a3e-9bff-2380f8b27327" alt=""><figcaption></figcaption></figure>

`janesmith`\
(appears as `cybercactus.local\janesmith` in the NTLMSSP authentication packet)

Answer `janesmith`

#### Q5 As part of our investigation, we aim to understand the extent of the attacker's activities. What is the hostname of the machine that the attacker accessed via SMB?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhHjvZl6N0ETSKJgWlGdx%2FScreenshot%202025-10-04%20at%209.17.48%E2%80%AFPM.png?alt=media&#x26;token=b7cce0e0-c30d-48fb-a888-0a992a183274" alt=""><figcaption></figcaption></figure>

**AccountingPC** (NetBIOS: `ACCOUNTINGPC`)

Answer AccountingPC

[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/poisonedcredentials/ ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/poisonedcredentials/)
