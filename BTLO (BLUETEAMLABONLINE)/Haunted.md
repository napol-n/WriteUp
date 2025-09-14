---
description: >-
  One of the company's websites has been defaced, raising alarms. Collaborate
  with other analysts to uncover the identity of the adversary and assess the
  situation.Scenario Scenario Haunted Company Inc.
---

# Haunted

**Scenario**\
Haunted Company Inc., a long-established Credit Reporting Agency, has been successfully operating in major financial hubs such as New York, London, and Tokyo. As a privately owned entity without external investors, the company has maintained consistent client satisfaction and steady earnings reports. With plans for expansion, the management has decided to take the company public, and the Initial Public Offering (IPO) is scheduled to occur within the next few days.

However, a crisis emerged just as the IPO date approaches. One of the company's websites has been defaced, raising alarms. Shortly after, it is discovered that the company's Tokyo server has come under attack. Concerned about the timing and the potential damage to the company’s reputation, the management is determined to identify the threat actor behind this attack and understand the breach mechanism to create detection before the IPO.

As a Threat Intelligence Analyst, you are tasked with collaborating with other analysts to uncover the identity of the adversary and assess the situation.

Available External and Internal Threat Intelligence:

New York(External: Business Commonality): Report on the 2017 GenX Breach, a major cyber attack on a leading Credit Reporting Agency. London(Internal Intelligence: Adversary Analysis): Analysis report for Haunted Company Inc., including Asset-Threat Mapping and adversary analysis featuring FIN7, APT27, Twisted Spider, and TG-3390, all of which are known to target the finance sector. Tokyo(Cyber Activity Attribution): Malware analysis from the compromised server, providing critical insights into the tools used during the attack.



### Overview

This investigation focuses on a cyberattack against Haunted Company Inc., a Credit Reporting Agency preparing for an Initial Public Offering (IPO). The company's website was defaced and their Tokyo server was compromised, creating significant reputational risk just days before going public.

### Lab Setup

Upon deploying the investigation machine, we find an "Investigation" folder on the desktop containing:

* `README.txt` - Scenario description and HTML link
* `DecodeME.txt` - Base64 encoded strings

The investigation requires:

1. Decoding the base64 content from `DecodeME.txt`
2. Submitting the decoded HTML to complete the threat intelligence interface
3. Analyzing three threat intelligence reports from New York, London, and Tokyo

### Investigation Questions and Solutions

#### Q1: In 2017, a well-known company was attacked. What is the name of the company, its country of origin, and its business model?



<div><figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FeaU5uWUUTcTErDliQqlJ%2FScreenshot%202025-09-14%20at%202.41.22%E2%80%AFPM.png?alt=media&#x26;token=16461a83-0992-426e-a7e4-2ad4f3d986f7" alt=""><figcaption></figcaption></figure> <figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FHPRWFxgYHqA4rt7lOmp3%2FScreenshot%202025-09-14%20at%202.42.15%E2%80%AFPM.png?alt=media&#x26;token=2f5f7967-15f0-48ac-b395-66d30ae69bd2" alt=""><figcaption></figcaption></figure></div>

**Analysis:** From the London intelligence report discussing the 2017 GenX breach, we can identify:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FcxI8GWV8ScN5XKSLJvKe%2FScreenshot%202025-09-14%20at%202.43.59%E2%80%AFPM.png?alt=media&#x26;token=e0af2429-a579-48f0-ab61-fbbe2529cfe3" alt=""><figcaption></figcaption></figure>

* Company: GenX Financial
* Country: United States (US)
* Business Model: Credit Reporting Agency

**Answer:** `GenX Financial, US, Credit Reporting Agency`

***

#### Q2: Vulnerability Type

**Question:** According to the data breach summary, one of their critical assets was compromised, and they later discovered a vulnerability in one of their public-facing applications. What type of weakness was exploited?

**Analysis:** The breach summary indicates that attackers exploited a weakness in a public-facing application. This refers to application-level vulnerabilities that allowed network compromise.

**Answer:** `Application Vulnerability`

***

#### Q3: Detection Timeline

**Question:** How long did this breach go undetected? What was the Mean Time to Detect (MTTD)?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FM6HoGzovgcz9VYRsi2rM%2FScreenshot%202025-09-14%20at%202.52.50%E2%80%AFPM.png?alt=media&#x26;token=2ccc5190-dbb9-471f-b6a7-32cd3336b188" alt=""><figcaption></figcaption></figure>

**Analysis:** From the incident scope documentation: "The GenX Financial breach lasted for 76 days, during which attackers infiltrated 48 unrelated databases."

**Answer:** `76 days`

***

#### Q4: Target Application and Vulnerability

**Question:** What application was targeted by the attacker? What vulnerability was exploited, and where is this application located within the network?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FunINrhppuFViRAl7s2ZA%2FScreenshot%202025-09-14%20at%202.56.43%E2%80%AFPM.png?alt=media&#x26;token=ce468709-6078-4471-bb90-10c8970c308f" alt=""><figcaption></figcaption></figure>

**Analysis:** From the executive summary and incident scope:

* Application: Apache Struts (web application framework)
* Vulnerability: CVE-2017-5638 (publicly disclosed in March 2017)
* Location: ACIS (internal system environment)

The report specifically mentions "exploiting the Apache Struts vulnerability" and later references the ACIS environment.

**Answer:** `Apache Struts, CVE-2017-5638, ACIS`

***

#### Q5: Data Exfiltration Scale and Method

**Question:** The attackers exfiltrated millions of records. How many consumer details were estimated to be exposed? How, and through which channel, was the data exfiltrated?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FZwFoeQpwiH6TWeRBRHKq%2FScreenshot%202025-09-14%20at%202.59.27%E2%80%AFPM.png?alt=media&#x26;token=ccb0eed3-812c-4d07-ab5a-13f13c8d192a" alt=""><figcaption></figcaption></figure>

**Analysis:** From the executive summary: "Nearly 150 million people's personal and financial information was stolen" From the technical details: The data was exfiltrated through encrypted network traffic, which went undetected due to expired SSL certificates affecting monitoring capabilities.

**Answer:** `150, Encrypted`

***

#### Q6: ACIS Code Vulnerabilities

**Question:** Later, during the investigation, a flaw was discovered in their ACIS code rendering system. What were these flaws?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FrxTppxpAJBxvB6s9GzX2%2FScreenshot%202025-09-14%20at%203.01.20%E2%80%AFPM.png?alt=media&#x26;token=08706601-c6d9-4d17-9134-b22e53ae64e9" alt=""><figcaption></figcaption></figure>

**Analysis:** From the July 30, 2017 investigation notes: "GenX Financial discovered flaws in the ACIS code rendering the system vulnerable to SQL injection and Insecure Direct Object Reference attacks."

**Answer:** `SQL Injection, Insecure Direct Object Reference`

***

#### Q7: Malicious File and Origin Country

**Question:** What file was inserted during the attack, and which country did the attack originate from?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F4DSPMCs2sOwsN82koHp7%2FScreenshot%202025-09-14%20at%203.03.22%E2%80%AFPM.png?alt=media&#x26;token=68046764-e902-4fb1-8f04-0dc901e04fdb" alt=""><figcaption></figcaption></figure>

**Analysis:** From the July 31, 2017 investigation notes:

* File type: "The team had identified an unexpected JSP file inserted into the ACIS application"
* Country: "suspicious traffic originating from a second IP address owned by a German ISP but leased to a Chinese provider"

**Answer:** `JSP, China`

***

#### Q8: Missing Security Control

**Question:** It is said that if a specific network security technique had been properly implemented, the attacker likely would have failed to accomplish their mission. What is this technique called?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhVfhUOhgI60ePOJWQybD%2FScreenshot%202025-09-14%20at%203.04.17%E2%80%AFPM.png?alt=media&#x26;token=8090495b-f17c-4663-8d97-34a8a1e09c3e" alt=""><figcaption></figcaption></figure>

**Analysis:** From the vulnerability assessment: "Improper Network Segmentation Practice: The attackers were able to move from the web portal to other servers because the systems weren't adequately segmented from one another"

**Answer:** `Network Segmentation`

***

#### Q9: First Threat Group Analysis

**Question:** Adversary Analysis, this one group in particular as being involved in numerous attacks, including an attack on a medical research company during COVID-19. What is the name of this threat group (according to MITRE), what threat vector do they use, what is their country of origin, and what is their motivation?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FqFbSbAtjVEaiTi4O6rH9%2FScreenshot%202025-09-14%20at%203.16.14%E2%80%AFPM.png?alt=media&#x26;token=e5c12765-4a31-4099-880a-59b835bc02f9" alt=""><figcaption></figcaption></figure>

**Analysis:** From the FIN7 adversary analysis document:

* Group: FIN7 (also known as Carbon Spider, Twisted Spider, Viking Spider, Storm-0216)
* Threat Vector: Ransomware (including Egregor, Maze, and REvil)
* Origin: Russia (Russian-speaking threat group, possibly residing in Europe)
* Motivation: Financial gain
* Notable: Attacked Hammersmith Medicines Research during COVID-19 vaccine trials in March 2020

**Answer:** `FIN7, Ransomware, Russia, Financial`

***

#### Q10: Second Threat Group Analysis

**Question:** Investigating the other threat group. What is the APT number assigned to this group? What is the name of the specific operation that involved dropping web shells on SharePoint servers? In what year was this group first observed, and what is their possible motivation?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F1qmLSuVls3akOFUrBt0k%2FScreenshot%202025-09-14%20at%203.18.56%E2%80%AFPM.png?alt=media&#x26;token=185584d6-b2c2-4b30-9dd3-d2161d458dca" alt=""><figcaption></figcaption></figure>

**Analysis:** From the APT27 adversary analysis document:

* APT Number: APT27 (also known as Threat Group-3390, Iron Tiger)
* SharePoint Operation: "SharePoint Server Compromise" (April 2019)
* First Observed: 2010 with "Operation Iron Tiger"
* Motivation: Espionage

**Answer:** `APT27, SharePoint Server Compromise, 2010, Espionage`

***

#### Q11: Tokyo Attack Vectors

**Question:** Haunted Company Inc. in Tokyo is under cyber attack. Based on the IOCs that were provided (hint: BAT!), what attack vectors did the threat actor use?

**Analysis:** Based on the IOCs and the hint about "BAT!" (likely referring to batch files or social engineering techniques), the attack vectors used were:

* Social Engineering: Used to gain initial access
* Webshell: Used for persistence and remote control

**Answer:** `Social Engineering, Webshell`

***

#### Q12: Shellcode Analysis

**Question:** One of the IOCs contains shellcode. Use a tool and review the output to identify the offset of the PEB (Process Environment Block). (Hint: Output + OSINT!)

**Analysis:** This requires analyzing shellcode from the Tokyo IOCs. The Process Environment Block (PEB) offset in Windows shellcode analysis typically appears at a standard offset. Based on common Windows shellcode patterns and PEB structure analysis.

**Answer:** `0x30`

***

#### Q13: Attack Attribution

**Question:** Based on the intelligence gathered, which threat group was responsible for the cyberattack on Haunted Company Inc.? What is the name of the malware they used to compromise Tokyo's infrastructure?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fx8cZubmyrPRzwKNSajDA%2FScreenshot%202025-09-14%20at%207.49.15%E2%80%AFPM.png?alt=media&#x26;token=43a8627c-582f-4e5c-8b33-0af6fdf3fff6" alt=""><figcaption></figcaption></figure>

**Analysis:** From the adversary analysis and correlation with the attack patterns:

* Threat Group: Threat Group-3390 (also known as APT27)
* Malware: ChinaChopper (web-based executable script/webshell)
* Evidence: The use of webshells, Chinese origin, and targeting patterns match TG-3390's historical operations

**Answer:** `Threat Group-3390, ChinaChopper`

***

#### Q14: Current Vulnerability Assessment

**Question:** Referring to the Asset-Threat Diagram which is an integral part of building intelligence, It appears the attacker exploited a vulnerability in Tokyo's infrastructure. What is the latest CVE for the version the threat actor targeted, and what type of attack was it?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FXnatIx5ShtUTD337THuq%2FScreenshot%202025-09-14%20at%207.20.35%E2%80%AFPM.png?alt=media&#x26;token=a2f35742-af04-4887-bb67-35aa90fd91d9" alt=""><figcaption></figcaption></figure>

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FYB8lSiUk24zgMeXTFbNA%2FScreenshot%202025-09-14%20at%207.22.53%E2%80%AFPM.png?alt=media&#x26;token=8b21136d-0339-4fbd-9604-5a92a2a228d5" alt=""><figcaption></figcaption></figure>

**Analysis:** From the Asset-Threat Diagram showing:

* Apache Struts 2 Version 6.3.0 (Public Facing)
* The latest critical vulnerability for this version is CVE-2023-50164
* Attack Type: RCE (Remote Code Execution)

**Answer:** `CVE-2023-50164, RCE`

***

### Key Takeaways

This investigation demonstrates several critical cybersecurity concepts:

1. **Attribution Challenges**: Multiple threat groups with overlapping TTPs require careful analysis
2. **Timeline Analysis**: Understanding MTTD and breach duration is crucial for impact assessment
3. **Vulnerability Management**: Unpatched systems create significant risk exposure
4. **Network Segmentation**: Proper segmentation could have limited lateral movement
5. **Intelligence Correlation**: Combining multiple intelligence sources provides better attribution confidence

### Tools and Techniques Used

* Base64 decoding for intelligence gathering
* IOC analysis and correlation
* Threat actor attribution methodology
* Vulnerability research and CVE analysis
* Shellcode analysis techniques
* OSINT (Open Source Intelligence) gathering
