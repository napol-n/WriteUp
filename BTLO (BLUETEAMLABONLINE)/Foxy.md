---
description: >-
  As an Intelligence Analyst you are tasked with assisting the SOC Analysts with
  their investigations, providing additional context and information.
---

# Foxy

## Foxy SOC Investigation Lab - Complete Walkthrough

#### Scenario

As an Intelligence Analyst you are tasked with assisting the SOC Analysts with their investigations, providing additional context and information.

We recommend using Gnumeric to open CSV files, or use linux CLI commands from within the exports folder.

### Overview

As an Intelligence Analyst, you are tasked with assisting SOC Analysts with their investigations, providing additional context and information. This lab involves analyzing various threat intelligence data from multiple CSV export files to investigate malicious network activity.

#### Lab Environment

* **Tools**: Linux CLI, Gnumeric
* **Files**: full\_urls.csv, full\_ip-port.csv, Recent Additions.csv, SHA256 Hashes.csv
* **Focus Areas**: OSINT, BTL1, T1204.002 (User Execution: Malicious File), T1566 (Phishing)

### Initial Investigation - Cobalt Strike Activity

#### Question 1: Network Connection Analysis

**Scenario**: The SOC recently observed network connections from 3 internal hosts towards `hxxp://45.63.126[.]199/dot.gif` (URL has been sanitized). What is this activity likely related to?

**Analysis**: The observed activity indicates:

* Multiple internal hosts connecting to external URL with .gif extension
* IP address instead of domain name suggests malicious C2 communication
* Pattern consistent with malware beaconing behavior

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FFeDfkKlE5cgLr94Il2MM%2FScreenshot%202025-09-16%20at%2011.20.56%E2%80%AFPM.png?alt=media&#x26;token=a8fc07ed-5cdf-4d2c-aaa0-dc1ba3f56c12" alt=""><figcaption></figcaption></figure>

**Answer**: **Cobalt Strike**

This activity is characteristic of Cobalt Strike C2 (Command & Control) beaconing, where infected hosts periodically contact external servers to receive commands or exfiltrate data.

#### MITRE ATT\&CK Mapping:

* T1071.001 – Application Layer Protocol: Web Protocols (HTTP/HTTPS)
* T1204.002 – User Execution: Malicious File
* T1566 – Phishing (if initial infection vector)

***

### Question 2: URL Endpoint Analysis

**Question**: How many URLs are using the same endpoint 'dot.gif', across all export files? (include duplicates)

**Method**:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F3ebTDrPzDIAhvzX7c3qt%2FScreenshot%202025-09-16%20at%2011.34.21%E2%80%AFPM.png?alt=media&#x26;token=1cfc50f4-9a5e-4e3a-8df5-8c6edccd74d6" alt=""><figcaption></figcaption></figure>

```bash
# Check Recent Additions.csv
grep -i "dot.gif" "Recent Additions.csv" | wc -l
# Result: 4

# Check full_urls.csv
grep -i "dot.gif" full_urls.csv | wc -l
# Result: 564

# Total calculation
4 + 564 = 568
```

**Answer**: **568**

***

### Malware Hash Analysis

#### Question 3: SHA256 Hash Investigation

**Question**: The SHA256 hash of a file was detected and quarantined on one of the Executive's old Android phones. The hash value is `6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5`. Is this file associated with malware? If so, what is the malware name? (as stated by Malware Bazaar)

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F2WfK3aHQLRwDUKvikpDp%2FScreenshot%202025-09-16%20at%2011.39.29%E2%80%AFPM.png?alt=media&#x26;token=35ec2c2d-9f43-40b3-a11f-c8b37a47697a" alt=""><figcaption></figcaption></figure>

**Analysis**: From the ThreatFox/Malware Bazaar data:

* File type: Android APK
* Malware family: IRATA (Iranian Remote Access Tool)
* File name: سکس‌چت‌تصویری.apk ("sex chat image.apk")
* Detection: 7 vendors flagged as malicious
* Confidence: 100%

**Answer**: **IRATA**

#### Question 4: Threat Intelligence Deep Dive

**Question**: Investigate the reference link for this SHA256 hash value. Submit the threat name (acronym only), the C2 domain, IP, and the domain registrar.

**Reference Analysis**: From OneCert Cyber Security report:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FxlecfnT0MWAGGBeueEtP%2FScreenshot%202025-09-16%20at%2011.44.19%E2%80%AFPM.png?alt=media&#x26;token=210a714d-69ce-40eb-8cd1-8dd9fb50b5de" alt=""><figcaption></figcaption></figure>

```
#Malware Alert
File type: #Apk #Android
Threat name: #IRATA #spyware
(IRATA - Iranian Remote Access Tool Android)
- C&C: uklivemy.gq
- IP: 20.238.64.240
- ISP: Azure/Microsoft
- Registrar: freenom
```

**Answer**: **IRATA,uklivemy.gq,20.238.64.240,freenom**

***

### MITRE ATT\&CK Collection Analysis

#### Question 5: Joe Sandbox Analysis

**Question**: Visit https://www.joesandbox.com/analysis/1319345/1/html. Investigate the MITRE ATT\&CK Matrix to understand the Collection activities this file can take. Submit the 5 Technique names in alphabetical order.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FKOKXi2WlUIJwHkII5aBc%2FScreenshot%202025-09-16%20at%2011.51.23%E2%80%AFPM.png?alt=media&#x26;token=51576fe4-625a-4671-a48c-61a6de6283e0" alt=""><figcaption></figcaption></figure>

**Analysis**: From Joe Sandbox MITRE ATT\&CK Matrix, the Collection techniques identified:

1. **Access Contact List** - Steals contact information
2. **Access Stored Application Data** - Accesses app data
3. **Capture SMS Messages** - Intercepts text messages
4. **Location Tracking** - Monitors device location
5. **Network Information Discovery** - Gathers network details

**Answer**: **Access Contact List,Access Stored Application Data,Capture SMS Messages,Location Tracking,Network Information Discovery**

#### Impact on Executive's Mobile Phone:

* **Data Exfiltration**: Personal and business contacts, SMS messages
* **Location Surveillance**: Continuous tracking of executive's movements
* **Application Data Access**: Sensitive app information including credentials
* **Privacy Breach**: Complete compromise of mobile privacy

***

### AdWind RAT Investigation

#### Question 6: IP Address and Ports

**Question**: A junior analyst was handling an event that involved outbound connections to a private address and didn't perform any further analysis on the IP. What are the two ports used by the IP 192.236.198.236?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FEQNT8ZxLJNqWGKoNEuui%2FScreenshot%202025-09-16%20at%2011.59.42%E2%80%AFPM.png?alt=media&#x26;token=2906de87-79f2-4094-bd5c-426360c2f8d9" alt=""><figcaption></figcaption></figure>

**Answer**: **1505,1506**

#### Question 7: C2 Domain Investigation

**Question**: Use the reference to help you further research the IP. What is the C2 domain?

<div><figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fvsf8YB5zVloFWCpBRdLF%2FScreenshot%202025-09-17%20at%2012.01.38%E2%80%AFAM.png?alt=media&#x26;token=24de93a9-30b0-47b9-bd61-c3de4eafc6d8" alt=""><figcaption></figcaption></figure> <figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FvPicaKGTRInP2rvUMOvC%2FScreenshot%202025-09-17%20at%2012.02.48%E2%80%AFAM.png?alt=media&#x26;token=560c8762-2a7b-45dc-bf0a-c46e95f92d59" alt=""><figcaption></figcaption></figure></div>

**Analysis**: From reference URL https://x.com/ddash\_ct/status/1560660561586982912:

* AdWind RAT packer sequence identified
* C2 domain: ianticrish.tk
* Ports: 1505 and 1506
* Version: ADIT SOURCE v1\_077
* Network password: 79686d0315cf2364f63dcb5979c7714d4f9969a3

**Answer**: **ianticrish.tk**

#### Question 8: Delivery Method Analysis

**Question**: What is the likely delivery method into our organization? Provide the Technique name and Technique ID from ATT\&CK.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FDfvAUTgdHAtWJ7YW3ygg%2FScreenshot%202025-09-17%20at%2012.05.03%E2%80%AFAM.png?alt=media&#x26;token=9f40ba5f-62f2-4e8d-8b2b-d3f7b274c53a" alt=""><figcaption></figcaption></figure>

**Analysis**: AdWind RAT typically delivered via phishing emails with malicious attachments that users execute.

**Answer**: **Phishing, T1566**

#### Question 9: Weaponized Document

**Question**: Investigate further and try to find the name of the weaponized Word document, so we can use our EDR to check if it is present anywhere else within the organization.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FW77gkrFWRAb5UnMDtiaH%2FScreenshot%202025-09-17%20at%2012.15.23%E2%80%AFAM.png?alt=media&#x26;token=01f78644-98a7-49f5-8ba0-742f004771ab" alt=""><figcaption></figcaption></figure>

**Analysis**: From MalwareBazaar reference with SHA256: 03265b3f9c94dc5e6bcb827c70638b786ac3023f91a3669978552318af5ebca5:

**Answer**: **08.2022 pazartesi sipari#U015fler.docx**

#### Question 10: JAR File Analysis

**Question**: What is the name of the .JAR file dropped by the Word document?



**Analysis**: From Joe Sandbox analysis (https://www.joesandbox.com/analysis/680865/0/irxml):

* The weaponized Word document drops a JAR file
* Path: `C:\Users\user\AppData\Local\Temp\NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR`

**Answer**: **NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.JAR**

***

### Discord CDN Abuse Investigation

#### Question 11: Discord CDN URL

**Question**: Executives have expressed concern about allowing employees to visit Discord on the corporate network because of online reports that it can be used for malware delivery and data exfiltration. What is the URL of the Discord CDN, ending with /attachments/?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FZIPx9KZg5WhnQDHFsCui%2FScreenshot%202025-09-17%20at%2012.16.01%E2%80%AFAM.png?alt=media&#x26;token=567bc287-64b9-4299-a222-4df575a567cf" alt=""><figcaption></figcaption></figure>

**Analysis**: Discord's Content Delivery Network (CDN) is commonly abused by threat actors for:

* Hosting malicious payloads
* Data exfiltration via webhooks
* Distributing malware disguised as legitimate files

**Answer**: **https://cdn.discordapp.com/attachments/**

#### Question 12: Discord URL References

**Question**: Looking at all export files, how many rows reference this URL? (include duplicates)

**Method**:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FoCywUBtrMyeZ7CcuxO0x%2FScreenshot%202025-09-17%20at%2012.29.19%E2%80%AFAM.png?alt=media&#x26;token=958ebc9c-3daf-4d79-91b5-8aa13cd513dc" alt=""><figcaption></figcaption></figure>

```bash
grep -c https://cdn.discordapp.com/attachments ./full_urls.csv
```

**Answer**: **565**

#### Question 13: Discord Malware Distribution

**Question**: Based on this information, what is the name of the malware family that is being widely distributed via Discord?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fe1atKsKrZAl4KtUBW567%2FScreenshot%202025-09-17%20at%2012.36.48%E2%80%AFAM.png?alt=media&#x26;token=88faedcc-29ba-43e1-a1cc-9322ab35b7ec" alt=""><figcaption></figcaption></figure>

**Analysis**: From the threat intelligence data, Dridex banking trojan is frequently distributed via Discord CDN.

**Answer**: **Dridex**

***

### Threat Intelligence Confidence Analysis

#### Question 14: High Confidence Indicators

**Question**: When it comes to blocking indicators, it is crucial that they are from a reputable source and have a high level of confidence. How many rows in the full\_urls.csv have a confidence rating of 100, and would likely be safe to block on the web proxy?

**Method**: Using Gnumeric spreadsheet analysis:

1. Total rows in confidence column: 56,732
2. Rows with confidence 25, 50, 75: 16,740
3. Calculation: 56,732 - 16,740 = 39,992

**Answer**: **39,992**

***

### Log4Shell Vulnerability Investigation

#### Question 15: Unknown Malware Analysis

**Question**: An analyst has reported activity coming from an IP address using source port 8001. Looking at full\_ip-port.csv in Gnumeric, filter on malware\_printable = Unknown malware, and find an IP that is using port 8001. What is the IP address value?

**Method**:

1. Open full\_ip-port.csv in Gnumeric
2. Apply filter: malware\_printable = "Unknown malware"
3. Search for port 8001

**Answer**: **107.172.214.23**

#### Question 16: CVE Investigation

**Question**: Investigating the reference material, what is the CVE ID of the vulnerability that this IP has been trying to exploit? And what is the industry nickname for this vulnerability?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fq0qmtyIJfOiQIInlTJ59%2FScreenshot%202025-09-17%20at%2012.48.40%E2%80%AFAM.png?alt=media&#x26;token=dee94df4-db63-47d1-b355-2f20a9ac5bd4" alt=""><figcaption></figcaption></figure>

**Analysis**: The IP 107.172.214.23 is attempting to exploit the Log4j vulnerability:

* **CVE ID**: CVE-2021-44228
* **Industry Nickname**: Log4Shell
* **Impact**: Remote Code Execution in Java applications using Apache Log4j

**Answer**: **CVE-2021-44228,Log4Shell**

***

### Key Takeaways

#### Security Recommendations:

1. **Immediate Actions**:
   * Isolate affected hosts with Cobalt Strike infections
   * Block identified C2 domains and IPs at firewall level
   * Scan for weaponized documents using EDR systems
2. **Detection Rules**:
   * Create SIEM rules for identified IoCs
   * Monitor for Log4Shell exploitation attempts
   * Alert on Discord CDN file downloads
3. **Prevention Measures**:
   * User education on phishing awareness
   * Endpoint protection against malicious documents
   * Network segmentation and monitoring

#### MITRE ATT\&CK Techniques Observed:

* **T1566** - Phishing
* **T1204.002** - User Execution: Malicious File
* **T1071.001** - Application Layer Protocol: Web Protocols
* **T1005** - Data from Local System
* **T1113** - Screen Capture

This comprehensive investigation demonstrates the interconnected nature of modern cyber threats and the importance of thorough threat intelligence analysis in incident response.

[https://blueteamlabs.online/achievement/share/122610/116](https://blueteamlabs.online/achievement/share/122610/116)
