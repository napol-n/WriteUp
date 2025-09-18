# SalineBreeze-1

## Salt Typhoon Threat Intelligence Analysis Lab - Complete Writeup

### Executive Summary

This lab exercise involved conducting comprehensive threat intelligence research on Salt Typhoon, a sophisticated Advanced Persistent Threat (APT) group attributed to China. The analysis focused on mapping their tactics, techniques, and procedures (TTPs) to the MITRE ATT\&CK framework and identifying actionable intelligence for defensive operations.

### Lab Scenario

**Role**: Junior Threat Intelligence Analyst at a cybersecurity firm\
**Mission**: Investigate Salt Typhoon cyber espionage campaign due to budget cuts requiring expanded responsibilities\
**Objective**: Conduct comprehensive research focusing on TTPs and provide actionable insights using MITRE ATT\&CK framework

### Question-by-Question Analysis

#### 1. Attribution and State Sponsorship

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FC6lRJf6VpHgVrWHMBzxG%2FScreenshot%202025-09-18%20at%206.24.17%E2%80%AFPM.png?alt=media&#x26;token=f2895616-d0a2-4c90-a6e2-64abc22ce243" alt=""><figcaption></figcaption></figure>

**Question**: Which country is thought to be behind Salt Typhoon?\
**Answer**: China\
**Analysis**: According to MITRE ATT\&CK Group G1045, Salt Typhoon is attributed to the People's Republic of China (PRC), indicating state-sponsored cyber espionage activities.

#### 2. Operational Timeline

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FqFXfkbDqhzAgIaU0DAYh%2FScreenshot%202025-09-18%20at%206.25.03%E2%80%AFPM.png?alt=media&#x26;token=d4ffa68d-2cf6-4ded-9326-224f708f5557" alt=""><figcaption></figcaption></figure>

**Question**: Salt Typhoon has been active since at least when? (Year)\
**Answer**: 2019\
**Analysis**: The threat group has maintained persistent operations for over 5 years, demonstrating sustained intelligence collection capabilities and long-term strategic objectives.

#### 3. Target Infrastructure

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FxSSbsXqYcLJSBCq8jmAk%2FScreenshot%202025-09-18%20at%206.26.16%E2%80%AFPM.png?alt=media&#x26;token=24a750e0-f59a-4c9b-ad18-1936fcf5542e" alt=""><figcaption></figcaption></figure>

**Question**: What kind of infrastructure does Salt Typhoon target?\
**Answer**: Network infrastructure\
**Analysis**: The group specifically focuses on telecommunications infrastructure, targeting network devices, routers, firewalls, and VPN gateways to establish persistent access for intelligence collection.

#### 4. Custom Malware Identification

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FXaOgTanbVMglGIzgKq7L%2FScreenshot%202025-09-18%20at%206.26.56%E2%80%AFPM.png?alt=media&#x26;token=f22fc905-f7e1-4f70-a2a3-c0c7086b3baf" alt=""><figcaption></figcaption></figure>

**Question**: What is the name of the malware associated with ID S1206?\
**Answer**: JumbledPath\
**Analysis**: JumbledPath represents one of several custom-built malware tools in Salt Typhoon's arsenal, demonstrating their sophisticated development capabilities.

#### 5. Malware Target Platform

**Question**: What operating system does JumbledPath target?\
**Initial Answer**: Windows (incorrect)\
**Correct Answer**: Linux\
**Analysis**: JumbledPath is an ELF file compiled for x86-64 architecture, specifically designed for Linux systems, particularly targeting Cisco network devices.

#### 6. Programming Language

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F82rqyO0NML8LTARP5Puc%2FScreenshot%202025-09-18%20at%206.34.50%E2%80%AFPM.png?alt=media&#x26;token=3fefd37c-91dd-43c7-834b-c53ddb597ef4" alt=""><figcaption></figcaption></figure>

**Question**: What programming language is JumbledPath written in?\
**Initial Answer**: C++ (incorrect)\
**Correct Answer**: Go\
**Analysis**: The malware is developed in Go programming language, which provides cross-platform compatibility and efficient network operations for the group's objectives.

#### 7. Network Sniffing Capabilities

**Question**: On which vendor's devices does the malware act as a network sniffer?\
**Answer**: Cisco\
**Analysis**: JumbledPath specifically targets Cisco devices, including Cisco Nexus switches, for packet capture and network traffic interception.

#### 8. MITRE ATT\&CK Technique Mapping - Indicator Removal

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhFP9Hel9yAexJ3OjeLs7%2FScreenshot%202025-09-18%20at%206.36.39%E2%80%AFPM.png?alt=media&#x26;token=71f3a20d-f572-4262-af76-08f5f0e20e18" alt=""><figcaption></figcaption></figure>

**Question**: What is the MITRE ATT\&CK ID for Indicator Removal (erasing logs)?\
**Initial Answer**: T1070.001 (incorrect)\
**Correct Answer**: T1070.002\
**Analysis**: The specific technique for log deletion/tampering maps to T1070.002 - File Deletion, which is part of the broader Indicator Removal category.

#### 9. CVE Exploitation - Sophos Firewall

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhKktvLsfKQolfv9dluDl%2FScreenshot%202025-09-18%20at%206.37.59%E2%80%AFPM.png?alt=media&#x26;token=2b4f9597-378f-422c-8765-24881a8f8d2e" alt=""><figcaption></figcaption></figure>

**Question**: What was the CVE for the vulnerability related to the Sophos Firewall? (from Picus Security blog, December 20, 2024)\
**Answer**: CVE-2022-3236\
**Analysis**: This vulnerability exploitation demonstrates Salt Typhoon's ability to leverage known security flaws in network appliances for initial access.

#### 10. Registry Persistence - Crowdoor Backdoor

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FDCpIOFTJD9vIdPRcLLDl%2FScreenshot%202025-09-18%20at%206.46.05%E2%80%AFPM.png?alt=media&#x26;token=e9bb86b9-f8c4-48c3-ad74-cd35630bf56c" alt=""><figcaption></figcaption></figure>

**Question**: Which registry key do they target for Crowdoor persistence?\
**Initial Answers**:

* HKLM\Software\Microsoft\Windows\CurrentVersion\Run (incorrect)

**Correct Answer**: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
**Analysis**: The user-specific registry hive (HKCU) is targeted for persistence, ensuring the backdoor executes when the specific user logs in, providing stealth and user-context execution.

#### 11. MITRE ATT\&CK Technique - Registry Modification

**Question**: What is the MITRE ATT\&CK ID for the registry modification technique?\
**Answer**: T1112\
**Analysis**: This technique represents Modify Registry, a common persistence mechanism used by advanced threat actors.

#### 12. Threat Group Naming Convention

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FDskRZ19B73iLICp6EawK%2FScreenshot%202025-09-18%20at%206.49.15%E2%80%AFPM.png?alt=media&#x26;token=7e2f0bda-ad6b-4c13-a514-ad9ba9372052" alt=""><figcaption></figcaption></figure>

**Question**: What name does TrendMicro use to refer to the group? (November 25, 2024 blog)\
**Answer**: Earth Estries\
**Analysis**: Different security vendors use various naming conventions for the same threat group, demonstrating the importance of threat intelligence correlation across sources.

#### 13. Multi-Modular Backdoor Identification

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FuWeH0km3VC9XBKny5ywT%2FScreenshot%202025-09-18%20at%206.50.07%E2%80%AFPM.png?alt=media&#x26;token=ab4f0b73-59a6-4cf0-baae-676b58b41b04" alt=""><figcaption></figcaption></figure>

**Question**: Which malware is described as a 'multi-modular backdoor using a custom protocol protected by TLS'?\
**Initial Answer**: Crowdoor (incorrect)\
**Correct Answer**: GHOSTSPIDER\
**Analysis**: GHOSTSPIDER represents a sophisticated backdoor with modular architecture and encrypted communications, indicating advanced development capabilities.

#### 14. Command and Control Infrastructure

**Question**: What is the full domain name for the .dev TLD used by the malware?\
**Answer**: telcom.grishamarkovgf8936.workers.dev\
**Analysis**: The use of Cloudflare Workers domain suggests leveraging legitimate services for C2 infrastructure to evade detection.

#### 15. Initial C2 Communication

**Question**: What is the filename for the first GET request to the C\&C server?\
**Correct Answer**: index.php\
**Analysis**: The use of common web file extensions helps blend malicious traffic with legitimate web requests.

#### 16. Historical Threat Group Names

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FmSMedq76Ogq3kQe8oT31%2FScreenshot%202025-09-18%20at%207.10.43%E2%80%AFPM.png?alt=media&#x26;token=3422a144-f934-496c-923d-5e5985877bbd" alt=""><figcaption></figcaption></figure>

**Question**: What was the threat actor's name in the Kaspersky blog (September 30, 2021)?\
**Answer**: GhostEmperor\
**Analysis**: This demonstrates the evolution of threat group tracking and naming across different time periods and security vendors.

#### 17. Historical Malware Analysis

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FqycPDGBxhUrdwOouZdpe%2FScreenshot%202025-09-18%20at%207.48.59%E2%80%AFPM.png?alt=media&#x26;token=3cd7cd07-f89e-41dc-bd7b-cb2c10fffade" alt=""><figcaption></figcaption></figure>

**Question**: What is the name of the malware that the Kaspersky article focuses on?\
**Answer**: Demodex\
**Analysis**: Demodex represents an earlier iteration of the group's malware toolkit, showing evolution in their capabilities.

#### 18. Malware Classification

**Question**: What type of malware is Demodex?\
**Answer**: Rootkit\
**Analysis**: Kernel-mode rootkits represent sophisticated malware designed for stealth and persistence at the operating system level.

#### 19. Code Obfuscation Technique

**Question**: What type of encryption is used in the PowerShell dropper?\
**Initial Answer**: Base64 (incorrect)\
**Correct Answer**: AES\
**Analysis**: Advanced Encryption Standard (AES) usage demonstrates sophisticated obfuscation techniques beyond simple encoding methods.

#### 20. IOCTL Code for Service Hiding

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FAd6nqvAk36yt1Nd6m6zo%2FScreenshot%202025-09-18%20at%207.15.51%E2%80%AFPM.png?alt=media&#x26;token=7ccd95be-9496-4334-9a57-f73fb38f4068" alt=""><figcaption></figcaption></figure>

**Question**: What is the IOCTL code used to hide services within services.exe?\
**Initial Answer**: 0x80102010 (incorrect)\
**Correct Answer**: 0x220300\
**Analysis**: Input/Output Control codes enable direct kernel-level manipulation for hiding malicious artifacts from detection tools.

### Key Findings and Threat Assessment

#### Threat Actor Profile

* **Attribution**: People's Republic of China (state-sponsored)
* **Active Since**: 2019 (5+ years of operations)
* **Primary Targets**: Telecommunications and network infrastructure
* **Sophistication Level**: High (custom malware, kernel rootkits, advanced obfuscation)

#### Technical Capabilities

* **Custom Malware Development**: JumbledPath, GHOSTSPIDER, Crowdoor, Demodex
* **Multi-Platform Support**: Linux (network devices) and Windows (endpoints)
* **Advanced Persistence**: Registry modification, kernel rootkits, service hiding
* **Network Operations**: Packet sniffing, C2 infrastructure, encrypted communications

#### MITRE ATT\&CK Mapping Summary

* **T1070.002**: Indicator Removal - File Deletion
* **T1112**: Modify Registry
* **T1190**: Exploit Public-Facing Application (CVE-2022-3236)
* **T1014**: Rootkit (Demodex)
* **T1027**: Obfuscated Files or Information (AES encryption)

### Conclusion

Salt Typhoon represents a persistent, well-resourced threat actor with sophisticated capabilities spanning multiple platforms and attack vectors. Their focus on telecommunications infrastructure poses significant risks to critical communications systems. The analysis reveals a threat group that has evolved over time, adapting their tools and techniques while maintaining consistent targeting patterns.

The comprehensive mapping to MITRE ATT\&CK framework provides actionable intelligence for defensive operations, enabling organizations to prioritize security controls and detection capabilities against this specific threat. Regular threat intelligence updates and proactive hunting operations are essential for defending against such advanced persistent threats.

### Sources and References

* MITRE ATT\&CK Group G1045 (Salt Typhoon)
* CISA Advisory on Salt Typhoon
* Picus Security Blog (December 20, 2024)
* TrendMicro Earth Estries Analysis (November 25, 2024)
* Kaspersky GhostEmperor Report (September 30, 2021)

<https://labs.hackthebox.com/achievement/sherlock/2521593/979>
