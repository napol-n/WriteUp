# PhishNet
![Screenshot](images/Screenshot%202025-09-18%20at%2011.03.21%E2%80%AFPM.png)


## PhishNet Sherlock Challenge - Complete Writeup

### Challenge Overview

**Challenge Name:** PhishNet\
**Difficulty:** Very Easy\
**Category:** Sherlock Scenario\
**Platform:** Hack The Box

#### Scenario Description

An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Our task is to analyze the email headers and uncover the attacker's scheme.

#### Files Provided

* `email.eml` (3500 bytes) - The suspicious email file
* `PhishNet.zip` (1735 bytes) - ZIP attachment containing malware

***

### Task Solutions

#### Task 1: What is the originating IP address of the sender?

**Answer:** `45.67.89.10`

**Analysis:** To find the originating IP address, we need to examine the email headers, specifically the `X-Originating-IP` and `X-Sender-IP` headers, as well as the `Received` headers.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FvDMWkVR4PMoIoLHDOJzR%2FScreenshot%202025-09-18%20at%2012.43.02%E2%80%AFPM.png?alt=media&#x26;token=85b64c95-4c59-42db-9650-1824a0978310" alt=""><figcaption></figcaption></figure>

```bash
cat email.eml | grep -E "(X-Originating-IP|X-Sender-IP|Received)"
```

From the email headers:

```
X-Originating-IP: [45.67.89.10]
X-Sender-IP: 45.67.89.10
```

The IP address `45.67.89.10` is consistently referenced as the originating sender's IP address in multiple header fields.

***

#### Task 2: Which mail server relayed this email before reaching the victim?

**Answer:** `203.0.113.25`

**Analysis:** Looking at the `Received` headers to trace the email's path:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FqFEPTj2Yn96ZGPnNemrc%2FScreenshot%202025-09-18%20at%2012.46.32%E2%80%AFPM.png?alt=media&#x26;token=c9828900-5dea-45ff-9ba3-090f9e01b1fa" alt=""><figcaption></figcaption></figure>

```bash
cat email.eml | grep "Received:"
```

The relevant header shows:

```
Received: from mail.business-finance.com ([203.0.113.25])
        by mail.target.com (Postfix) with ESMTP id ABC123;
```

The IP address `203.0.113.25` corresponds to `mail.business-finance.com`, which is the mail server that relayed this email before it reached the victim's mail server (`mail.target.com`).

***

#### Task 3: What is the sender's email address?

**Answer:** `finance@business-finance.com`

**Analysis:** The sender's email address is found in the `From` header:

```
From: "Finance Dept" <finance@business-finance.com>
```

***

#### Task 4: What is the 'Reply-To' email address specified in the email?

**Answer:** `support@business-finance.com`

**Analysis:** The `Reply-To` header specifies where replies should be sent:

```
Reply-To: <support@business-finance.com>
```

This is a common phishing technique where the sender uses a different email address for replies, potentially to avoid detection or to use a more legitimate-sounding address for responses.

***

#### Task 5: What is the SPF (Sender Policy Framework) result for this email?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fi5aXSmM6pEDQmY6BTxrw%2FScreenshot%202025-09-18%20at%2012.48.34%E2%80%AFPM.png?alt=media&#x26;token=50294e50-e58e-4213-8b58-f43e9ec171c6" alt=""><figcaption></figcaption></figure>

**Answer:** `Pass`

**Analysis:** The SPF result is found in the `Received-SPF` header:

```
Received-SPF: Pass (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender)
```

Interestingly, the SPF check passed, which indicates that the sender's IP address (45.67.89.10) is authorized to send emails for the domain business-finance.com. This could suggest either:

1. The domain is legitimate but compromised
2. The attacker has control over the DNS records
3. This is a more sophisticated attack using a legitimate but malicious domain

***

#### Task 6: What is the domain used in the phishing URL inside the email?

**Answer:** `secure.business-finance.com`

**Analysis:** Examining the email body content, we find a suspicious link:

```html
<a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a>
```

The domain `secure.business-finance.com` is used in the phishing URL. Note that this appears to be a subdomain of the main sender domain, which is a common technique to make malicious URLs appear more legitimate.

***

#### Task 7: What is the fake company name used in the email?

**Answer:** `Business Finance Ltd.`

**Analysis:** The company name appears in the email signature:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FS8G89hyq9N7KDqfUaJap%2FScreenshot%202025-09-18%20at%2012.50.16%E2%80%AFPM.png?alt=media&#x26;token=9d6e9d42-fd8d-4f2d-b3e1-f6ce6b2af506" alt=""><figcaption></figcaption></figure>

```
Best regards,
Finance Department
Business Finance Ltd.
```

This company name is used throughout the email to establish credibility and make the phishing attempt appear legitimate.

***

#### Task 8: What is the name of the attachment included in the email?

**Answer:** `Invoice_2025_Payment.zip`

**Analysis:** The attachment name is specified in the MIME headers:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FxXwfaotyOqtIBAHtJUe4%2FScreenshot%202025-09-18%20at%2012.50.44%E2%80%AFPM.png?alt=media&#x26;token=9c05be3e-b1f7-48e8-98e1-3e6e3ae0175e" alt=""><figcaption></figcaption></figure>

```
Content-Disposition: attachment; filename="Invoice_2025_Payment.zip"
```

The filename follows a common phishing pattern - using legitimate-sounding document names related to invoices and payments to entice victims to open them.

***

#### Task 9: What is the SHA-256 hash of the attachment?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FNYOSWfhEHAiHJybZQLyo%2FScreenshot%202025-09-18%20at%2012.54.51%E2%80%AFPM.png?alt=media&#x26;token=1ea97db7-205f-4bd8-b9e2-7cc839d49878" alt=""><figcaption></figcaption></figure>

**Answer:** `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a`

**Analysis:** To calculate the SHA-256 hash of the attachment:

```bash
sha256sum PhishNet.zip
```

This hash can be used for:

* Threat intelligence lookups
* Identifying if this malware sample has been seen before
* Sharing IOCs (Indicators of Compromise) with security teams

***

#### Task 10: What is the filename of the malicious file contained within the ZIP attachment?

**Answer:** `invoice_document.pdf.bat`

**Analysis:** By extracting or examining the ZIP file contents:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FIg3PotaUNwtR2HTJPbR9%2FScreenshot%202025-09-18%20at%2012.57.29%E2%80%AFPM.png?alt=media&#x26;token=bda41054-d936-485c-ba3e-a2368ab7cdd6" alt=""><figcaption></figcaption></figure>

```bash
unzip -l PhishNet.zip
```

The malicious file uses a double extension technique (`invoice_document.pdf.bat`), which is a common malware delivery method. The file appears to be a PDF document to users, but it's actually a Windows batch file (.bat) that will execute malicious commands when opened.

This technique exploits:

* User trust in PDF files as "safe" documents
* Windows' default behavior of hiding file extensions
* Social engineering (users expect to see invoice documents as PDFs)

***

#### Task 11: Which MITRE ATT\&CK techniques are associated with this attack?

**Answer:** `T1566.001`

**Analysis:** Based on the attack characteristics, the primary MITRE ATT\&CK technique is:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FNwdizE1HpdxdgFm7COGf%2FScreenshot%202025-09-18%20at%201.08.37%E2%80%AFPM.png?alt=media&#x26;token=87e081aa-551d-4d8a-b87c-e84995ea4dcf" alt=""><figcaption></figcaption></figure>

**T1566.001 - Phishing: Spearphishing Attachment**

This technique involves sending malicious attachments to specific individuals, companies, or industries. The attack matches this technique because:

1. **Targeted Nature:** The email specifically targets an accounting team
2. **Malicious Attachment:** Contains a ZIP file with a disguised executable
3. **Social Engineering:** Uses urgent payment request as a pretext
4. **File Masquerading:** Uses double extension to hide the malicious nature

Additional techniques that could be associated with this attack vector:

* **T1566.002** - Phishing: Spearphishing Link (for the malicious URL)
* **T1204.002** - User Execution: Malicious File (if the attachment is executed)
* **T1027** - Obfuscated Files or Information (ZIP compression hiding the .bat file)

***

### Attack Analysis Summary

#### Attack Vector

This is a classic **Business Email Compromise (BEC)** attack combined with malware delivery:

1. **Initial Access:** Spearphishing email targeting accounting team
2. **Social Engineering:** Urgent payment request from "known vendor"
3. **Dual Payload:** Both malicious link and attachment for higher success rate
4. **File Masquerading:** `.pdf.bat` double extension to bypass user suspicion
5. **Domain Spoofing:** Using legitimate-looking domain and subdomain

#### Key Indicators of Compromise (IOCs)

* **IP Address:** 45.67.89.10
* **Domains:** business-finance.com, secure.business-finance.com
* **Email Addresses:** <finance@business-finance.com>, <support@business-finance.com>
* **File Hash:** 8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a
* **Malicious File:** invoice\_document.pdf.bat

#### Defense Recommendations

1. **Email Security:** Implement advanced email filtering to detect suspicious attachments
2. **User Training:** Educate users about double extension files and urgent payment requests
3. **Process Verification:** Establish out-of-band verification for payment requests
4. **File Execution Controls:** Restrict execution of batch files and scripts
5. **Network Monitoring:** Monitor for connections to identified malicious domains

***

### Conclusion

This PhishNet challenge demonstrates a realistic phishing scenario that combines multiple attack techniques. The analysis reveals a sophisticated approach using legitimate-appearing domains, proper email authentication (SPF pass), and clever social engineering tactics. The dual delivery method (both link and attachment) increases the likelihood of successful compromise, making this a particularly effective attack vector against accounting teams handling financial transactions.

The challenge effectively illustrates the importance of thorough email forensics and the need for comprehensive security awareness training in organizational environments.

<https://labs.hackthebox.com/achievement/sherlock/2521593/985>
