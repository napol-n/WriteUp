# Countdown

## Countdown Lab Writeup - Complete Digital Forensics Investigation

### Table of Contents

1. Overview
2. Scenario Background
3. Investigation Methodology
4. Question Analysis and Solutions
5. Key Artifacts and Evidence
6. Conclusion

### Overview

**Lab Name:** Countdown\
**Scenario:** Bomb Threat Investigation\
**Tools Used:**

* Autopsy 4.17.0
* SQLite DB Browser
* WinPrefetchView
* Jumplist Explorer
* Thumbcache Viewer
* ROT13 Decoder

**Objective:** Investigate a laptop seized from a suspect named "Zerry" to determine if a bomb threat is real or a hoax.

### Scenario Background

NYC Police received intelligence about a gang planning to detonate an explosive device in the city. During investigations, a suspect named "Zerry" was detained and his laptop was seized for digital forensic analysis. The investigation aims to uncover any information about the potential attack by analyzing Zerry's digital activities.

### Investigation Methodology

#### 1. Evidence Integrity Verification

* **Tool:** Autopsy File Properties
* **Process:** Verify disk image integrity using MD5 hash calculation
* **Purpose:** Ensure evidence hasn't been tampered with during acquisition

#### 2. Timeline Analysis

* **Tool:** Autopsy Timeline Feature
* **Process:** Create chronological sequence of user activities
* **Focus Areas:** File creation, modification, program execution, and communications

#### 3. Communication Analysis

* **Tool:** SQLite DB Browser
* **Process:** Examine messaging applications and databases
* **Target:** Signal messenger application artifacts

#### 4. File System Analysis

* **Tool:** Autopsy File System View
* **Process:** Navigate through user directories and application data
* **Areas:** AppData, Desktop, Downloads, Recent Documents

#### 5. Metadata Extraction

* **Tool:** Various (EXIF, Thumbcache Viewer, Sticky Notes)
* **Process:** Extract hidden information from files and system artifacts
* **Purpose:** Recover deleted or hidden intelligence

### Question Analysis and Solutions

#### Question 1: Disk Image Verification

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FAPNrP3u9aZTDmXgLRHmY%2FScreenshot%202025-09-18%20at%208.59.48%E2%80%AFPM.png?alt=media&#x26;token=747c69e4-9a1c-48de-b1ba-7b0e31c42186" alt=""><figcaption></figcaption></figure>

**Question:** Verify the Disk Image. Submit SectorCount and MD5

**Solution Process:**

1. Load the disk image (Zerry.E01) into Autopsy
2. Navigate to Properties/Metadata of the disk image
3. Extract sector count and MD5 hash values

**Answer:** 25165824,5c4e94315039f890e839d6992aeb6c58

* **Sector Count:** 25,165,824
* **MD5 Hash:** 5c4e94315039f890e839d6992aeb6c58

**Evidence Location:** Disk image properties in Autopsy

***

#### Question 2: Messenger Decryption Key

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FlF3ggNnGZP1ctz8CnuQX%2FScreenshot%202025-09-18%20at%209.14.17%E2%80%AFPM.png?alt=media&#x26;token=357a436c-341b-4634-ab42-dc039d20d2db" alt=""><figcaption></figcaption></figure>

**Question:** What is the decryption key of the online messenger app used by Zerry?

**Solution Process:**

1. Navigate to File System → vol3 → Users → ZerryD → Desktop → Countdown
2. Open `Countdown.aut` file
3. Extract the decryption key from file contents
4. Verify by checking Signal application folder in AppData\Roaming\Signal

**Answer:** `c2a0e8d6f0853449cfcf4b75176c277535b3677de1bb59186b32f0dc6ed69998`

**Evidence Location:**

* Primary: `/Users/ZerryD/Desktop/Countdown/Countdown.aut`
* Verification: `/Users/ZerryD/AppData/Roaming/Signal/`

***

#### Question 3: Signal Registration Details

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F8hsudIEfxyOg3dhTOloS%2FScreenshot%202025-09-18%20at%209.24.55%E2%80%AFPM.png?alt=media&#x26;token=cd6a512c-bb79-4ef9-a808-8c7eab1c7078" alt=""><figcaption></figcaption></figure>

**Question:** What is the registered phone number and profile name of Zerry in the messenger application used?

**Solution Process:**

1. Extract Signal folder from AppData\Roaming\Signal
2. Open `db.sqlite` using SQLite DB Browser
3. Use decryption key from Question 2
4. Navigate to `conversations` table
5. Extract phone number and profile name

**Answer:** 13026482364,ZerryThe🔥

* **Phone Number:** +13026482364
* **Profile Name:** ZerryThe🔥

**Evidence Location:** Signal database `/AppData/Roaming/Signal/db.sqlite` → conversations table

***

#### Question 4: Email Address in Chat

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FNNIH3RMrDP6eddB9TSoh%2FScreenshot%202025-09-18%20at%209.26.45%E2%80%AFPM.png?alt=media&#x26;token=9eb3e1d2-a9f6-4321-b45e-aca940401cc3" alt=""><figcaption></figcaption></figure>

**Question:** What is the email id found in the chat?

**Solution Process:**

1. Continue examining Signal database using SQLite DB Browser
2. Navigate to `messages` table
3. Search through message content for email addresses
4. Identify email used for temporary/expiring communications

**Answer:** `eekurk@baybabes.com`

**Evidence Location:** Signal database `messages` table, message body content

**Context:** Email was used for sending expiring attachments via Tor browser

***

#### Question 5: Email Attachment Filename

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FE4aBY8OFD8DRybQff4mP%2FScreenshot%202025-09-18%20at%209.35.35%E2%80%AFPM.png?alt=media&#x26;token=694b1f16-248a-429a-a7b5-21281e24fe99" alt=""><figcaption></figcaption></figure>

**Question:** What is the filename (including extension) that is received as an attachment via email?

**Solution Process:**

1. Analyze chat messages in Signal database for attachment references
2. Cross-reference with Recent Documents in Autopsy
3. Navigate to Results → Recent Documents
4. Examine Downloads folder path entries
5. Identify filename with emoji characters

**Answer:** `⌛📅.PNG`

**Evidence Location:**

* Primary: Recent Documents artifact in Autopsy
* Path: `C:\Users\ZerryD\Downloads\⌛📅.PNG`
* Verification: Thumbcache artifacts

***

#### Question 6: Planned Attack Date and Time

**Question:** What is the Date and Time of the planned attack?

**Solution Process:**

1. Use Thumbcache Viewer to examine `thumbcache_256.db`
2. Locate thumbnail entry for `⌛📅.PNG`
3. Extract timestamp from thumbnail metadata
4. Verify timing correlates with other evidence

**Answer:** `01-02-2021 09:00 AM`

**Evidence Location:** Thumbcache database `thumbcache_256.db`

**Verification:** Timestamp matches with file access patterns and communication timeline

***

#### Question 7: GPS Location of Blast

**Question:** What is the GPS location of the blast? The format is the same as found in the evidence. \[Hint: Encode(XX Degrees,XX Minutes, XX Seconds)]

**Solution Process:**

1. Navigate to Sticky Notes artifact location:`C:\Users\%UserProfile%\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

**Answer:** 40 degrees 45 minutes 28.6776 seconds N, 73 degrees 59 minutes 7.994 seconds W

**Evidence Location:** Windows Sticky Notes database `plum.sqlite`

**Decoding Method:** ROT13 cipher

### Key Artifacts and Evidence

#### 1. Signal Messenger Database

* **Location:** `/AppData/Roaming/Signal/db.sqlite`
* **Key Information:**
  * User registration details
  * Message history with potential co-conspirators
  * References to email communications
  * Evidence of attachment transfers

#### 2. Thumbcache Database

* **Location:** `thumbcache_256.db`
* **Key Information:**
  * File access timestamps
  * Visual confirmation of downloaded content
  * Timeline correlation for attack planning

#### 3. Windows Sticky Notes

* **Location:** `plum.sqlite` in MicrosoftStickyNotes package
* **Key Information:**
  * Encoded GPS coordinates
  * ROT13 encrypted location data
  * Target location specifications

#### 4. Recent Documents

* **Location:** Windows Recent Documents artifacts
* **Key Information:**
  * Downloaded file tracking
  * User activity timeline
  * Evidence of file manipulation

#### 5. File System Metadata

* **Various Locations:** Throughout user profile
* **Key Information:**
  * File creation/modification timestamps
  * Application usage patterns
  * Data exfiltration evidence

### Technical Analysis Summary

#### Timeline Reconstruction

1. **2021-01-16 08:02:00 UTC** - Initial Signal setup and configuration
2. **2021-01-17 06:24:39 UTC** - Download of `⌛📅.PNG` attachment
3. **2021-01-17 17:48:50 UTC** - Active messaging period with co-conspirators
4. **2021-01-17 18:12:29 UTC** - Final communications and cleanup activities

#### Communication Pattern Analysis

* **Primary Channel:** Signal encrypted messaging
* **Secondary Channel:** Temporary email (`eekurk@baybabes.com`)
* **Security Measures:** Tor browser usage, message deletion, attachment erasure
* **Encryption:** Custom decryption key, ROT13 encoding for sensitive data

#### Threat Assessment Indicators

**Evidence of Real Threat:**

* Specific GPS coordinates for target location
* Detailed timeline with exact attack date/time
* Encrypted communications with operational security measures
* Coordinated multi-channel communication pattern
* Evidence of reconnaissance and planning activities

**Operational Security Observed:**

* Use of encrypted messaging (Signal)
* Temporary email services
* Tor browser for anonymous communications
* File deletion and evidence cleanup attempts
* Encoded location data using ROT13

### Conclusion

Based on the comprehensive digital forensic analysis of Zerry's laptop, the investigation reveals **substantial evidence of a credible bomb threat** rather than a hoax. The evidence includes:

1. **Specific Target Information:** Precise GPS coordinates (40°45'28.6776"N, 73°59'7.994"W) encoded using ROT13
2. **Detailed Timeline:** Exact attack timing (01-02-2021 09:00 AM) stored in multiple locations
3. **Operational Communications:** Encrypted messaging with co-conspirators using operational security measures
4. **Intelligence Gathering:** Evidence of reconnaissance activities and information sharing

**Recommendation:** Immediate law enforcement action is warranted based on the specificity and credibility of the threat intelligence recovered from the suspect's digital devices.

**Evidence Chain of Custody:** All artifacts were properly extracted and documented using forensically sound methodologies with hash verification maintaining evidence integrity throughout the investigation process.

<https://blueteamlabs.online/achievement/share/122610/1>
