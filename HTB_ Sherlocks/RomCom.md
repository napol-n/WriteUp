# RomCom

## RomCom Lab Writeup&#x20;

**Prepared by:** VivisGhost\
**Difficulty:** Very Easy\
**Skills Learned:** MFT analysis, USNJournal analysis, Evaluating CVE-2025-8088

***

### **Scenario**

Susan works at the **Research Lab, Forela International Hospital**.

* Microsoft Defender alert was received from her computer.
* While extracting a document from a received WinRAR file, she got multiple errors, but the document opened successfully.
* WinRAR was exploited in the wild by groups like RomCom and Paper WereWolf in 2025 for initial access.
* Analysts are provided with a **lightweight triage image (.vhdx)** for initial investigation.

***

### **Artifacts Provided**

1. `RomCom.zip`
   * Hash: `6b4fefb92769b8cf106c6b13b773e5b093b67b64509d05056ee32352c788e2d0`
2. `2025-09-02T083211_pathology_department_incidentalert.vhdx`
   * Hash: `cccd85ef47fd372a1ebf0f759d212dda378a8b0832bd98d4263eb6a9c7d99ee1`

***

### **Initial Analysis**

1. **Unlock Zip File**

```bash
unzip -P hacktheblue RomCom.zip -d ./RomCom_unzipped
```

2. **Mount VHDX on Linux**

```bash
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 ./RomCom_unzipped/2025-09-02T083211_pathology_department_incidentalert.vhdx
sudo fdisk -l /dev/nbd0
sudo mkdir -p /mnt/romcom
sudo mount -o ro /dev/nbd0p1 /mnt/romcom
```

3. **Verify Mount**

* Root of the disk: `/mnt/romcom`
* Contains:
  * `$MFT`
  * `$Extend`
  * `2025-09-02T08_32_11_5202830_CopyLog.csv`
  * `System Volume Information`

Questions

#### 1. CVE assigned to WinRAR vulnerability

* **Answer:** `CVE-2025-8088`
* **Reference:** NIST CVE Database

#### 2. Nature of the vulnerability

* **Answer:** Path Traversal

#### 3. Archive file under Susan's Documents exploiting the vulnerability

* **Answer:** `Pathology-Department-Research-Records.rar`
* **Method:** Parse `$MFT` with **MFTECmd**, load CSV in Timeline Explorer, filter for `.rar` and parent path `Documents`.

#### 4. Date archive file was created

* **Answer:** `2025-09-02 08:13:50`
* **Source:** USNJournal `FileCreate` event.

#### 5. Date archive file was opened

* **Answer:** `2025-09-02 08:14:04`
* **Source:** USNJournal / MFT for `.lnk` file.

#### 6. Decoy document extracted from the archive

* **Answer:** `Genotyping_Results_B57_Positive.pdf`
* **Method:** Filter MFT for common document extensions in the same parent folder as the archive.

#### 7. Backdoor executable dropped by the archive

* **Answer:** `C:\Users\Susan\Appdata\Local\ApbxHelper.exe`
* **Method:** Correlate USNJournal `FileCreate` events with MFT data.

#### 8. Persistence file facilitating backdoor execution

* **Answer:** `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`

#### 9. Associated MITRE Technique ID

* **Answer:** `T1547.009`
* **Technique:** AutoStart/Boot Logon (`.lnk` writing shortcuts to Windows Startup folder)

#### 10. Decoy document opened by user

* **Answer:** `2025-09-02 08:15:05`
* **Method:** Check MFT / USNJournal for `.lnk` creation and correlated timestamps.

***

### **Summary & Observations**

* Exploit leverages **WinRAR Path Traversal (CVE-2025-8088)**.
* Archive `Pathology-Department-Research-Records.rar` contained:
  * Decoy document: `Genotyping_Results_B57_Positive.pdf`
  * Backdoor: `ApbxHelper.exe`
  * Startup persistence: `.lnk` file
* All timelines can be reconstructed using **MFT + USNJournal**, confirming attack sequence:
  1. Archive created
  2. Archive opened
  3. Decoy document extracted
  4. Backdoor installed
  5. Persistence established via Startup `.lnk`
* MITRE ATT\&CK technique `T1547.009` applies for persistence.

***

### **References**

* NIST CVE Database
* MFTECmd / Timeline Explorer: Eric Zimmerman Tools
* MITRE ATT\&CK Enterprise Matrix: T1547.009
