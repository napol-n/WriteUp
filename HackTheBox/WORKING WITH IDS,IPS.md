# WORKING WITH IDS/IPS

## Working with IDS/IPS - Complete Guide

### 1. Introduction to IDS/IPS

#### Overview

This content explains the importance of **IDS (Intrusion Detection System)** and **IPS (Intrusion Prevention System)** in Network Security Monitoring (NSM). It covers their operation, detection methods, network positioning, differences between IDS and IPS, discusses **Host-based IDS/IPS (HIDS/HIPS)**, the importance of updates, and integration with **SIEM (Security Information and Event Management)**.

This serves as a foundation for learning **Suricata, Snort**, and **Zeek**, which are popular IDS/IPS systems.

### 2. Key Concepts

#### IDS (Intrusion Detection System)

IDS monitors/detects attacks or policy violations → alerts but does not prevent directly.

**Two detection methods:**

* **Signature-based**: Compares against known signatures/patterns
* **Anomaly-based**: Detects deviations from normal baseline behavior

#### IPS (Intrusion Prevention System)

IPS works proactively → prevents attacks directly (block, drop, reset connection). Uses the same detection methods as IDS (signature + anomaly).

#### Network Positioning

* **IDS**: Placed behind Firewall, works passively → detects traffic that has already passed through
* **IPS**: Placed inline behind Firewall → can block/stop attacks immediately
* **HIDS/HIPS**: Installed directly on hosts to monitor inbound/outbound traffic

#### Defense-in-Depth

IDS/IPS is part of multi-layered security defense. Design positioning depends on network structure, data importance, and threat landscape.

#### Updates and Tuning

Regular updates to threat signatures and fine-tuning anomaly detection are required to prevent false positives and support new threats.

#### SIEM Integration

* Collects logs from IDS/IPS and other devices
* Uses correlation and advanced analytics → detects complex/multi-stage attacks
* Provides comprehensive network security visibility

### 3. Detailed Technical Explanation

#### Signature-based Detection

Like using a "dictionary" of known attacks such as malware signatures, SQL injection patterns.

**Advantages:**

* Accurate detection of known threats

**Disadvantages:**

* Cannot detect new threats (zero-day attacks)

#### Anomaly-based Detection

Uses baseline of normal behavior, such as normal server traffic. If behavior deviates (e.g., unusually high request volume) → alerts.

**Disadvantages:**

* May generate frequent false positives

#### IPS Response Actions

* Drop packet
* Block connection
* Reset abnormal sessions
* Suitable for real-time protection

#### Placement Strategies

* **Behind Firewall**: IDS detects traffic that passed first layer
* **Inline**: IPS can prevent immediately
* **Host-based (HIDS/HIPS)**: For servers or endpoints requiring specific monitoring

#### System Integration

IDS/IPS requires continuous updates to handle new threats. Works alongside SIEM → combines data from multiple sources to detect complex attacks like APT (Advanced Persistent Threat).

### 4. Suricata Fundamentals

#### What is Suricata?

Suricata is an open-source **IDS/IPS/NSM (Network Security Monitoring)** developed by **OISF**. It operates using **rules/signatures** to detect or prevent threats, supporting both high-speed and general hardware.

#### Suricata Operating Modes

1. **IDS Mode**: Detection only, no blocking (increases visibility but no direct prevention)
2. **IPS Mode**: Detection and blocking traffic (beware of false positives that may block normal traffic)
3. **IDPS Mode**: Combined IDS + IPS (can send RST packets to terminate connections)
4. **NSM Mode**: Logging only (for forensic/incident response later)

#### Input Methods

**Offline Input (PCAP)**

* Uses .pcap files for retrospective analysis

**Live Input**

* **LibPCAP**: Direct packet capture (disadvantages: slow, no load balancing)
* **NFQ (Linux only)**: Inline IPS mode with iptables
* **AF\_PACKET**: Higher performance than LibPCAP, supports multithreading

#### Output Methods

* **Logs/Alerts**: fast.log, stats.log
* **EVE JSON**: Compatible with ELK/Logstash (HTTP, DNS, TLS, flows, alerts, etc.)
* **Unified2**: Same format as Snort, use with u2spewfoo

#### Rules and Configuration

Rules stored in `/etc/suricata/rules/`

Example rule:

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET MALWARE SC-KeyLog"; sid:2002979;)
```

Variables (`$HOME_NET`, `$EXTERNAL_NET`, etc.) defined in `suricata.yaml`. Custom rules can be added to `local.rules` and configured in `suricata.yaml`.

#### Practical Usage

**1. Read PCAP offline:**

```bash
suricata -r suspicious.pcap
# Use -k none to skip checksum, -l to specify log directory
```

**2. Live capture (IDS Mode):**

```bash
sudo suricata -i ens160
# or
sudo suricata --af-packet=ens160
```

**3. Inline (IPS Mode with NFQ):**

```bash
sudo iptables -I FORWARD -j NFQUEUE
sudo suricata -q 0
```

**4. Replay traffic for testing:**

```bash
sudo tcpreplay -i ens160 suspicious.pcap
```

**5. Check logs after running:**

```bash
cd /var/log/suricata
cat eve.json
```

### 5. Suricata Log Management and File Extraction

#### Main Log Files

Located at `/var/log/suricata/`

**eve.json**: Primary output (recommended). Contains JSON data including timestamp, flow\_id, event\_type (alert, dns, tls, etc.)

Use jq to filter specific events:

```bash
cat old_eve.json | jq -c 'select(.event_type == "alert")'
```

**fast.log**: Plain text log, stores alerts only **stats.log**: Statistics log summarizing operations (packets, flows, memory, etc.)

#### Key Fields

* **flow\_id**: ID of each flow (links different events in same flow)
* **pcap\_cnt**: Packet sequence number processed by Suricata (comparable with pcap file)

#### File Extraction

Suricata can extract files from various protocols like HTTP, FTP, SMB.

**1. Enable in suricata.yaml:**

```yaml
file-store:
  version: 2
  enabled: yes
  force-filestore: yes
```

**2. Create rule in local.rules:**

```
alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
```

**3. Run with pcap:**

```bash
suricata -r /home/htb-student/pcaps/vm-2.pcap
```

Extracted files stored in `filestore/` directory, named with SHA256 hash.

**4. Check files (e.g., Windows EXE):**

```bash
xxd ./21/21742fc6... | head
# Look for MZ header → executable file
```

#### Live Rule Reloading

**Enable in suricata.yaml:**

```yaml
detect-engine:
  - reload: true
```

**Reload rules without restarting:**

```bash
sudo kill -usr2 $(pidof suricata)
```

#### Ruleset Updates

```bash
sudo suricata-update
```

Downloads rules from **Emerging Threats Open (ET Open)** immediately.

### 6. Suricata Rule Development

#### Rule Structure

Example rule:

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 9443 (msg:"Known malicious behavior"; content:"some thing"; sid:10000001; rev:1;)
```

#### Header Components

* **action**: What Suricata does when matched (alert, log, pass, drop, reject)
* **protocol**: tcp, udp, icmp, ip, http, tls, smb, dns
* **IP/Port and direction**: `$HOME_NET any -> $EXTERNAL_NET 9443`
  * `->` outbound, `<-` inbound, `<>` bidirectional
* **port**: Can use port number, range, or variable like `$UNCOMMON_PORTS`

#### Rule Message & Content

* **msg**: Message displayed when triggered
* **flow**: Detects connection direction (to\_server, from\_client, established)
* **dsize**: Payload size to match
* **content**: Pattern in packet payload
  * Can use **hex** like `|3a 20|` for `:`
  * Use **Rule Buffers** like `http.accept` to match specific HTTP headers
* **modifier**: Increases accuracy (nocase, offset, depth, distance, within)

#### Metadata

* **reference**: Rule source reference
* **sid**: Unique rule identifier
* **rev**: Rule version

#### PCRE (Perl Compatible Regular Expression)

Use `pcre:` followed by regex `/pattern/flags`

Should not rely on PCRE alone.

**Flags:**

* `i` = case-insensitive
* `R` = relative position
* `P` = buffer position

Example:

```
pcre:!"/^\\$?[\\sa-z\\\\_0-9.-]*(\\&|\\$)/iRP"
```

* `!` = trigger when doesn't match
* `^` = start of line
* `[\\sa-z\\\\_0-9.-]*` = match space, a-z, \\, \_, 0-9, ., -

### 7. IDS/IPS Rule Development Approaches

#### Signature-based Detection

* Detects known patterns (payload, command, string)
* **Pros**: Accurate with known threats
* **Cons**: Cannot catch zero-day

#### Behavior-based/Anomaly Detection

* Detects abnormal behavior (HTTP size, beaconing interval, unusual ports)
* **Pros**: May catch zero-day
* **Cons**: High false positive rate

#### Stateful Protocol Analysis

* Tracks connection and protocol state
* Compares actual behavior vs expected state

### 8. Detecting Encrypted Traffic

#### The Challenge

Encrypted traffic (TLS/SSL) presents major obstacles for malware or attack detection since payload is encrypted, making pattern detection difficult for traditional IDS/IPS.

#### Detection Methods

Use **SSL/TLS metadata** and **JA3 fingerprints** to create detection rules.

**SSL/TLS Certificates**

Exchanged during TLS handshake, contains unencrypted information:

* **issuer**: Certificate issuer
* **issue date, expiry date**
* **subject**: Certificate holder name and domain

Unusual domains or certificates may indicate malware.

**JA3 Fingerprint**

Method to create hash for TLS client by capturing **Client Hello**. Helps identify malware or suspicious software. Can create Suricata rules for detection.

#### Example Rules

**Detecting Dridex:**

```
alert tls $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET MALWARE ABUSE.CH SSL Blacklist Malicious SSL certificate detected (Dridex)";
  flow:established,from_server;
  content:"|16|"; content:"|0b|"; within:8;
  byte_test:3,<,1200,0,relative;
  content:"|03 02 01 02 02 09 00|"; fast_pattern;
  content:"|30 09 06 03 55 04 06 13 02|"; distance:0; pcre:"/^[A-Z]{2}/R";
  content:"|55 04 07|"; distance:0;
  content:"|55 04 0a|"; distance:0;
  content:"|55 04 03|"; distance:0; byte_test:1,>,13,1,relative;
  content:!"www."; distance:2; within:4;
  content:!"|2a 86 48 86 f7 0d 01 09 01|";
  content:!"GoDaddy";
  sid:2023476; rev:5;
)
```

**Detecting Sliver (TLS Encrypted):**

```
alert tls any any -> any any (
  msg:"Sliver C2 SSL";
  ja3.hash;
  content:"473cd7cb9faa642487833865d516e578";
  sid:1002; rev:1;
)
```

### 9. Snort Fundamentals

#### What is Snort?

Snort is an open-source tool that works as both **IDS (Intrusion Detection System)** and **IPS (Intrusion Prevention System)**. It can also function as a **packet logger** or **sniffer** to detect and log network traffic. Requires **rule sets** to define what to detect and actions to take.

#### Snort Operating Modes

1. **Inline IDS/IPS**: Can block packets
2. **Passive IDS**: Detects and logs but doesn't block
3. **Network-based IDS**: Monitors overall network
4. **Host-based IDS**: Not ideal, use specialized tools

#### Mode Selection Commands

* `-r <file.pcap>`: Passive mode (read pcap file)
* `-i <interface>`: Passive mode (listen on interface)
* `-Q`: Inline mode

**DAQ Module**: e.g., afpacket used for accessing packets in Linux interface

#### Snort Architecture

1. **Packet Decoder/Sniffer**: Parses packet structure
2. **Preprocessors**: Detects behavioral characteristics (HTTP, port\_scan)
3. **Detection Engine**: Compares packets against Snort rules
4. **Logging & Alerting System + Output modules**: Logs or alerts

Preprocessor and Output configuration in `snort.lua`

#### Configuration (snort.lua)

* **Main file**: `snort.lua`
* **Default file**: `snort_defaults.lua`

**Sections:**

* Network variables (HOME\_NET, EXTERNAL\_NET)
* Decoder configuration
* Detection engine configuration
* Preprocessors
* Output plugins
* Rule set customization

**Example IPS module configuration:**

```lua
ips = {
  { variables = default_variables, include = '/home/htb-student/local.rules' }
}
```

**Check configuration:**

```bash
snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq
```

#### Usage Examples

**Read pcap file:**

```bash
sudo snort -c snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap
```

**Listen on network interface:**

```bash
sudo snort -c snort.lua --daq-dir /usr/local/lib/daq -i ens160
```

#### Snort Modules

Examples:

* stream, stream\_tcp, stream\_udp, stream\_icmp
* arp\_spoof
* port\_scan
* http\_inspect
* appid (Application Identification)

Modules in `{ }` use default configuration.

**View module defaults:**

```bash
snort --help-config arp_spoof
```

#### Outputs & Alerts

**Main statistics:**

* Packet Stats, Module Stats, File Stats, Summary Stats

**Alert types:**

* `-A cmg`: Alert + packet headers + payloads
* `-A u2`: Unified2 binary
* `-A csv`: CSV format

### 10. Zeek Fundamentals

#### What is Zeek?

**Zeek** is an **open-source network traffic analyzer** used for detailed network traffic analysis to find suspicious or dangerous activities. Besides malware detection, Zeek is used for network troubleshooting and network measurement.

#### Key Features

* Creates **logs** of all connections and application-layer activity (HTTP, DNS, FTP, SMTP, etc.)
* Has **Zeek scripting language** for writing scripts similar to Suricata rules
* Supports **semantic misuse detection, anomaly detection, behavioral analysis**
* Runs on **standard hardware**, no special servers required

#### Operating Modes

* **Fully passive traffic analysis**: Analyzes traffic without network disruption
* **libpcap interface**: Uses for packet capture
* **Real-time** and **offline (PCAP)**: Analyzes during events and retrospectively from PCAP files
* **Cluster support**: Supports large-scale deployment

#### Zeek Architecture

* **Event engine (core)**: Converts packets to **high-level events** like http\_request
* **Script interpreter**: Runs Zeek scripts to analyze events and define policies
* **Event queue**: Manages events **first-come, first-served**

#### Zeek Logs

Logs stored for **offline analysis** in current directory.

**Main log examples:**

* `conn.log`: Connection details IP/TCP/UDP/ICMP
* `dns.log`: DNS queries/responses
* `http.log`: HTTP requests/responses
* `ftp.log`: FTP requests/responses
* `smtp.log`: SMTP transactions

**http.log fields example:**

* **host**: domain/IP
* **uri**: HTTP URI
* **referrer**: HTTP referrer
* **user\_agent**: client user-agent
* **status\_code**: HTTP status code

Zeek **compresses logs** hourly → stored in YYYY-MM-DD folders. Use `gzcat`, `zgrep` for viewing or searching old logs.

#### Tools Usage

* Use **Unix commands**: cat, grep
* Use **zeek-cut**: Convenient column selection from logs

#### Detection Examples

**Example 1: Detecting Beaconing Malware**

**Beaconing malware**: Malware that contacts C2 server periodically to receive commands or send data.

**Indicators:**

* Repeated connections to same IP/domain
* Consistent data size
* Patterned connection timing

**Analysis:**

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psempire.pcap
cat conn.log
```

Example: Host 192.168.56.14 contacts 51.15.197.127:80 every 5 seconds → PowerShell Empire beaconing behavior.

**Example 2: Detecting DNS Exfiltration**

**DNS Exfiltration**: Method of sending data out using DNS requests to avoid detection.

**Zeek logs used:**

* `dns.log`: View suspicious domains and queries
* `files.log`: View files being sent out
* `http.log`: Check HTTP POST data

**Analyze suspicious queries:**

```bash
cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7
```

**Example queries:**

* 456c54f2.blue.letsgohunt.online
* [www.1204192da26d109d4.1c9a5671.456c54f2.blue.letsgohunt.online](http://www.1204192da26d109d4.1c9a5671.456c54f2.blue.letsgohunt.online)

Multiple subdomains pattern indicates DNS tunneling data transmission.

### 11. Practical Exercises and Q\&A

#### Question 1: Filter out only HTTP events from /var/log/suricata/old\_eve.json using the the jq command-line JSON processor. Enter the flow\_id that you will come across as your answer.

**Task**: Filter only HTTP events from `/var/log/suricata/old_eve.json` using jq.

**Solution:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FLS6l0phsFuW2vVbKd7uc%2FScreenshot%202025-09-20%20at%2010.52.59%E2%80%AFPM.png?alt=media&#x26;token=bef0fcb0-e07d-40c9-a948-b77860ef3919" alt=""><figcaption></figcaption></figure>

```bash
sudo cat /var/log/suricata/old_eve.json | jq 'select(.event_type=="http") | .flow_id'
```

**Answer**: 1252204100696793

#### Question 2: Enable the http-log output in suricata.yaml and run Suricata against /home/htb-student/pcaps/suspicious.pcap. Enter the requested PHP page as your answer. Answer format: \_.php

**Task**: Enable http-log output in suricata.yaml and run Suricata against suspicious.pcap.

**Solution:**

1. Edit suricata.yaml eve-log section:

```yaml
- eve-log:
    enabled: yes
    filetype: regular
    filename: eve.json
    types:
      - alert
      - http
      - dns
      - tls
```

2. Create output directory and run:

```bash
sudo mkdir -p /tmp/suricata_output
sudo suricata -r /home/htb-student/pcaps/suspicious.pcap -l /tmp/suricata_output
```

3. Extract PHP URI:

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FVUWO8ZYx7AFBxQKM8EiS%2FScreenshot%202025-09-20%20at%2011.04.50%E2%80%AFPM.png?alt=media&#x26;token=d43826fd-7554-444e-843a-80454c17909e" alt=""><figcaption></figcaption></figure>

```bash
cat /tmp/suricata_output/eve.json | jq -r 'select(.event_type=="http") | .http.url'
```

**Answer**: app.php

#### Question 3: In the /home/htb-student directory of this section's target, there is a file called local.rules. Within this file, there is a rule with sid 2024217, which is associated with the MS17-010 exploit. Additionally, there is a PCAP file named eternalblue.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to MS17-010. What is the minimum offset value that can be set to trigger an alert?

**Task**: Find minimum offset value for MS17-010 exploit detection.

Understanding MS17-010/EternalBlue structure and SMB packet analysis reveals that the signature appears at offset 4 bytes from payload start, not the initially assumed offset 9.

**Answer**: 4

#### Question 4: There is a file named trickbot.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to a certain variation of the Trickbot malware. Enter the precise string that should be specified in the content keyword of the rule with sid 100299 within the local.rules file so that an alert is triggered as your answer.

**Task**: Find JA3 hash for Trickbot C2 SSL rule.

**Solution:**

```bash
ja3 -a --json trickbot.pcap
```

From the analysis, the specific Trickbot variant uses JA3 digest: 72a589da586844d7f0818ce684948eea

: 72a589da586844d7f0818ce684948eea

#### Question 5: There is a file named wannamine.pcap in the /home/htb-student/pcaps directory. Run Snort on this PCAP file and enter how many times the rule with sid 1000001 was triggered as your answer.

**Task**: Count how many times rule sid 1000001 was triggered in wannamine.pcap.

**Solution:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F8QtOiw5UBFLuEa6L3Fw4%2FScreenshot%202025-09-21%20at%2012.01.09%E2%80%AFAM.png?alt=media&#x26;token=775f7e87-3a3f-4458-a8c1-bfc223cd5948" alt=""><figcaption></figcaption></figure>

```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/wannamine.pcap -A cmg | grep "1000001" | wc -l
```

**Answer**: 234

#### Question 6: There is a file named log4shell.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to log4shell exploitation attempts, where the payload is embedded within the user agent. Enter the keyword that should be specified right before the content keyword of the rule with sid 10000098 within the local.rules file so that an alert is triggered as your answer. Answer format: \[keyword];

**Task**: Find keyword for log4shell rule with embedded payload in User-Agent.

Since the payload is embedded within the User-Agent header, the rule should use `http_header;` to inspect HTTP headers.

**Answer**: http\_header;

#### Question 7: There is a file named printnightmare.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the PrintNightmare (<https://labs.jumpsec.com/printnightmare-network-analysis/>) vulnerability. Enter the zeek log that can help us identify the suspicious spooler functions as your answer. Answer format: \_.log

**Task**: Identify Zeek log for suspicious spooler functions.

**Solution:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FwGHYMUx6HJ2aBFgbIQA8%2FScreenshot%202025-09-21%20at%2012.18.44%E2%80%AFAM.png?alt=media&#x26;token=56c8bc28-093f-46c2-86a6-a4dc486cc456" alt=""><figcaption></figcaption></figure>

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/printnightmare.pcap
```

PrintNightmare exploits Windows Print Spooler via RPC calls. The `dce_rpc.log` captures RPC function calls including suspicious spooler activities.

**Answer**: dce\_rpc.log

#### Question 8:There is a file named revilkaseya.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the REvil ransomware Kaseya supply chain attack. Enter the total number of bytes that the victim has transmitted to the IP address 178.23.155.240 as your answer.

**Task**: Find total bytes transmitted to IP 178.23.155.240 in revilkaseya.pcap.

**Solution:**

1. Open PCAP in Wireshark
2. Apply filter: `ip.dst == 178.23.155.240`
3. Check Statistics → Protocol Hierarchy
4. Find TLS bytes transmitted

**Answer**: 2311

### Skills Assessment - Suricata

There is a file named pipekatposhc2.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to WMI execution. Add yet another content keyword right after the msg part of the rule with sid 2024233 within the local.rules file so that an alert is triggered and enter the specified payload as your answer. Answer format: C\_\_\_\_e

**Answer**: Create

## Skills Assessment - Snort

### Snort Rule Development Exercise: Detecting Overpass-the-Hash

**PCAP source**: <https://github.com/elcabezzonn/Pcaps>

**Attack description and possible detection points**: <http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day2.html>

`Overpass-the-Hash (Pass-the-Key)` is a type of attack where an adversary gains unauthorized access to resources by using a stolen `NTLM (NT LAN Manager)` hash or Kerberos key, without needing to crack the password from which the hash was derived. The attack involves using the hash to create a `Kerberos TGT (Ticket-Granting Ticket)` to authenticate to Active Directory (AD).

When the adversary utilizes Overpass-the-Hash, they have the `NTLM` hash of the user's password, which is used to craft an `AS-REQ (Authentication Service Request)` to the `Key Distribution Center (KDC)`. To appear authentic, the `AS-REQ` contains a `PRE-AUTH` field, which contains an encrypted timestamp (`Enc-Timestamp`). This is normally used by a legitimate client to prove knowledge of the user's password, as it is encrypted using the user's password hash. In this attack scenario, the hash used to encrypt the timestamp is not derived from the actual password but rather it is the stolen NTLM hash. More specifically, in an `Overpass-the-Hash` attack the attacker doesn't use this hash to encrypt the `Enc-Timestamp`. Instead, the attacker directly uses the stolen NTLM hash to compute the Kerberos `AS-REQ`, bypassing the usual Kerberos process that would involve the user's password and the `Enc-Timestamp`. The attacker essentially "overpasses" the normal password-based authentication process, hence the name Overpass-the-Hash.

One key aspect of this type of attack that we can leverage for detection is the `encryption type` used for the `Enc-Timestamp`. A standard `AS-REQ` from a modern Windows client will usually use the `AES256-CTS-HMAC-SHA1-96` encryption type for the Enc-Timestamp, but an `Overpass-the-Hash` attack using the older NTLM hash will use the `RC4-HMAC` encryption type. This discrepancy can be used as an indicator of a potential attack.

***

Review the previously referenced resource that discusses the network traces resulting from executing an `Overpass-the-Hash` attack, and then proceed to address the following question.

There is a file named wannamine.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the Overpass-the-hash technique which involves Kerberos encryption type downgrading. Replace XX with the appropriate value in the last content keyword of the rule with sid XXXXXXX within the local.rules file so that an alert is triggered as your answer.

**Open the Snort local rules file**

```
sudo nano /etc/snort/rules/local.rules
```

Locate the rule with `sid:9999999;`, which looks like:

```
alert tcp $HOME_NET any -> any 88 (msg: "Kerberos Ticket Encryption Downgrade to RC4 Detected"; flow: no_stream, established, to_server; content: "|A1 03 02 01 05 A2 03 02 01 0A|", offset 12, depth 10; content: "|A1 03 02 01 02|", distance 5, within 6; content: "|A0 03 02 01 XX|", distance 6, within 6; content: "krbtgt", distance 0; sid:9999999;)
```

* **Open the pcap file in Wireshark**

  ```
  wireshark /home/htb-student/pcaps/wannamine.pcap
  ```

  Apply the filter:

  ```
  kerberos
  ```

  Look for AS-REQ or TGS-REQ packets, especially PA-DATA sections showing the encryption type (etype).
* **Identify the RC4-HMAC byte**\
  In Wireshark, expand:

```
Kerberos -> PA-DATA (Pre-Authentication) -> PA-ENC-TIMESTAMP -> etype
```

* The byte value for RC4-HMAC is `0x17` (decimal `23`).
* **Update the rule**\
  Replace `XX` with `17`:

  ```
  content: "|A0 03 02 01 17|"
  ```

  Full rule becomes:

  ```
  alert tcp $HOME_NET any -> any 88 (msg: "Kerberos Ticket Encryption Downgrade to RC4 Detected"; flow: no_stream, established, to_server; content: "|A1 03 02 01 05 A2 03 02 01 0A|", offset 12, depth 10; content: "|A1 03 02 01 02|", distance 5, within 6; content: "|A0 03 02 01 17|", distance 6, within 6; content: "krbtgt", distance 0; sid:9999999;)
  ```
* **Test the rule**

  ```
  sudo snort -c /etc/snort/snort.conf -r /home/htb-student/pcaps/wannamine.pcap -A console
  ```

**Answer 17**

## Skills Assessment - Zeek

### Intrusion Detection With Zeek: Detecting Gootkit's SSL Certificate

**PCAP source**: [https://www.malware-traffic-analysis.net/2016/07/08/index.html](https://web.archive.org/web/20230128061716/https://www.malware-traffic-analysis.net/2016/07/08/index.html)

**Attack description and possible detection points**: [https://www.malware-traffic-analysis.net/2016/07/08/index.html](https://web.archive.org/web/20230128061716/https://www.malware-traffic-analysis.net/2016/07/08/index.html) <-- Focus on the SSL certificate parts.

`Neutrino`, a notorious exploit kit, and `Gootkit`, a potent banking trojan, collaborated in the past to perpetrate cyberattacks.

The `Neutrino` exploit kit opened the gate, and then `Gootkit` begun to communicate over the network using SSL/TLS encryption. It's within these encrypted communications that we encountered a particularly striking detail - the SSL certificates used by `Gootkit` contained the Common Name (`CN`) "`My Company Ltd.`".

Cybercriminals frequently employ self-signed or non-trusted CA issued certificates to foster encrypted communication. These certificates often feature bogus or generic details. In this case, the common name `My Company Ltd.` stands out as an anomaly we can use to identify this specific `Gootkit` infection delivered via the `Neutrino` exploit kit.

***

Review the previously referenced resource that discusses the network traces resulting from `Gootkit` communications, and then proceed to address the following question.

WMI Execution Detection

Create Suricata rule to detect WMI execution via wmiexec:

```
alert tcp any any -> any 135 (msg:"WMIExec - WMI Execution via DCOM"; 
  content:"Win32_Process"; nocase; 
  content:"Create"; nocase; distance:0; within:200; 
  sid:1000001; rev:1;)
```

#### Overpass-the-Hash Detection

For detecting Kerberos encryption type downgrade to RC4-HMAC:

```
alert tcp $HOME_NET any -> any 88 (msg: "Kerberos Ticket Encryption Downgrade to RC4 Detected"; flow: no_stream, established, to_server; content: "|A1 03 02 01 05 A2 03 02 01 0A|", offset 12, depth 10; content: "|A1 03 02 01 02|", distance 5, within 6; content: "|A0 03 02 01 17|", distance 6, within 6; content: "krbtgt", distance 0; sid:9999999;)
```

The key value `17` represents RC4-HMAC encryption type (0x17 in hex).

#### Gootkit SSL Certificate Detection

Using Zeek's x509.log to detect malicious SSL certificates:

**Solution:**

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FTsb5dVDDpANLaQx8lGbA%2FScreenshot%202025-09-21%20at%201.12.02%E2%80%AFAM.png?alt=media&#x26;token=60b03efe-ea0d-4eec-836c-11551ba4ca77" alt=""><figcaption></figcaption></figure>

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/neutrinogootkit.pcap
cat x509.log
```

Looking for "MyCompany Ltd." in the certificate subject field.

**Answer**: certificate.subject

### Conclusion

This comprehensive guide covers the essential aspects of working with IDS/IPS systems, including theoretical foundations, practical implementations with Suricata, Snort, and Zeek, and hands-on exercises for detecting various types of malware and attacks. The integration of these tools provides a robust network security monitoring capability essential for modern cybersecurity operations.

Key takeaways include:

* IDS/IPS are crucial components of defense-in-depth strategy
* Regular updates and tuning are essential for effectiveness
* Integration with SIEM provides comprehensive security visibility
* Each tool (Suricata, Snort, Zeek) has specific strengths for different detection scenarios
* Understanding attack patterns and network protocols is crucial for effective rule development
