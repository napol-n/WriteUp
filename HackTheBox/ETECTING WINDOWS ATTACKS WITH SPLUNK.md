DETECTING WINDOWS ATTACKS WITH SPLUNK

## Detecting Common User/Domain Recon


### Overview

This document explains how adversaries perform Active Directory (AD) domain reconnaissance in Windows environments and how defenders can detect such activities using Splunk. It covers techniques attackers use with native Windows executables and specialized tools such as BloodHound/SharpHound, and provides specific Splunk search queries to identify these activities.
The content highlights the importance of monitoring process creation events, LDAP queries, and unusual command executions to detect reconnaissance attempts early. It also details challenges in monitoring, such as lack of LDAP query logging by default, and proposes methods like Event Tracing for Windows (ETW) and SilkETW/SilkService as effective detection strategies.

### Key Points

Domain Reconnaissance Overview
AD reconnaissance is a key stage in cyberattacks, used to gather details on architecture, security, and vulnerabilities.
Attackers seek Domain Controllers, accounts, trust relationships, group policies, and high-value targets.
Reconnaissance with Native Windows Executables
Attackers use commands like whoami /all, net user /domain, net group "Domain Admins" /domain, arp -a, and nltest /domain_trusts.
Example: net group "Domain Admins" /domain reveals domain administrators such as Administrator, BRUCE_GEORGE, CHANCE_ARMSTRONG, HOPE_ADKINS, TYLER_MORRIS.
BloodHound/SharpHound Reconnaissance
BloodHound is an open-source tool for visualizing AD attack paths using graph theory.
SharpHound collects data (e.g., enumerated 3,385 objects in example run) and packages it for BloodHound analysis.
Detection Challenges and Solutions
Monitoring LDAP queries is difficult since Windows logs don’t capture them by default.
Event 1644 provides partial visibility but is limited.
A better method is using ETW with SilkETW & SilkService, which can log LDAP client activity and apply Yara rules.
Microsoft’s Recon LDAP Filter List
Microsoft ATP identified commonly used LDAP filters in tools like Metasploit and PowerView, enabling defenders to detect reconnaissance more effectively.
Splunk Detection for Native Executables
Example search (timeframe: earliest=1690447949 latest=1690450687) filters Sysmon Event ID 1 (process creation).
Looks for suspicious processes (e.g., arp.exe, ipconfig.exe, net.exe) executed together, especially >3 commands from same parent process.
Example detection: user JOLENE_MCGEE ran commands on BLUE.corp.local via rundll32.exe.
Splunk Detection for BloodHound Activity
Example search (timeframe: earliest=1690195896 latest=1690285475) targets SilkService logs.
Filters LDAP queries containing samAccountType=805306368.
Flags suspicious activity if >10 such queries occur by the same process.
Example: SharpHound process generated 259 LDAP events on BLUE.corp.local between 7/24/23–7/25/23.
Detailed Explanation
Domain Reconnaissance Overview
AD is central to enterprise identity and access. Attackers recon it to map users, groups, and policies.
Successful recon allows privilege escalation and lateral movement inside the network.
Reconnaissance with Native Executables
Windows comes with built-in tools attackers exploit to avoid detection.
Example output from net group showed specific administrators, demonstrating how attackers identify privileged users quickly.
Defenders can monitor command-line usage and PowerShell scripts for anomalies.
BloodHound/SharpHound Reconnaissance
BloodHound builds a visual graph of AD entities (users, groups, computers).
SharpHound runs collectors to gather AD info via LDAP and SMB queries, compresses into BloodHound.zip.
In the example, collection began and ended within the same minute (4:29 PM), showing how fast enumeration can occur.
Detection Challenges and Solutions
LDAP queries by recon tools don’t show up in normal logs.
Event 1644 tracks LDAP performance but misses key events.
ETW (Event Tracing for Windows) with SilkETW captures fine-grained LDAP client activity.
Can output to Windows Event Log.
Supports Yara rules to detect patterns such as ASREPRoast attempts.
This provides SOC analysts better visibility.
Microsoft’s Recon LDAP Filter List
Tools like Metasploit (enum_ad_user_comments, enum_ad_computers) and PowerView (Get-NetUser, Get-NetOU) rely on LDAP queries.
By matching common LDAP filters, defenders can identify BloodHound-like activity.
Splunk Detection for Native Executables
Splunk query filters Sysmon process creation logs (Event ID 1).
Filters for recon commands (arp, ipconfig, net, etc.) or when run via cmd.exe/powershell.exe.
Aggregates results by parent process and user, flagging cases with >3 different recon commands.
Example: user JOLENE_MCGEE executed recon via rundll32.exe on BLUE.corp.local, suspicious because rundll32 is not a typical parent for these tools.
Splunk Detection for BloodHound Activity
Splunk query pulls logs from SilkService (ETW wrapper).
Extracts structured LDAP query data with spath.
Filters LDAP queries for samAccountType=805306368 (indicating user accounts).
Flags cases where one process makes >10 such queries.
Example: SharpHound executed on BLUE.corp.local, producing 259 LDAP queries in 24 hours, confirming automated enumeration.

### Conclusion / Takeaways

AD reconnaissance is a critical early attack stage that defenders must detect to prevent privilege escalation.
Attackers often use built-in Windows commands to avoid detection; monitoring Sysmon Event ID 1 and command-line activity helps spot this.
BloodHound/SharpHound are powerful tools for attackers, but their activity can be detected by monitoring LDAP queries.
Default Windows logging is insufficient; ETW with SilkETW/SilkService offers better visibility.
Splunk searches with filters for process creation events and LDAP query patterns provide effective detection strategies.
Security teams should leverage Microsoft’s list of LDAP filters and establish baselines to identify abnormal AD recon activity.

### Glossary

Active Directory (AD): Microsoft’s directory service for managing users, groups, and network resources.
LDAP (Lightweight Directory Access Protocol): Protocol used to query and modify directory services like AD.
ETW (Event Tracing for Windows): A high-performance logging mechanism built into Windows.
Sysmon: Windows system service that logs process creation, network connections, and other system events.
BloodHound: Open-source AD recon tool that maps relationships and attack paths.
SharpHound: Data collection tool for BloodHound, written in C#.
Yara: A tool for pattern-matching rules used in malware and anomaly detection.
1️⃣ index=* earliest=0 latest=now
index=* → Search all indexes in Splunk.
earliest=0 latest=now → Search events from the beginning of time (Unix timestamp 0 = Jan 1, 1970) up to the current time.
Summary: Retrieves all events in Splunk from the earliest to now.
**2️⃣ ( source="WinEventLog:SilkService-Log" OR source="WinEventLog:Microsoft-Windows-LDAP-Client/Operational" OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" )
Filters events from specific sources related to AD/LDAP monitoring:
SilkService-Log → Logs collected by SilkETW monitoring LDAP activity
Microsoft-Windows-LDAP-Client/Operational → Windows LDAP client event logs
Sysmon/Operational → Sysmon logs (process creation, network activity, registry changes, etc.)
OR → Includes events from any of these sources
3️⃣ | spath input=Message
spath → Parses JSON or XML fields in an event.
input=Message → Uses the raw Message field containing XML/JSON data.
Result: Extracts fields from structured Message content for later filtering.
4️⃣ | rename XmlEventData.* as *
Many XML logs prefix field names with XmlEventData.
This command removes the prefix so you can reference fields easily.
Example: XmlEventData.ProcessName → ProcessName
**5️⃣ | search SearchFilter="*(samAccountType=805306368)*" OR Message="*(samAccountType=805306368)*"
Filters events related to LDAP queries targeting user accounts in Active Directory.
*(samAccountType=805306368)* → Searches for user accounts.
SearchFilter → Field extracted by SilkETW
OR Message → If SearchFilter is missing, check the raw Message field.
**6️⃣ | eval proc=coalesce(ProcessName, ProcessName_s, Process, process_name, process)
Creates a new field proc.
coalesce(...) → Takes the first non-null value from the list of possible fields.
This handles differences in how various logs record the process name.
Result: proc contains the process name that executed the LDAP query.
7️⃣ | stats count by proc
Counts the number of events per process (proc).
Shows which processes are performing LDAP queries and how many times.
8️⃣ | sort -count
Sorts the results from highest to lowest count.
Highlights the processes that performed the most LDAP queries.
Overall Summary
This query:
Selects all events from the beginning to now.
Filters events from sources related to LDAP/AD reconnaissance.
Extracts fields from XML/JSON data.
Filters events that contain LDAP queries targeting user accounts (samAccountType=805306368).
Normalizes process names into a single field (proc).
Counts how many times each process executed LDAP queries.
Sorts the processes by activity, showing the most active reconnaissance processes first.
✅ Result: A table of process names and counts that helps identify which processes are performing Active Directory reconnaissance.
1 Modify and employ the Splunk search provided at the end of this section on all ingested data (All time) to find all process names that made LDAP queries where the filter includes the string *(samAccountType=805306368)*. Enter the missing process name from the following list as your answer. N/A, Rubeus, SharpHound, mmc, powershell, _
ANSWER rundll32
Detecting Password Spraying

### Overview

This section explains password spraying attacks—a type of credential attack where attackers attempt a small set of common passwords across many user accounts to avoid account lockouts. It also outlines methods to detect such attacks using Windows event logs and Splunk queries.
The focus is on identifying patterns of failed login attempts from the same source IP across multiple accounts, using specific Event IDs like 4625, 4768, 4776, and 4648 to pinpoint suspicious activity. Splunk is used to aggregate and analyze these events for easier detection.

### Key Points

Password Spraying Attack Overview
Attackers try a few common passwords across many accounts to evade lockout policies.
Example tool: Spray 2.1 by Jacob Wilkin, using passwords like "Winter2016" and "Autumn17" against SMB servers.
Detection Using Windows Logs
Event logs indicate failed login attempts and authentication issues.
Relevant Event IDs include:
a. 4625 – Failed Logon
b. 4768 and ErrorCode 0x6 – Kerberos Invalid Users
c. 4768 and ErrorCode 0x12 – Kerberos Disabled Users
d. 4776 and ErrorCode 0xC000006A – NTLM Invalid Users
e. 4776 and ErrorCode 0xC0000064 – NTLM Wrong Password
f. 4648 – Authenticate Using Explicit Credentials
g. 4771 – Kerberos Pre-Authentication Failed
Splunk Detection for Password Spraying
Splunk query filters EventCode 4625 for failed logons.
Groups events into 15-minute intervals using bin span=15m.
Aggregates events by source, network address, destination, EventCode, and failure reason.
Calculates unique users involved (values(user) and dc(user)) to identify multiple account attempts from the same source.
Example detection: source "KALI" (IP 10.10.0.201) attempted multiple logons on BLUE.corp.local, failing due to "Unknown user name or bad password."
Detailed Explanation
Password Spraying Attack Overview
Unlike brute-force attacks, password spraying targets multiple accounts but with few passwords per account.
Purpose: avoid triggering account lockout policies, which prevent brute-force attacks by locking accounts after repeated failed attempts.
Tools like Spray 2.1 allow automated spraying against SMB or other authentication services.
Example: spraying passwords "Winter2016" and "Autumn17" across a user list.
Detection Using Windows Logs
Failed logons create Event ID 4625 in Windows Security logs.
Other logs include Kerberos errors (4768, 4771) and NTLM authentication failures (4776), which provide context on invalid accounts, disabled users, or incorrect passwords.
By monitoring these Event IDs across accounts, security teams can identify coordinated attempts indicating password spraying.
Splunk Detection for Password Spraying
Splunk search begins by filtering index=main and source=WinEventLog:Security for EventCode 4625.
Timeframe is set using Unix timestamps (e.g., 1690280680 to 1690289489).
bin span=15m _time groups events into 15-minute intervals, making trends visible.
stats command aggregates failed logons:
values(user) as Users lists all user accounts targeted.
dc(user) as dc_user counts distinct users per source IP.
Multiple failed logons across many users from a single IP suggest password spraying.
Example: KALI (10.10.0.201) attempted access to BLUE.corp.local with multiple accounts, all failing, indicating a spraying attack.

### Conclusion / Takeaways

Password spraying is a stealthy attack designed to evade account lockouts by spreading attempts across many accounts.
Detection relies on monitoring Windows Event IDs such as 4625, 4768, 4776, 4648, and 4771 for failed authentication attempts.
Aggregating failed logons in time intervals (e.g., 15 minutes) helps identify patterns.
Splunk queries can efficiently detect password spraying by analyzing source IPs and number of accounts attempted.
Regular monitoring and correlation of failed login events across multiple users improve early detection and response.
Tools like Spray 2.1 demonstrate how attackers automate these attempts, emphasizing the need for proactive detection strategies.

### Glossary

Password Spraying: Credential attack using a few common passwords across many accounts to avoid lockouts.
SMB (Server Message Block): Network protocol for file and resource sharing in Windows networks.
Event ID 4625: Windows Security log indicating a failed logon attempt.
dc(user): Distinct count of user accounts in Splunk statistics.
Spray 2.1: A password spraying tool for testing multiple accounts with common passwords.
Employ the Splunk search provided at the end of this section on all ingested data (All time) and enter the targeted user on SQLSERVER.corp.local as your answer.
From the Splunk search you ran:
index=* earliest=0 latest=now source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
| search dest="SQLSERVER.corp.local"
| sort -dc_user
Results you obtained:
Destination: SQLSERVER.corp.local
EventCode: 4625 (Failed Logon)
Failure Reason: Unknown user name or bad password
Users: sa
✅ Conclusion: The targeted user on SQLSERVER.corp.local is sa.
This means that the failed login attempts on SQLSERVER were primarily aimed at the sa account, which is a common administrative account in SQL Server.
ANSWER sa
Detecting Responder-like Attacks

### Overview

This section explains Responder-like attacks, which involve LLMNR, NBT-NS, and mDNS poisoning—techniques attackers use to capture Windows credentials at the network level. It describes how attackers exploit weaknesses in local name resolution protocols and outlines methods for detecting these attacks using PowerShell scripts, Windows event logs, and Splunk.
The focus is on identifying suspicious hostname resolution queries, anomalous responses, and explicit logon attempts to rogue servers, enabling security teams to detect and respond to credential theft attempts.

### Key Points

LLMNR/NBT-NS/mDNS Poisoning Overview
LLMNR and NBT-NS resolve hostnames locally when DNS fails but lack security, making them vulnerable to spoofing.
Attackers use tools like Responder to respond to queries for mistyped hostnames and capture NetNTLM hashes.
Attack Steps
Victim queries a mistyped hostname (e.g., fileshrae) via DNS; DNS fails.
LLMNR/NBT-NS is queried.
Attacker responds with their own IP, poisoning the resolution.
Result: attacker obtains NetNTLM hashes for cracking or relaying.
Detection Opportunities
Monitor abnormal LLMNR/NBT-NS traffic (high query volume from a single source).
Deploy honeypots for non-existent hostnames; successful resolution indicates spoofing.
Use PowerShell scripts to log spoofed hostname queries and detect attacker IPs.
Example:



New-EventLog -LogName Application -Source LLMNRDetection
Write-EventLog -LogName Application -Source LLMNRDetection -EventId 19001 -Message $msg -EntryType Warning
Splunk Detection Using PowerShell Logs
Splunk query filters SourceName=LLMNRDetection to view logged spoofing events.
Example output: computer BLUE.corp.local, source LLMNRDetection, showing attacker IPs ::1 and 10.10.0.221.
Splunk Detection Using Sysmon Event ID 22
Event ID 22 tracks DNS queries for non-existent/mistyped hosts.
Example: timestamp 2023-07-25 13:01:52, computer BLUE.corp.local, query name myfileshar3, results include ::1; ::ffff:10.10.0.221.
Splunk Detection Using Event 4648
Event 4648 logs explicit logons to potentially rogue file shares.
Example: timestamp 2023-07-25 13:13:50, user Administrator attempts logon to ILUA.LOCAL using explicit credentials by CORP\JOLENE_MCGEE.
Detailed Explanation
LLMNR/NBT-NS/mDNS Poisoning Overview
LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) resolve hostnames locally when DNS fails.
Lack of authentication allows attackers to spoof responses and intercept credentials.
Responder is commonly used to capture NetNTLM hashes during such attacks.
Attack Steps
Victim types incorrect hostname (e.g., fileshrae).
DNS fails to resolve it.
Victim sends LLMNR/NBT-NS query.
Attacker responds, poisoning the resolution with their IP.
Victim communicates with attacker-controlled system; NetNTLM hashes are captured for cracking or relaying.
Detection Opportunities
Monitor network traffic for unusual LLMNR/NBT-NS requests.
Set up honeypot names to detect spoofing (resolution success on non-existent names).
PowerShell scripts can log requests to false hostnames and attacker IPs.
Use New-EventLog and Write-EventLog cmdlets to generate logs for Splunk ingestion.
Splunk Detection Using PowerShell Logs
Splunk query example:



index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
Displays events indicating spoofed queries, with attacker IPs and affected hosts.
Splunk Detection Using Sysmon Event ID 22
Event ID 22 tracks DNS queries.
Splunk query example:



index=main earliest=1690290078 latest=1690291207 EventCode=22
| table _time, Computer, user, Image, QueryName, QueryResults
Highlights mistyped hostnames and corresponding resolution results.
Example shows query myfileshar3 resolved to ::1 and 10.10.0.221.
Splunk Detection Using Event 4648
Monitors explicit logons to potentially rogue file shares.
Splunk query example:



index=main earliest=1690290814 latest=1690291207 EventCode IN (4648)
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
Captures attempts like Administrator logging onto ILUA.LOCAL with credentials of CORP\JOLENE_MCGEE.

### Conclusion / Takeaways

Responder-like attacks exploit LLMNR, NBT-NS, and mDNS to capture NetNTLM hashes.
Attack detection involves monitoring network traffic, PowerShell logs, and DNS queries.
Honeypot hostnames help identify spoofed resolutions.
Splunk queries on LLMNRDetection, Sysmon Event 22, and Event 4648 provide visibility into these attacks.
Explicit logons to rogue servers should be investigated as they may indicate credential theft.
Combining multiple detection methods improves early warning and reduces the risk of lateral movement.

### Glossary

LLMNR: Link-Local Multicast Name Resolution, used for local hostname resolution when DNS fails.
NBT-NS: NetBIOS Name Service, used to resolve NetBIOS names to IP addresses.
mDNS: Multicast DNS, resolves hostnames within local networks.
NetNTLM hash: A hashed representation of a user's password used in Windows authentication.
Event ID 22: Sysmon event that tracks DNS queries.
Event ID 4648: Windows Security log for explicit credential logon attempts.
Responder: Tool for poisoning LLMNR/NBT-NS/mDNS to capture credentials.
Modify and employ the provided Sysmon Event 22-based Splunk search on all ingested data (All time) to identify all share names whose location was spoofed by 10.10.0.221. Enter the missing share name from the following list as your answer. myshare, myfileshar3, _
1) The Splunk query you ran
index=* earliest=0 latest=now EventCode=22
| search QueryResults="*10.10.0.221*" OR Message="*10.10.0.221*"
| table _time, Computer, user, Image, QueryName, QueryResults
| sort 0 _time
index=* → Search across all indexes.
earliest=0 latest=now → Include all events from the beginning of time up to the current time.
EventCode=22 → Filter only Sysmon Event ID 22, which tracks DNS/LLMNR/NBT-NS queries.
search QueryResults="10.10.0.221" OR Message="10.10.0.221" → Keep only events where the query results include the spoofed IP 10.10.0.221.
table _time, Computer, user, Image, QueryName, QueryResults → Display the relevant fields in a table.
sort 0 _time → Sort by timestamp ascending (oldest to newest).
2) Key results from your table
From the output you provided, the relevant entries are:
The QueryResults field shows the response IP 10.10.0.221, which indicates a spoofed share.
The QueryName field contains the share names requested by clients.
3) How to identify the missing share
Run the query filtering EventCode 22 and results containing 10.10.0.221.
Display QueryName in the table to see which shares were resolved to the spoofed IP.
Compare the list of shares you found with the options provided: myshare, myfileshar3, _.
The missing share that is not in the provided list is financefileshare.
4) Answer
The share name to enter is:
financefileshare
Detecting Kerberoasting/AS-REProasting

### Overview

This section covers Kerberoasting and AS-REPRoasting, two Active Directory attacks targeting Kerberos authentication. Both techniques aim to obtain password hashes for offline cracking, but they exploit different aspects of Kerberos:
Kerberoasting: Targets service accounts with Service Principal Names (SPNs). Attackers request TGS tickets, extract encrypted hashes, and crack them offline.
AS-REPRoasting: Targets user accounts with pre-authentication disabled. Attackers request TGTs without needing credentials, capturing hashes for offline cracking.
Detection relies on monitoring LDAP activity, Kerberos event logs, and explicit logon events, using tools like Splunkto correlate suspicious requests and incomplete authentication sequences.
Kerberoasting
Attack Steps
Identify Target Service Accounts
Enumerate AD for service accounts with SPNs (e.g., SQL, IIS, Exchange).
Request TGS Tickets
Use identified service accounts to request Kerberos service tickets (TGS) from the KDC.
Tickets contain encrypted service account hashes.
Offline Brute-Force Attack
Extract hashes from TGS tickets and crack them using tools like Hashcat or John the Ripper.
Benign Service Access (for comparison)
TGT Request → TGS Request → Client Connection → Server Validation
Logged events:
4768: TGT requested
4769: TGS requested
4624: Successful logon on server
4648: Logon with explicit credentials (optional for service accounts)
Kerberoasting Detection Logic
Compare TGS requests (4769) with subsequent logon events (4648).
Suspicious behavior: TGS request occurs without a logon, indicating ticket extraction attempts.
Splunk Queries
Benign TGS Requests
index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
SPN Querying (LDAP activity)
index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
TGS Requests without subsequent logon
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time
| search username!=*$
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
Transaction-based detection
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)
| where closed_txn=0 AND EventCode = 4769
| table _time, EventCode, service_name, username
Focus: Incomplete transactions where 4769 exists but 4648 does not, indicating potential Kerberoasting.
AS-REPRoasting
Attack Steps
Identify Target Users
Look for accounts without Kerberos pre-authentication enabled or with unconstrained delegation.
Request AS-REQ Service Tickets
Request TGTs for target users without needing credentials.
Offline Brute-Force Attack
Capture AS-REP responses and crack offline.
Kerberos Pre-Authentication
Enabled: AS-REQ includes encrypted timestamp; KDC validates before issuing TGT.
Disabled: AS-REQ does not require a valid timestamp; attacker can request TGT without knowing password.
Detection Opportunities
Monitor LDAP queries for accounts with pre-authentication disabled.
Event ID 4768 contains PreAuthType field:
0 = Pre-authentication disabled
1 = Pre-authentication enabled
Splunk Queries
Accounts with Pre-Auth Disabled (LDAP search)
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
TGT Requests for Accounts with Pre-Auth Disabled
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
Focus: Identify accounts being targeted without pre-authentication, indicative of AS-REPRoasting.

### Takeaways

Kerberoasting: Detect TGS requests for SPNs without subsequent logons.
AS-REPRoasting: Detect TGT requests for accounts with pre-authentication disabled.
Monitoring LDAP activity and correlating Event IDs 4768, 4769, 4648 is key.
Using Splunk queries, analysts can flag suspicious sequences for investigation before offline cracking occurs.
Modify and employ the Splunk search provided at the "Detecting Kerberoasting - SPN Querying" part of this section on all ingested data (All time). Enter the name of the user who initiated the process that executed an LDAP query containing the "*(&(samAccountType=805306368)(servicePrincipalName=*)*" string at 2023-07-26 16:42:44 as your answer. Answer format: CORP\_
CORP\TAYLOR_BENTON
index=main earliest="07/26/2023:16:41:44" latest="07/26/2023:16:43:14" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| spath input=Message
| rename XmlEventData.* as *
| table _time, Computer, ProcessId, ParentProcessId, Image, ParentImage, User, CommandLine
| sort 0 _time
Search Explanation
1. index=main earliest="07/26/2023:16:41:44" latest="07/26/2023:16:43:14" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
index=main → Search within the main index.
earliest / latest → Limit the search to events between 16:41:44 and 16:43:14 on July 26, 2023.
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" → Only consider logs coming from Sysmon’s Operational channel.
EventCode=1 → Filter for Sysmon Process Creation events, which record every new process started on the host.
2. | spath input=Message
Extracts structured fields from the XML message in each event. Sysmon logs are in XML format, and spath allows Splunk to parse and make XML fields accessible.
3. | rename XmlEventData.* as *
Renames all fields under XmlEventData to top-level fields for easier access.
Example: XmlEventData.Image becomes just Image.
4. | table _time, Computer, ProcessId, ParentProcessId, Image, ParentImage, User, CommandLine
Displays only the specified fields in a tabular format:
_time → Event timestamp
Computer → Hostname where the process was started
ProcessId → ID of the process
ParentProcessId → ID of the parent process
Image → Path to the executable that was run
ParentImage → Path to the parent process executable
User → Account that ran the process
CommandLine → Full command line used to start the process
5. | sort 0 _time
Sorts the events in ascending order by timestamp (_time).
0 tells Splunk to sort all events, not just the default first 10,000.
Detecting Pass-the-Hash

### Overview

This section covers Pass-the-Hash (PtH) attacks, a technique in which attackers authenticate to remote systems using a captured NTLM hash instead of the plaintext password. This allows lateral movement without knowing user passwords. Detection relies on monitoring logon events and LSASS memory access, especially correlating LogonType 9 (NewCredentials) with Sysmon EventCode 10.
Pass-the-Hash (PtH)
Attack Steps
Extract NTLM Hash
Requires administrative access to the compromised system.
Tools like Mimikatz extract hashes from memory (LSASS process).
Example: NTLM hash for Administrator: fc525c9683e8fe067095ba2ddc971889.
Authenticate Using Hash
Use the NTLM hash to authenticate to other systems or network resources.
No plaintext password needed.
Lateral Movement
Attacker moves across the network using stolen hashes.
Example: Access \dc01\c$ directories as SYSTEM or Administrator.
Windows Access Tokens & Alternate Credentials
Access Token: Defines security context of a process/thread, including identity and privileges.
Alternate Credentials: Allow execution as another user without logging out.
runas /netonly: Generates a new access token for remote access only; local user remains unchanged.
Detection Note:
Regular runas usage creates LogonType 2 (Interactive).
runas /netonly creates LogonType 9 (NewCredentials).
PtH modifies LSASS memory directly, enhancing detection by correlating NewCredentials events with Sysmon EventCode 10.
Pass-the-Hash Detection Opportunities
Security Event Logs
Event ID 4624, LogonType 9 indicates potential PtH or runas /netonly.
Sysmon Process Access
EventCode 10 targeting lsass.exe indicates memory access attempts.
Correlation
Combine LogonType 9 events with LSASS access for more accurate detection.
Splunk Queries
Basic LogonType 9 Detection
index=main earliest=1690450708 latest=1690451116 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
Enhanced Detection (Correlate LSASS Access)
index=main earliest=1690450689 latest=1690451116
(source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe")
OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
Query Breakdown:
Filters for Sysmon EventCode 10 targeting lsass.exe (excluding legitimate Defender processes) or Security LogonType 9 events.
Sorts events chronologically.
Groups related LSASS access and new logons within 1 minute using transaction.
Aggregates by host, source process, and account details.
Removes count field for cleaner output.

### Takeaways

Pass-the-Hash attacks rely on NTLM hashes for lateral movement.
Key detection signals: LogonType 9 events and LSASS memory access.
Splunk correlation improves accuracy and reduces false positives from legitimate runas /netonly usage.
A Pass-the-Hash attack took place during the following timeframe earliest=1690543380 latest=1690545180. Enter the involved ComputerName as your answer.
index=main earliest=1690543380 latest=1690545180 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
ran this Splunk search for the given epoch timeframe (earliest=1690543380 latest=1690545180):
index=main earliest=1690543380 latest=1690545180 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
This query looks for Windows Security 4624 (Logon) events where:
Logon_Type=9 — a NewCredentials type (occurs with runas /netonly or other “new credentials” flows),
Logon_Process=seclogo — the logon process name observed for these events.
What the result showed
The query returned a single relevant event:
_time: 2023-07-28 11:27:38
ComputerName: BLUE.corp.local
EventCode: 4624
user: SYSTEM
Network_Account_Domain: CORP
Network_Account_Name: RAUL_LYNN
Logon_Type: 9
Logon_Process: seclogo
Why this indicates a Pass‑the‑Hash (PtH) candidate
Logon Type 9 (NewCredentials): This logon type appears when a process obtains new network credentials without replacing the interactive logon token (e.g., runas /netonly or other explicit credential usage). PtH attacks often show up in logs as NewCredentials events because the attacker is using alternate authentication material (hashes/ticketing) to access remote resources.
Logon Process = seclogo: This is the logon process name recorded for the event; including it helps reduce noisy matches and focus on relevant NewCredentials events.
Context (what to correlate next): A PtH event is more convincing when correlated with a Sysmon Event 10 (Process Access) targeting lsass.exe around the same timeframe (indicating LSASS memory access to extract hashes). Even without that correlation in this specific query, a 4624/LogonType=9 event is a strong signal to investigate further.

### Conclusion / Final answer

Based on the query and results, the ComputerName involved in the Pass‑the‑Hash timeframe you specified is:
BLUE.corp.local
Detecting Pass-the-Ticket

### Overview

This section covers Pass-the-Ticket (PtT) attacks, a lateral movement technique where attackers abuse Kerberos TGT and TGS tickets instead of NTLM hashes. PtT allows authentication to other systems without knowing passwords. Detection focuses on anomalies in Kerberos ticket requests and usage, particularly missing TGT requests (Event ID 4768) prior to TGS requests (Event ID 4769) or renewals (Event ID 4770).
Pass-the-Ticket (PtT)
Attack Steps
Gain Access
Attacker compromises a system or escalates privileges to admin level.
Extract Kerberos Tickets
Tools like Mimikatz or Rubeus extract TGT or TGS tickets from memory.
Example: Administrator@LAB.INTERNAL.LOCAL, Base64-encoded TGT, valid for several hours.
Inject Tickets
Tickets are imported into the current logon session (ptt in Rubeus).
Authenticate to other systems without plaintext passwords.
Lateral Movement
Use the imported ticket to access resources across the network.
Kerberos Authentication Process
Client requests TGT from KDC.
KDC validates credentials and issues TGT.
Client requests TGS for a service using TGT.
KDC issues TGS encrypted with the service account key.
Client presents TGS to the server for authentication.
Note: PtT can skip the initial TGT request if importing a ticket, causing detection anomalies.
Related Windows Security Events
Detection Opportunity:
PtT often shows Event ID 4769 or 4770 without a preceding 4768 from the same system.
Look for mismatched Service/Host IDs and unusual source/destination IPs.
Monitor Pre-Authentication failures (4771) with unusual types or failure codes.
Splunk Detection Query
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
Query Breakdown:
Filters Kerberos-related Security events (4768, 4769, 4770) excluding machine accounts (*$).
Extracts username from user field.
Converts IPv6-style addresses to IPv4 (src_ip_4).
Groups events by username and source IP, starting with EventCode 4768, allowing transactions up to 10 hours.
Keeps open transactions (closed_txn=0) to identify TGS requests without prior TGT requests.
Displays results in a table for easy analysis.

### Takeaways

PtT attacks abuse valid Kerberos tickets for lateral movement.
Detection signals: Missing TGT requests, unusual TGS renewals, and service-host mismatches.
Behavioral correlation with user/system activity reduces false positives.
Execute the Splunk search provided at the end of this section to find all usernames that may be have executed a Pass-the-Ticket attack. Enter the missing username from the following list as your answer. Administrator, _
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
ANSWER YOUNG_WILKINSON
Overpass-the-Hash

### Overview

This section covers Overpass-the-Hash (Pass-the-Key) attacks, a variant where attackers use stolen NTLM hashes or AES keys to request Kerberos TGTs instead of authenticating via NTLM. This allows stealthy lateral movement using Kerberos authentication, bypassing NTLM and some access controls. Detection focuses on unusual Kerberos TGT requests, particularly from unexpected processes or hosts.
Overpass-the-Hash (OtH)
Attack Steps
Obtain NTLM Hash
Attacker gains local admin access and extracts NTLM hash using Mimikatz.
Example: SYSTEM or Administrator NTLM hashes.
Request Kerberos TGT
Use Rubeus to craft a raw AS-REQ request for a user.
Elevated privileges on the host are not required, making it stealthier than Pass-the-Hash.
Successful TGT request returns a Base64-encoded ticket for the user.
Inject TGT
Submit the requested TGT into the logon session (similar to Pass-the-Ticket).
Allows lateral movement using Kerberos rather than NTLM.
Detection Opportunities
Note: Traditional PtT detection may not trigger unless the ticket is used on another host.
Splunk Detection Query (Targeting Rubeus)
index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
Query Breakdown:
Filters Sysmon operational logs:
EventCode 3: Network connections to Kerberos port 88 from unusual processes (Image!=*lsass.exe).
EventCode 1: Process creation events for context.
Aggregates process names by process_id.
Keeps only network events (EventCode=3) for Kerberos traffic.
Counts occurrences by time, computer, destination IP/port, image, and process.
Removes the temporary count field for clarity.

### Takeaways

Overpass-the-Hash enables Kerberos authentication using stolen NTLM hashes, bypassing NTLM checks.
Detection signals include unusual TGT requests (4768) and network connections to port 88 by unexpected processes.
Monitoring process origin, logon sessions, and network traffic is key to identifying OtH activity.
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
From the Splunk search you ran (with All time), the Image field returned the following values:
C:\Windows\System32\rundl132.exe
C:\Users\LANDON_HINES\Downloads\Rubeus.exe
C:\Users\ADAM\Downloads\Rubeus.exe
C:\Users\JERRI_BALLARD\Downloads\Rubeus.exe
The task was to identify the missing image from the list Rubeus.exe, _.exe.
By comparing the results:
Rubeus.exe is already listed.
The other executable that appears alongside Rubeus in the search results is C:\Windows\System32\rundl132.exe.
Therefore, the missing image name is:
rundl132.exe
Detecting Golden Tickets/Silver Tickets

### Overview: Golden Tickets & Silver Tickets

This section explains Golden Ticket and Silver Ticket attacks—both involve forging Kerberos tickets to gain unauthorized access in an Active Directory (AD) environment. Detection focuses on Windows Event Logs and user/service behavior anomalies.
1. Golden Ticket
What It Is
Forged TGT (Ticket Granting Ticket) to impersonate a domain administrator.
Provides full domain access with long validity and persistence.
Attack Steps
Extract KRBTGT hash
Via DCSync, NTDS.dit, or LSASS memory dumps on Domain Controller.
Forge TGT
Assign arbitrary user as domain admin using tools like Mimikatz.
Inject TGT
Similar to Pass-the-Ticket injection.
Detection Opportunities
Monitor for KRBTGT hash extraction:
DCSync
NTDS.dit access
LSASS memory reads (Sysmon Event ID 10)
Treat as Pass-the-Ticket events (Event IDs 4768, 4769, 4770).
Splunk Detection
index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
2. Silver Ticket
What It Is
Forged TGS (Ticket Granting Service) ticket for a specific service (e.g., SharePoint, MSSQL).
Scope-limited: Only allows access to the targeted service, not the full domain.
Attack Steps
Extract service account hash
NTLM hash of target service/computer account.
Generate Silver Ticket
Use Mimikatz to forge TGS for the specific service.
Inject Ticket
Similar to Pass-the-Ticket.
Detection Opportunities
Difficult due to limited scope and forged tickets.
Check for:
Event ID 4720: Newly created user accounts.
Event ID 4672: Special privileges assigned during logon.
Splunk Detection Examples
a) Compare new users vs logged-in users
index=main latest=1690448444 EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
index=main latest=1690545656 EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| eval last24h = 1690451977
| where firstTime > last24h
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
b) Detect anomalous privileges on new logon
index=main latest=1690545656 EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h = 1690451977
| where firstTime > last24h
| table firstTime, ComputerName, Account_Name
| convert ctime(firstTime)
✅ Key Takeaways
Golden Ticket: Full domain admin, forged TGT, highly persistent.
Silver Ticket: Targeted service access, forged TGS, limited scope.
Detection requires correlating Event IDs 4768/4769/4770 with user and system behavior, looking for anomalies in logon, privilege assignment, and account creation.
For which "service" did the user named Barbi generate a silver ticket?
CIFS
Detecting Unconstrained Delegation/Constrained Delegation Attacks

### Overview: Unconstrained & Constrained Delegation Attacks

This section explains delegation attacks in Active Directory (AD), where services can impersonate users to access other resources. Detection relies on PowerShell logs, Sysmon logs, and unusual Kerberos activity.
1. Unconstrained Delegation
What It Is
Allows a service to authenticate on behalf of any user to any resource.
Example: Web server accesses a database using the user’s credentials.
Attack Steps
Discover accounts with Unconstrained Delegation
PowerShell / LDAP query for TrustedForDelegation.
Compromise the system with delegation enabled.
Extract TGTs from memory using tools like Mimikatz or request with Rubeus.
Reuse TGTs to access other services.
Detection Opportunities
Monitor PowerShell script block logging (Event ID 4104).
Detect unusual Kerberos ticket reuse (Pass-the-Ticket detection).
Look for unexpected network connections to TCP/UDP port 88.
Splunk Detection Example
index=main earliest=1690544538 latest=1690544540 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*"
| table _time, ComputerName, EventCode, Message
2. Constrained Delegation
What It Is
Limits delegation to specific services only (via msDS-AllowedToDelegateTo).
Safer than Unconstrained Delegation but can still be abused with S4U2self/S4U2proxy.
Attack Steps
Identify constrained delegation accounts
PowerShell / LDAP queries for msDS-AllowedToDelegateTo.
Obtain TGT of principal (memory or hash-based request via Rubeus).
Use S4U technique to impersonate high-privilege users:
S4U2self: Service requests TGS for itself on behalf of user.
S4U2proxy: Service requests TGS to another SPN for impersonated user.
Inject ticket and access services as impersonated user.
Detection Opportunities
PowerShell command or LDAP queries for discovery.
Rubeus connections to Domain Controller (TCP/UDP port 88).
Sysmon EventCode 3 showing unusual processes requesting Kerberos tickets.
Splunk Detection Examples
PowerShell Logs
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
Sysmon Logs
index=main earliest=1690562367 latest=1690562556 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
✅ Key Takeaways
Unconstrained Delegation: Service can impersonate any user → higher risk.
Constrained Delegation: Service impersonation restricted to specific SPNs → requires S4U attacks to escalate.
Detection relies on PowerShell/LDAP monitoring, ticket reuse detection, and unusual Kerberos network activity.
Employ the Splunk search provided at the "Detecting Unconstrained Delegation Attacks With Splunk" part of this section on all ingested data (All time). Enter the name of the other computer on which there are traces of reconnaissance related to Unconstrained Delegation as your answer. Answer format: _.corp.local
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
Why: The Splunk search for PowerShell EventCode 4104 with Message="*msDS-AllowedToDelegateTo*" shows both events on DC01.corp.local. This indicates that this computer has traces of reconnaissance activity looking for delegation settings in Active Directory (Unconstrained or Constrained Delegation).

### Key points:

EventCode 4104 → PowerShell ScriptBlock Logging, captures executed scripts.
Message content → Get-ADObject -fi {(msDs-AllowedToDelegateTo -like "*")} shows querying AD objects with delegation settings.
Significance → This is reconnaissance activity to find accounts/computers that can be abused for impersonation or privilege escalation.
DC01.corp.local
Detecting DCSync/DCShadow

### Overview: DCSync & DCShadow Attacks

This section focuses on Active Directory replication abuse. Attackers use these techniques to extract password hashes or manipulate AD objects while maintaining stealth. Detection relies on Windows security auditing and Splunk analysis.
1. DCSync
What It Is
Technique to extract password hashes from domain controllers by simulating replication requests.
Requires Replicating Directory Changes permission, typically available to:
Domain Admins
Enterprise Admins
Certain computer accounts on the DC
Attack Steps
Gain administrative access to a domain-joined system or escalate privileges.
Request replication data using tools like Mimikatz (DRSGetNCChanges).
Use extracted hashes to:
Create Golden/Silver Tickets
Conduct Pass-the-Hash/Overpass-the-Hash attacks
Detection Opportunities
Monitor Event ID 4662 with DS-Replication-Get-Changes GUID: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
Note: Requires enabling Advanced Audit Policy Configuration → DS Access.
Splunk Detection Example
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
2. DCShadow
What It Is
Advanced AD attack to make unauthorized changes to AD objects without triggering standard security logs.
Uses Directory Replicator permissions and requires:
Domain or DC admin privileges
Or the KRBTGT hash
Attack Steps
Gain administrative access.
Register a rogue domain controller in the AD domain.
Modify AD objects (e.g., elevate users to Domain Admin).
Replicate changes to legitimate domain controllers.
Registration, push, and unregistration steps are used to maintain stealth.
Detection Opportunities
DCShadow requires adding:
New nTDSDSA object
Global catalog ServicePrincipalName (SPN) to computer objects
Event ID 4742 logs computer account changes, including ServicePrincipalName.
Splunk Detection Example
index=main earliest=1690623888 latest=1690623890 EventCode=4742
| rex field=Message "(?P<gcspn>XX\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
✅ Key Takeaways
DCSync: Steals AD credentials via replication requests → prelude to ticket attacks.
DCShadow: Allows clandestine modification of AD objects → persistent backdoor.
Detection relies on specific Event IDs (4662, 4742), auditing configuration, and monitoring unusual replication activity.
Modify the last Splunk search in this section by replacing the two hidden characters (XX) to align the results with those shown in the screenshot. Enter the correct characters as your answer.
Modify the last Splunk search in this section by replacing the two hidden characters (XX) to align the results with those shown in the screenshot. Enter the correct characters as your answer.
index=main earliest=1690623888 latest=1690623890 EventCode=4742
| rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
1. index=main earliest=1690623888 latest=1690623890 EventCode=4742
index=main → Searches logs in the main index where Windows Security Events are stored.
earliest=1690623888 latest=1690623890 → Filters logs within the specified Unix timestamp timeframe.
EventCode=4742 → Filters for Event ID 4742, which logs “Computer account was changed” events (useful for detecting DCShadow).
Summary: This line retrieves Windows Security Event logs for the specific timeframe and Event ID relevant to DCShadow activity.
2. | rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)"
rex → Splunk command to extract specific information from a field using Regex.
field=Message → Applies the regex on the Message field of the log.
"(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)" → Regex explanation:
(?P<gcspn>...) → Creates a named group called gcspn to store the matched value.
GC\/ → Looks for strings that start with GC/.
[a-zA-Z0-9\.\-\/]+ → Matches one or more letters, numbers, dots (.), hyphens (-), or slashes (/).
Summary: This line extracts the Global Catalog ServicePrincipalName (GC SPN) from the event message and stores it in a new field called gcspn.
3. | table _time, ComputerName, Security_ID, Account_Name, user, gcspn
table → Displays the results in a table format.
_time → Timestamp of the event.
ComputerName → The computer that was changed.
Security_ID → Security Identifier of the affected object/account.
Account_Name → Name of the account being modified.
user → User or account that made the change.
gcspn → The extracted GC SPN value.
Summary: Organizes the relevant log data into a readable table for easy analysis.
4. | search gcspn=*
search → Filters table or events further based on a condition.
gcspn=* → Keeps only events where the gcspn field has a value (non-empty).
Summary: Excludes events that don’t involve a GC SPN, focusing on potential DCShadow activity.
Overall Workflow
Retrieve Event 4742 logs (computer account changes) from Windows Security.
Extract the GC SPN using regex.
Display results in a table showing time, computer, account, user, and GC SPN.
Filter out events without GC SPN to focus on relevant changes.
Benefit: Allows security teams to detect DCShadow attacks by identifying GC SPN values that indicate rogue or modified domain controller activity.
ANSWER GC
Creating Custom Splunk Applications

### Overview: Creating Custom Splunk Applications

This section explains how to build, configure, and enhance a Splunk app to monitor Active Directory attacks, including dashboards and navigation.
1. Create a New Splunk App
Steps:
Access Splunk Web: Open your browser → navigate to Splunk Web.
Manage Apps: Apps → Manage Apps → Create app.
App Details:
Name: <Your app name> (e.g., Academy hackthebox - Detection of Active Directory Attacks)
Folder name: <App_name>
Version: 1.0.0
Description: <App description>
Template: barebones
Save the App: Verify it appears under the Apps menu.
2. Explore App Directory Structure
Located at $SPLUNK_HOME/etc/apps/<App_name>:
Navigation File:
Path: $SPLUNK_HOME/etc/apps/<App>/default/data/ui/nav/default.xml
XML defines the app menu structure and default views.
Example:
<nav search_view="search">
<view name="search" default='true'/>
<view name="analytics_workspace"/>
<view name="dashboards"/>
</nav>
3. Create Your First Dashboard
Steps:
Go to Dashboards → Create New Dashboard
Name: e.g., Domain Reconnaissance
Permissions: Set as needed
Type: Classic Dashboards (or Dashboard Studio)
Configure Panels and Inputs:
Add time input → token $time$
Add statistical table panels → include search string using input tokens like $user$
Example Panel: Sysmon Process events → columns: time, process, PID, parent process, parent PID, destination, user
Save Changes → stored in <AppPath>/local/data/ui/views/dashboard_title.xml
4. Add Dashboard to Navigation Bar
Update <AppPath>/local/data/ui/nav/default.xml with new <view name="dashboard_title"/>
Optionally, group dashboards under <collection> for menu organization:
<collection label="Command and Control">
<view name="c2_investigator"/>
<view name="c2_investigator_zeek"/>
</collection>
5. Restart Splunk
Reboot Splunk to apply changes
Your dashboard will appear in the app navigation bar
6. Update or Install Prebuilt Apps
Download Detection-of-Active-Directory-Attacks.tar.gz
Apps → Manage Apps → Install app from file → Browse → Upgrade app
Overwrites existing app if needed
✅ Key Takeaways
Splunk apps organize dashboards, searches, and configurations.
Dashboards provide interactive visualizations for monitoring attacks (e.g., Sysmon, Active Directory reconnaissance).
Navigation XML allows custom menu and grouping of dashboards.
Prebuilt apps can be imported or updated to enhance monitoring capabilities quickly.
Detecting RDP Brute Force Attacks
Detecting RDP Brute Force Attacks
RDP brute force attacks are commonly used by attackers to gain access to network systems by repeatedly guessing passwords for Remote Desktop Protocol sessions. Weak or default passwords make this attack effective.
1. RDP Traffic Characteristics
Network capture observations:
Authentication attempts
Certificate exchange
Connection closure
RDP username may be visible in packet details.
2. Accessing the Target System
Spawn the target VM in the lab environment.
RDP into the target:
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
Files & logs location: /home/htb-student/module_files/rdp_bruteforce
Splunk index: rdp_bruteforce
Sourcetype: bro:rdp:json
3. Detecting RDP Brute Force Using Splunk & Zeek Logs
Search Query:
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
Explanation:
bin _time span=5m → Groups events into 5-minute intervals.
stats count values(cookie) by _time, id.orig_h, id.resp_h → Aggregates events by origin and destination IP, counting authentication attempts.
where count>30 → Flags potential brute force activity when attempts exceed 30 in 5 minutes.
Output Columns:
_time → Timestamp of the interval
id.orig_h → Source IP of attacker
id.resp_h → Target IP
count → Number of RDP attempts
values(cookie) → Session cookies for reference
✅ Key Takeaways
RDP brute force attacks can be detected using high-frequency login attempts in short time windows.
Zeek logs provide detailed RDP session data for analysis.
Splunk queries allow aggregation and threshold-based detection of suspicious RDP login activity.
Construct a Splunk query targeting the "ssh_bruteforce" index and the "bro:ssh:json" sourcetype. The resulting output should display the time bucket, source IP, destination IP, client, and server, together with the cumulative count of authentication attempts where the total number of attempts surpasses 30 within a 5-minute time window. Enter the IP of the client that performed the SSH brute attack as your answer.
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
ANSWER 192.168.152.140
Detecting Beaconing Malware
Beaconing malware is characterized by periodic communication from infected hosts to Command & Control (C2) servers, often sending small packets at regular intervals. This behavior can indicate malware like Cobalt Strike.
1. Beaconing Behavior
Patterns: Fixed interval, jittered interval, or complex schedules.
Protocols: HTTP/HTTPS, DNS, ICMP, etc.
C2 Example: Cobalt Strike in default configuration.
2. Accessing the Target System
Spawn the target VM in the lab environment.
RDP into the target:
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
Files & logs location: /home/htb-student/module_files/cobaltstrike_beacon
Splunk index: cobaltstrike_beacon
Sourcetype: bro:http:json
3. Detecting Beaconing Using Splunk & Zeek Logs
Search Query:
index="cobaltstrike_beacon" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
Explanation:
index="cobaltstrike_beacon" sourcetype="bro:http:json" → Selects Zeek HTTP logs for beaconing.
sort 0 _time → Sort events chronologically.
streamstats current=f last(_time) as prevtime by src, dest, dest_port → Track the previous event timestamp per host/port pair.
eval timedelta = _time - prevtime → Compute time difference between consecutive events.
eventstats avg(timedelta) as avg, count as total by src, dest, dest_port → Calculate average interval and total events.
eval upper=avg*1.1 & eval lower=avg*0.9 → Define a ±10% margin for interval check.
where timedelta > lower AND timedelta < upper → Keep events within expected interval.
stats count, values(avg) as TimeInterval by src, dest, dest_port, total → Aggregate statistics.
eval prcnt = (count/total)*100 → Calculate percentage of events within expected interval.
where prcnt > 90 AND total > 10 → Identify likely beaconing (≥90% events within interval, ≥10 events).
✅ Key Takeaways
Beaconing can be detected by regularity in network communication intervals.
Using Zeek logs + Splunk, we can compute timing statistics to identify suspicious periodic traffic.
Thresholds (like 90% within ±10% of average interval) help distinguish malware beaconing from normal network chatter.
Use the "cobaltstrike_beacon" index and the "bro:http:json" sourcetype. What is the most straightforward Splunk command to pinpoint beaconing from the 10.0.10.20 source to the 192.168.151.181 destination? Answer format: One word\
index="cobaltstrike_beacon" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
ANSWER timechart
Detecting Nmap Port Scanning
Port scanning is a common reconnaissance technique where attackers probe systems for open ports, which are potential points of entry. Nmap is a widely used tool for this purpose.
1. How Nmap Works
TCP Handshake: Nmap attempts to connect to each port to see if it is open.
Banners: Open ports may respond with service/version information.
Minimal Payload: Nmap typically sends no extra data besides the handshake (orig_bytes=0).
2. Accessing the Target System
Spawn the target VM in the lab environment.
RDP into the target:
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
Files & logs location: /home/htb-student/module_files/cobaltstrike_beacon
Splunk index: cobaltstrike_beacon
Sourcetype: bro:conn:json
3. Detecting Nmap Scans Using Splunk & Zeek Logs
Search Query:
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
| bin span=5m _time
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 3
Explanation:
index="cobaltstrike_beacon" → Search only in the relevant index.
sourcetype="bro:conn:json" → Filter Zeek connection logs.
orig_bytes=0 → Focus on events where no actual data payload was sent (TCP handshake only).
dest_ip IN (...) → Restrict to private network IP ranges (internal targets).
| bin span=5m _time → Group events into 5-minute intervals.
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip → Count distinct destination ports accessed per source-destination pair.
| where num_dest_port >= 3 → Flag potential port scans (3 or more ports accessed within a short interval).
✅ Key Takeaways
Nmap scans can be detected by zero-byte connections to multiple ports in a short timeframe.
Binning and counting distinct destination ports helps differentiate legitimate traffic from scanning activity.
This method works well for internal network monitoring where private IP ranges are used.
Use the "cobaltstrike_beacon" index and the "bro:conn:json" sourcetype. Did the attacker scan port 505? Answer format: Yes, No
ANSWER YES
Detecting Kerberos Brute Force Attacks
Kerberos brute force attacks involve user enumeration and password guessing against the Key Distribution Center (KDC). Attackers send AS-REQ (Authentication Service Requests) and analyze the responses to determine valid usernames.
1. How It Works
Valid Username: KDC returns a TGT or error KRB5KDC_ERR_PREAUTH_REQUIRED.
Invalid Username: KDC returns KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN.
By examining AS-REP messages, attackers can identify valid accounts before attempting password guesses.
2. Accessing the Target System
Spawn the target VM in the lab environment.
RDP into the target:
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
Files & logs location: /home/htb-student/module_files/kerberos_bruteforce
Splunk index: kerberos_bruteforce
Sourcetype: bro:kerberos:json
3. Detecting Kerberos Brute Force Using Splunk & Zeek Logs
Search Query:
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
Explanation:
index="kerberos_bruteforce" → Search in the relevant index.
sourcetype="bro:kerberos:json" → Filter Zeek Kerberos logs.
error_msg!=KDC_ERR_PREAUTH_REQUIRED → Ignore preauth-required errors, focus on failures revealing invalid users.
success="false" → Only failed authentication attempts.
request_type=AS → Focus on AS-REQ messages (initial authentication requests).
| bin _time span=5m → Aggregate events in 5-minute intervals.
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h → Count total events, number of unique usernames, and log error messages per source-destination pair.
| where count>30 → Flag potential brute force attempts with more than 30 failed requests in 5 minutes.
✅ Key Takeaways
High-frequency failed AS-REQ requests can indicate Kerberos brute force or user enumeration attacks.
Filtering out preauth-required responses helps identify actual invalid username probing.
This method leverages Zeek logs for accurate detection of Kerberos authentication attacks.
+ 0 Use the "kerberos_bruteforce" index and the "bro:kerberos:json" sourcetype. Was the "accrescent/windomain.local" account part of the Kerberos user enumeration attack? Answer format: Yes, No
YES
Detecting Kerberoasting
Kerberoasting is an Active Directory attack where attackers request Service Tickets (TGS) for accounts with Service Principal Names (SPNs) and attempt to crack them offline. It exploits the RC4 encryption used for these tickets.
1. How It Works
Attacker needs one valid user account in the domain.
Queries SPN accounts to request Kerberos TGS (Ticket Granting Service) tickets.
Receives TGS tickets encrypted with RC4-HMAC (or other ciphers).
Performs offline brute-force to recover the account password.
Traffic Indicators:
TGS-REQ / TGS-REP messages in Kerberos traffic
Encryption type: rc4-hmac
Flags: forwardable=true, renewable=true
2. Accessing the Target System
Spawn the target VM in the lab environment.
RDP into the target:
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
Files & logs location: /home/htb-student/module_files/sharphound
Splunk index: sharphound
Sourcetype: bro:kerberos:json
3. Detecting Kerberoasting Using Splunk & Zeek Logs
Search Query:
index="sharphound" sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac"
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
Explanation:
index="sharphound" → Focus on logs generated by SharpHound activities.
sourcetype="bro:kerberos:json" → Filter Zeek Kerberos logs.
request_type=TGS → Only include Ticket Granting Service requests.
cipher="rc4-hmac" → Look for tickets encrypted with RC4 (common in Kerberoasting).
forwardable="true" renewable="true" → Typical flags for service tickets.
| table ... → Display key fields for analysis: time, source, destination, client, and service accounts.
✅ Key Takeaways
Kerberoasting can be detected by filtering TGS requests with RC4 encryption.
Monitoring for a high number of TGS-REQs from normal user accounts can indicate an attack.
Using Splunk + Zeek logs allows analysts to identify malicious Kerberos ticket requests in near real-time.
What port does the attacker use for communication during the Kerberoasting attack?
Port 88 — Kerberos (TGS/AS) traffic uses TCP/UDP port 88.
ANSWER 88
Detecting Golden Tickets
Golden Ticket attacks allow attackers to bypass normal Kerberos authentication by forging or stealing Kerberos tickets, giving them unrestricted access to network services. Zeek cannot reliably detect them, so Splunk analysis focuses on anomalous ticket request patterns.
1. How Golden Ticket Attacks Work
Normal Kerberos Authentication:
Client sends AS-REQ → KDC responds with AS-REP (TGT) → Client requests TGS for specific services.
Golden Ticket Attack:
Attacker forges a TGT using the KRBTGT hash.
Can request TGS for any service without AS-REQ/AS-REP.
Pass-the-Ticket Attack:
Attacker steals a valid TGT or TGS from a legitimate user.
Can access services as if they are the legitimate user, bypassing normal authentication flow.
Traffic Indicators:
Only TGS requests are seen from the attacker.
Requests may appear without prior AS-REQ/AS-REP traffic.
2. Accessing the Target System
Spawn the target VM in the lab environment.
RDP into the target:
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
Files & logs location: /home/htb-student/module_files/golden_ticket_attack
Splunk index: golden_ticket_attack
Sourcetype: bro:kerberos:json
3. Detecting Golden Tickets Using Splunk & Zeek Logs
Search Query:
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
Explanation:
index="golden_ticket_attack" sourcetype="bro:kerberos:json" → Focus on Kerberos logs related to potential golden ticket activity.
| where client!="-” → Remove events with missing client information.
| bin _time span=1m → Aggregate events into 1-minute intervals for pattern analysis.
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h → For each interval and source/destination IP pair:
List unique clients
List request types
Count distinct request types
| where request_types=="TGS" AND unique_request_types==1 → Flag events where only TGS requests exist, indicative of forged or stolen tickets.
✅ Key Takeaways
Golden Ticket attacks bypass normal AS-REQ/AS-REP flows, leaving only TGS requests in logs.
Using Splunk, you can detect anomalies by isolating TGS-only requests from typical Kerberos authentication behavior.
Monitoring such patterns helps identify unauthorized privilege escalation and potential persistence in Active Directory environments.
What port does the attacker use for communication during the Golden Ticket attack?
Port 88 — Golden Ticket attacks still use Kerberos TGS requests, which communicate over TCP/UDP port 88.
ANSWER 88
Detecting Cobalt Strike's PSExec

### Overview

This text explains how attackers use Cobalt Strike’s PSExec feature (an implementation of the PsExec remote-execution tool) to run payloads on remote Windows hosts and how defenders can detect that activity using network and Zeek/Splunk logs. It describes the PSExec workflow (service creation, file transfer to ADMIN$, execution, cleanup, and beaconing) and highlights that this activity occurs over SMB (port 445).
The section also points to lab artifacts (PCAPs, logs, Splunk index cobalt_strike_psexec, and Zeek sourcetype bro:smb_files:json) and provides a Splunk/Zeek query to find suspicious SMB file operations consistent with PSExec-style activity.

### Key Points

What Cobalt Strike’s PSExec does
Creates a service on the target, copies a payload (often to ADMIN$), starts the service to execute the payload, then removes the service to reduce traces.
Network/protocol characteristics
PSExec-style activity uses SMB over port 445 and often writes executables to \\<host>\ADMIN$ (the hidden administrative share).
Post-execution communication
Executed payloads commonly include beacons/backdoors (e.g., Cobalt Strike beacon) that call back to a C2 server.
Requirements & privileges
Local administrator privileges on the target are required to create services and write to ADMIN$.
Detection artifacts & lab evidence
Network PCAPs show SMB file creation and service-related operations; Zeek/ Splunk logs are available in /home/htb-student/module_files/cobalt_strike_psexec, Splunk index cobalt_strike_psexec, sourcetype bro:smb_files:json.
Detection query (Zeek/Splunk)
Look for SMB file-open events where action="SMB::FILE_OPEN", filenames match *.exe|*.dll|*.bat, paths include *\c$ or *\\ADMIN$, and size>0.
Detailed Explanation
Cobalt Strike PSExec workflow (ordered steps)
Service creation — The attacker creates a service on the remote host (usually with a random name to avoid detection).
File transfer — The payload binary (exe/dll/bat) is written to an administrative share such as ADMIN$ (e.g., \\DC\ADMIN$\be5312f.exe).
Service execution — The service is started, causing the payload to execute in the target environment.
Service removal — After execution, the created service is stopped and deleted to minimize forensic traces.
Callback / C2 communication — If the payload is a beacon/backdoor, it will initiate outbound communication to a C2 server (commonly HTTP/HTTPS or other channels).
These steps are important because each produces observable artifacts (file creation, service creation events, SMB writes, network callbacks) that defenders can monitor.
Network and log indicators
SMB file operations: PCAPs highlight SMB2 activity showing file writes to ADMIN$ and handle creation; these are strong indicators when combined with service creation.
Port: SMB traffic uses TCP port 445. Detection of unusual process/network activity involving port 445 (especially from unexpected processes) is suspicious.
Zeek / Splunk evidence locations: The lab stores relevant evidence in /home/htb-student/module_files/cobalt_strike_psexec. Splunk ingestion uses index cobalt_strike_psexec and sourcetype bro:smb_files:json. These logs capture SMB::FILE_OPEN actions and metadata (file name, path, size, timestamps, uid).
Detection logic & Splunk query explained
The core detection looks for SMB file-open events with:
action="SMB::FILE_OPEN" — a file was opened on SMB.
name IN ("*.exe", "*.dll", "*.bat") — executable-like files.
path IN ("*\\c$", "*\\ADMIN$") — administrative shares where attackers commonly drop payloads.
size>0 — confirms actual content was written.
Example Splunk/Zeek search (as presented):



index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
Why this works: Legitimate SMB traffic rarely opens/writes executables into ADMIN$ from non-admin tools; repeated or one-off writes of executable files to admin shares by interactive processes or unexpected sources are high-fidelity indicators for PSExec-style post-exploitation.
Privilege context and false-positive considerations
Because ADMIN$ writes and service creation legitimately occur in admin maintenance tasks, correlate with:
Source user/context (is it a known admin account?).
Process that performed the write (is it a legitimate management tool or wmic/rundll32 etc.?).
Timing and surrounding events (service creation, subsequent service control operations, unusual process execution, outgoing beacon traffic).
Combining file write detection with process/service events and outbound beaconing reduces false positives.

### Conclusion / Takeaways

Cobalt Strike’s PSExec abuses SMB (port 445) and ADMIN$ to transfer and execute payloads; detection should focus on SMB file writes of executables to admin shares plus service creation and command/control callbacks.
Key detection signal: SMB::FILE_OPEN events for *.exe, *.dll, or *.bat under *\c$ or *\\ADMIN$ with size>0.
Correlate SMB file events with service creation, process execution, and outbound beaconing to raise confidence and reduce false positives.
Local administrative privileges are required for PSExec activity; look for unusual admin-context actions from non-admin hosts or unexpected users.
Use the provided Splunk/Zeek logs and lab evidence (/home/htb-student/module_files/cobalt_strike_psexec, Splunk index cobalt_strike_psexec, sourcetype bro:smb_files:json) to validate detection rules and tune thresholds.

### Glossary

Cobalt Strike: A commercial adversary simulation/C2 framework used by red teams and, unfortunately, by attackers.
PSExec / psexec: A remote process execution method (original PsExec from Sysinternals); Cobalt Strike implements similar functionality.
SMB (Server Message Block): Network file-sharing protocol used by Windows for file and printer sharing (operates over TCP port 445).
ADMIN$: Hidden administrative share on Windows that maps to the system root (e.g., C:\Windows).
Beacon (C2 beacon): Periodic outbound communications from a compromised host to a command-and-control server.
Zeek (bro): Network monitoring tool that produces rich logs (here bro:smb_files:json holds SMB file activity).
Sourcetype / Splunk index: Splunk ingestion metadata — sourcetype identifies the log format, and index specifies where logs are stored.
Use the "change_service_config" index and the "bro:dce_rpc:json" sourcetype to create a Splunk search that will detect SharpNoPSExec (https://gist.github.com/defensivedepth/ae3f882efa47e20990bc562a8b052984). Enter the IP included in the "id.orig_h" field as your answer.
index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
ANSWER 192.168.38.104
Detecting Zerologon
Zerologon (CVE-2020-1472) is a critical cryptographic flaw in the Netlogon Remote Protocol that allows an attacker to impersonate a computer (including a domain controller) and change machine account passwords, potentially giving full domain compromise. Detection focuses on spotting unusual Netlogon RPC operations (e.g., NetrServerReqChallenge, NetrServerAuthenticate3, NetrServerPasswordSet2) and high-volume or abnormal sequences of those operations in network/Zeek logs ingested into Splunk.

### Overview

Zerologon (CVE-2020-1472) is a vulnerability in Microsoft’s Netlogon Remote Protocol (MS-NRPC) caused by a flawed cryptographic implementation where the AES-CFB8 initialization vector (IV) can be effectively predictable (treated as all zeros). This lets attackers bypass authentication to a domain controller.
By exploiting this flaw an attacker can establish a secure channel as any machine account, call NetrServerPasswordSet2to set a computer account password (including the domain controller’s) to an attacker-controlled value (even blank), and thereby obtain full control of Active Directory.
The attack is fast and noisy on the network (only a few messages often suffice). Defenders should monitor Netlogon RPC activity, enable appropriate audit/collection, and use the provided Splunk/Zeek detection query to surface suspicious patterns.

### Key Points

Vulnerability summary (CVE-2020-1472)
The bug is in Netlogon’s cryptography (AES-CFB8 IV handling) and allows authentication bypass by using zeroed session keys/IVs.
Impact — impersonation and password reset
An attacker can impersonate any computer (including DC) and call NetrServerPasswordSet2 to change machine account passwords, enabling domain compromise.
Attack simplicity and speed
Exploit requires only a small sequence of Netlogon RPC messages and can succeed within seconds.
Network-level indicators
Relevant Netlogon RPC operations: NetrServerReqChallenge, NetrServerAuthenticate3, NetrServerPasswordSet2. Multiple repeated or high-volume occurrences between a client and DC are suspicious.
Detection approach with Zeek + Splunk
Use Zeek DCE/RPC logs (e.g., bro:dce_rpc:json) indexed into Splunk and look for specific operations in short time windows, with thresholds for count and unique operations.
Evidence & lab artifacts
Lab evidence located under /home/htb-student/module_files/zerologon, Splunk index zerologon, sourcetype bro:dce_rpc:json.
Suggested Splunk detection query (exact as given)
Filters Netlogon endpoint and operations, aggregates per minute, and flags high-count multi-operation transactions.
Detailed Explanation
Vulnerability mechanics
Netlogon (MS-NRPC) authenticates machines using a session key derived from the machine account password; that key is used to derive an IV for AES-CFB8 encryption.
Because of the flawed implementation, an attacker can often get away with using zeroed session key/IVs (or equivalent malformed values) and bypass the authentication checks — effectively the DC accepts the attacker as the machine.
Implication: cryptographic design/implementation error → authentication bypass; no need for valid password.
What an attacker can do (ordered steps)
Send NetrServerReqChallenge to the target DC (initiate Netlogon challenge).
Complete NetrServerAuthenticate3 exchanges using manipulated/zeroed values to appear authenticated.
Call NetrServerPasswordSet2 to set the machine account password to any desired value (including blank).
Use that control to impersonate the DC or other systems, extract credentials, and escalate to domain compromise.
Note: steps repeat until success; exploit often succeeds after multiple attempts.
Network perspective & why Zeek logs help
Zeek’s DCE/RPC parsing can surface Netlogon RPC endpoint traffic and show operation names in bro:dce_rpc:json records.
Because the exploit uses a small set of RPC calls in rapid succession, aggregating these RPC events by source/destination with time-binning reveals abnormal patterns (many Netlogon operations, or unusual sequences, coming from a non-DC host).
Splunk detection logic explained
Query purpose: find minute-binned buckets where Netlogon endpoint operations include any of the critical RPCs and are both frequent and diverse enough to indicate attempted exploitation.
Query (exact):



index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
Field notes:
id.orig_h = origin (client) IP, id.resp_h = responder (server/DC) IP.
count>100 is a high-volume threshold (tunable for environment); unique_operations >= 2 ensures multiple operation types occurred in the window (challenge/authenticate/password set).
Why tune thresholds: Production environments vary; a lower threshold may be needed in small networks; a higher threshold reduces false positives.
Operational recommendations & mitigation
Patch: apply Microsoft patches for CVE-2020-1472 (enforce secure Netlogon secure channel) — primary remediation.
Audit: enable and collect DCE/RPC/Netlogon logs and Zeek DCE/RPC parsing if using network sensors.
Monitor: run the Splunk query (or variants) across all time ranges (or continuous alerting) and investigate any hits.
Contain & respond: if exploitation suspected, isolate the source host, validate DC account passwords, roll/reset computer account passwords (and KRBTGT if needed as per recovery playbooks), and perform forensic analysis.
What’s missing / limitations to call out
Zeek + Splunk detection relies on network visibility to Netlogon traffic; if attackers operate on the DC itself (local), network logs won’t capture exploit steps — host-based telemetry (process creation, unusual Netlogon service interactions, LSASS accesses) is complementary.
The Splunk query uses fairly high thresholds (count>100); investigators should tune thresholds and consider lower-volume anomalies combined with unusual source identity (non-domain controllers initiating Netlogon RPCs).

### Conclusion / Takeaways

Zerologon (CVE-2020-1472) is a severe Netlogon cryptographic vulnerability that enables machine impersonation and DC takeover.
Primary defense: apply Microsoft’s patches and enforce Netlogon secure channel protections.
Detection: monitor Netlogon RPC operations (NetrServerReqChallenge, NetrServerAuthenticate3, NetrServerPasswordSet2) and look for abnormal frequency or sequences from unexpected clients.
Splunk + Zeek approach: use the provided query on bro:dce_rpc:json logs in index zerologon to surface suspicious patterns; tune thresholds to your environment.
Don’t rely on network logs alone: combine with host telemetry and SRM/AD hygiene (password resets, KRBTGT hardening) for detection and recovery.

### Glossary

Netlogon (MS-NRPC): Microsoft’s Netlogon Remote Protocol used to establish secure channels between machines and domain controllers.
AES-CFB8 IV (initialization vector): A value used to initialize AES-CFB8 encryption; should be unique/random for each encryption operation.
NetrServerReqChallenge: Netlogon RPC call to request a challenge from a server (part of authentication handshake).
NetrServerAuthenticate3: Netlogon RPC call to perform authentication exchange/response.
NetrServerPasswordSet2: Netlogon RPC call that sets a machine account password on a domain controller.
DCE/RPC: Distributed Computing Environment / Remote Procedure Call protocol used for RPCs such as Netlogon.
Zeek (bro): Network security monitor that can parse DCE/RPC and output bro:dce_rpc:json logs.
0 In a Zerologon attack, the primary port of communication for the attacker is port 88. Answer format: True, False.
Because in a Zerologon attack, the attacker exploits the Netlogon Remote Protocol (MS-NRPC), which primarily communicates over TCP port 445 (SMB), not port 88.
Port 88 is used for Kerberos authentication, but Zerologon bypasses normal Kerberos authentication by manipulating the Netlogon protocol directly. So the attack traffic does not use port 88—it targets the domain controller over SMB/Netlogon.
ANSWER False
Detecting Exfiltration (HTTP)

### Overview

This content describes data exfiltration via HTTP POST bodies, where attackers hide stolen data inside normal-looking web POST requests to send it from a compromised host to an attacker-controlled server (C2). It explains why POST-based exfiltration is stealthy and outlines a detection approach based on aggregating outgoing POST traffic volumes.
The guidance shows how to use Zeek HTTP logs ingested into Splunk to sum POST body sizes per destination and identify unusually large or frequent transfers. Lab artifacts and the exact Splunk index/sourcetype used for the examples are provided.

### Key Points

Technique: POST-body data exfiltration
Attackers place stolen data inside the HTTP POST request body and send it to their external C2 server to avoid easy detection.
Why it’s hard to detect
HTTP POSTs are common and legitimate (forms, uploads), so exfiltration blends into normal traffic unless volume or destination patterns are analyzed.
Detection principle
Aggregate outgoing POST body sizes to destinations and flag unusually large or frequent data transfers to single hosts/ports.
Splunk/Zeek detection example
Use Zeek HTTP logs (bro:http:json) indexed into Splunk (cobaltstrike_exfiltration_http) and run a query summing request_body_len grouped by source, destination, and destination port.
Lab evidence & context
Related files/PCAPs are in /home/htb-student/module_files/cobaltstrike_exfiltration_http. The Splunk index used in examples is cobaltstrike_exfiltration_http and the sourcetype is bro:http:json.
Detailed Explanation
Technique: POST-body data exfiltration
Attackers embed data (files, credentials, log extracts) in the body of an HTTP POST.
Because POST is a standard mechanism for sending data to web servers, malicious content can appear as normal application traffic.
Why it’s hard to detect
HTTP POSTs are ubiquitous—user uploads, API calls, form submissions—so content inspection alone often yields many false positives and privacy/legal issues.
Attackers often use innocuous-looking URLs, common headers, or encryption/encoding to further hide payloads.
Detection principle (how to find it)
Rather than content inspection, aggregate volume and frequency metadata:
Sum the request_body_len (length of POST body) per (src, dest, dest_port).
Convert bytes to human-friendly units (example converts to MB).
Flag destinations receiving unusually large total bytes or receiving many sizable POSTs from a host over a given period.
Splunk/Zeek implementation (exact query provided)
Example search (exact as given):



index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
Explanation of the query:
a. index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST — select Zeek HTTP POST records in the specified index.
b. stats sum(request_body_len) as TotalBytes by src, dest, dest_port — sum POST body lengths grouped by source host, destination host, and destination port.
c. eval TotalBytes = TotalBytes/1024/1024 — convert bytes to megabytes for easier interpretation.
Use results to spotlight high-volume outbound POST traffic for investigation.
Lab context & evidence
All related artifacts (PCAPs, logs) are under /home/htb-student/module_files/cobaltstrike_exfiltration_http.
Analysts can reproduce queries in the lab Splunk instance at https://[Target IP]:8000 against the cobaltstrike_exfiltration_http index to practice detection.
Limitations & what’s missing (important to note)
The guidance does not supply concrete thresholds for “unusually large” or “frequent” — threshold tuning is environment-specific and must be set by baseline analysis.
The method assumes Zeek is capturing HTTP traffic and that POST body length is populated; if HTTPS is used and not TLS-terminated at a visibility point, only metadata (not body length) may be available.
Encrypted or chunked uploads and multipart forms may complicate request_body_len accuracy.

### Conclusion / Takeaways

Monitor outgoing HTTP POST activity for high-volume or high-frequency transfers to the same destination as a practical detection handle for POST-body exfiltration.
Use Zeek HTTP logs (bro:http:json) and the provided Splunk query to aggregate request_body_len by (src, dest, dest_port)and convert to MB for review.
Tune thresholds after establishing normal baselines; there is no one-size-fits-all threshold in the document.
Combine volume-based detection with contextual signals (unusual destination IPs, rare domains, odd user agents, and time-of-day anomalies) to reduce false positives.
If visibility is limited by HTTPS, consider TLS termination points, proxy logs, or endpoint telemetry to improve detection fidelity.

### Glossary

HTTP POST: An HTTP method used to send data (the request body) from a client to a server (e.g., form submission).
C2 (Command and Control): An attacker-controlled server that receives data from compromised hosts and issues commands.
Zeek (bro): A network sensor that parses protocols (HTTP, DNS, etc.) and writes structured logs such as bro:http:json.
Splunk index / sourcetype: Splunk terms — an index is where events are stored (e.g., cobaltstrike_exfiltration_http) and a sourcetype describes event format (e.g., bro:http:json).
request_body_len: Field representing the size (in bytes) of the HTTP request body captured by Zeek.
Use the "cobaltstrike_exfiltration_https" index and the "bro:conn:json" sourcetype. Create a Splunk search to identify exfiltration through HTTPS. Enter the identified destination IP as your answer.
index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
ANSWER 192.168.151.181
Detecting Exfiltration (DNS)

### Overview

This section covers DNS-based data exfiltration, a stealthy technique where attackers hide stolen data in DNS queries to bypass network defenses. It explains the attack workflow, illustrates what DNS exfiltration traffic looks like, and demonstrates how to detect it using Zeek logs ingested into Splunk.

### Key Points

Technique: DNS-based exfiltration
Attackers encode data into DNS query names (subdomains) and send them to attacker-controlled or compromised DNS servers.
Advantages for attackers:
DNS traffic is typically allowed through firewalls.
Low volume queries blend with normal traffic.
Difficult to detect without careful analysis.
Attack Workflow
Initial Compromise: Malware, phishing, or vulnerabilities gain network access.
Data Prep: Target data is identified, encoded/encrypted, and split into small chunks.
Exfiltration via DNS: Each chunk is sent in a DNS query (e.g., as a subdomain). The attacker's DNS server reconstructs the data.
Data Retrieval: The attacker decodes or decrypts the collected queries to reconstruct the exfiltrated data.
Detection Principle
Focus on unusual DNS queries that are:
Longer than normal (here: len_query >= 40 characters).
Not part of common legitimate domains (*.ip6.arpa, *.amazonaws.com, _googlecast.*, _ldap.*).
Aggregate queries per host per day to identify hosts generating high volumes of suspicious DNS queries.
Splunk/Zeek Detection Example
Index: dns_exf
Sourcetype: bro:dns:json
Example Splunk search:



index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day
Explanation:
eval len_query=len(query) → Compute the length of each DNS query.
search len_query>=40 AND ... → Filter long queries and exclude common legitimate domains.
bin _time span=24h → Group events by day for trend analysis.
stats count(query) as req_by_day by _time, id.orig_h, id.resp_h → Count suspicious queries per day per host pair.
where req_by_day>60 → Focus on hosts making more than 60 suspicious queries/day.
table → Display time, origin IP, destination IP, and count.
Lab context & evidence
All relevant files/PCAPs are in /home/htb-student/module_files/dns_exf.
Analysts can reproduce queries in the lab Splunk instance at https://[Target IP]:8000 for hands-on practice.

### Takeaways / Best Practices

Why it matters: DNS exfiltration can bypass firewalls and IDS/IPS controls, making it one of the most stealthy methods for data theft.
Detection tips:
Focus on query length and frequency per host.
Filter out common legitimate domains to reduce false positives.
Aggregate and review per host per day to spot anomalous patterns.
Complementary methods:
Compare with baseline DNS behavior to tune thresholds.
Use passive DNS or threat intelligence to identify suspicious domains.
Combine with endpoint monitoring to detect the initial compromise or malware generating DNS queries.
Use the "dns_exf" index and the "bro:dns:json" sourcetype. Enter the attacker-controlled domain as your answer. Answer format: _._
index="dns_exf" sourcetype="bro:dns:json"
| eval len_query = len(query)
| search len_query >= 40
| search NOT (query LIKE "*.ip6.arpa*" OR query LIKE "*amazonaws.com*" OR query LIKE "*._googlecast.*" OR query LIKE "_ldap.*")
| stats count AS hits by query
| sort - hits
| table hits, query
From the Splunk search results you shared, there are several query entries that are subdomains of a suspicious domain, for example:
cdn.0105d17d6.456c54f2.blue.letsgohunt.online
cdn.013821c34.456c54f2.blue.letsgohunt.online
This indicates that the attacker-controlled domain is letsgohunt.online.
Step-by-Step Guide to Identify the Attacker Domain in Splunk
1) Open Splunk → Search & Reporting
Navigate to the Search & Reporting app in Splunk.
2) Set the Time Range
Choose a time range that covers the period of the attack (e.g., Last 24 hours).
3) Run a search to filter suspicious DNS queries and extract the registered domain
You can use the following SPL:
index="dns_exf" sourcetype="bro:dns:json"
| eval len_query = len(query)
| search len_query >= 40
| search NOT (query LIKE "*.ip6.arpa*" OR query LIKE "*amazonaws.com*" OR query LIKE "*._googlecast.*" OR query LIKE "_ldap.*")
| rex field=query "(?<registered_domain>[a-z0-9\-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)$"
| stats count AS hits by registered_domain
| sort - hits
| table hits, registered_domain
Explanation of the query:
eval len_query = len(query) — calculates the length of each DNS query. Long queries often indicate exfiltration.
The search NOT (...) filters out benign or known service queries.
rex field=query "(?<registered_domain>...)" — extracts the registered domain (the attacker-controlled domain) from the query.
stats count by registered_domain — counts how many times each domain was queried.
sort - hits — sorts domains by frequency to identify the most likely attacker-controlled domain.
4) Review the results
The domain at the top of the list (with the most queries) is typically the attacker-controlled domain. In your case, this is:
ANSWES letsgohunt.online
Detecting Ransomware

### Overview

This section explains ransomware detection using Splunk and Zeek logs, focusing on SMB-based file activity. Two main ransomware behaviors are highlighted: excessive file overwriting and file renaming with new extensions.

### Key Points

1. Ransomware File Overwrite Approach
How it works:
Ransomware enumerates files.
Reads files via SMB (SMB::FILE_OPEN).
Encrypts files in memory.
Overwrites original files via SMB (SMB::FILE_RENAME).
Detection strategy:
Monitor high counts of file open and rename actions within short intervals (e.g., 5 minutes).
Focus on hosts performing both actions repeatedly.
Splunk Detection Query Example:
index="ransomware_open_rename_sodinokibi" sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
Detects hosts performing both open and rename actions excessively.
2. Ransomware File Renaming Approach
How it works:
Reads files via SMB.
Encrypts them in memory.
Writes files with a new extension, often ransomware-specific.
Detection strategy:
Identify files renamed with unusual extensions.
Count occurrences per host and per interval.
Focus on bursts of renames with the same new extension.
Splunk Detection Query Example:
index="ransomware_new_file_extension_ctbl_ocker" sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME"
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort -count
Explanation:
Extract old and new file extensions.
Filter where extensions differ.
Count renames per 5-minute interval per host.
Focus on bursts >20, indicating potential ransomware activity.
Resources for ransomware extensions:
Google Sheet – Known ransomware extensions
Corelight – Detect ransomware filenames
Experiant – Ransomware file extensions

### Takeaways

Excessive file activity (open + rename) signals potential file-encrypting ransomware.
New/unknown file extensions in renames indicate ransomware strain indicators.
Monitoring interval: 5-minute bins are effective for spotting bursts.
Data source: SMB logs from Zeek (bro:smb_files:json) ingested into Splunk.
Combine both detection approaches for higher coverage and accuracy.
Modify the action-related part of the Splunk search of this section that detects excessive file overwrites so that it detects ransomware that delete the original files instead of overwriting them. Run this search against the "ransomware_excessive_delete_aleta" index and the "bro:smb_files:json" sourcetype. Enter the value of the "count" field as your answer.
index="ransomware_excessive_delete_aleta" sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
index="ransomware_excessive_delete_aleta" sourcetype="bro:smb_files:json"
This filters events from the Splunk index ransomware_excessive_delete_aleta and the sourcetype bro:smb_files:json.
Essentially, we are only looking at SMB file events relevant to this ransomware investigation.
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
Filters the events to include only those where the action is either SMB::FILE_OPEN (file read/open) or SMB::FILE_DELETE (file deleted).
This helps identify ransomware that deletes original files after reading them.
| bin _time span=5m
Groups the events into 5-minute time intervals.
This is useful for detecting bursts of activity within short periods of time.
| stats count by _time, source, action
Counts the number of events for each combination of 5-minute time interval (_time), source IP (source), and action type (action).
Produces a breakdown of file operations per host and action per time window.
| where count>30
Filters out intervals where the number of actions is 30 or fewer.
Focuses on high-activity periods, which are more likely to indicate malicious behavior.
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
Aggregates the counts of all actions per _time and source.
sum(count) as count sums the number of events.
values(action) lists the types of actions observed.
dc(action) as uniq_actions calculates the number of unique actions (i.e., did the host perform both OPEN and DELETE?).
| where uniq_actions==2 AND count>100
Keeps only records where both actions occurred (uniq_actions==2) and the total number of actions exceeds 100 in that time window.
This ensures we focus on hosts that exhibit heavy file activity including deletion, which is indicative of ransomware behavior.
Summary:
This search detects ransomware that reads files and deletes them in large numbers within short intervals. By checking for both SMB::FILE_OPEN and SMB::FILE_DELETE actions and requiring a high count, it highlights suspicious activity likely caused by a ransomware attack
ANSWER 4588
Skills Assessment
This module's skills assessment involves identifying malicious activity using Splunk and Zeek logs.
In many instances, the solution can be discovered by simply viewing the events in each index, as the number of events is limited. However, please take the time to refine your Splunk searches to achieve a better understanding.
Use the "empire" index and the "bro:http:json" sourcetype. Identify beaconing activity by modifying the Splunk search of the "Detecting Beaconing Malware" section and enter the value of the "TimeInterval" field as your answer.
index="empire" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
4.680851063829787
ANSWER 4.680851063829787
Use the "printnightmare" index and the "bro:dce_rpc:json" sourcetype to create a Splunk search that will detect possible exploitation of the PrintNightmare vulnerability. Enter the IP included in the "id.orig_h" field as your answer.
index=printnightmare sourcetype=bro:dce_rpc:json
| table id.orig_h, operation, proc_name
| dedup id.orig_h
192.168.1.149
ANSWER 192.168.1.149
Use the "bloodhound_all_no_kerberos_sign" index and the "bro:dce_rpc:json" sourcetype to create a Splunk search that will detect possible BloodHound activity (https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/). Enter the IP included in the "id.orig_h" field as your answer.
index=bloodhound_all_no_kerberos_sign sourcetype=bro:dce_rpc:json
| table id.orig_h
| dedup id.orig_h
192.168.109.105
ANSWER 192.168.109.105

| _time | QueryName | QueryResults |
| --- | --- | --- |
| 2023-07-25 13:01:20 | financefileshare | ::1; ::ffff:10.10.0.221; |
| 2023-07-25 13:01:52 | myfileshar3 | ::1; ::ffff:10.10.0.221; |
| 2023-07-25 13:07:05 | myshare | ::1; ::ffff:10.10.0.221; |



| Event ID | Description |
| --- | --- |
| 4648 | Explicit credential logon attempt |
| 4624 | Successful logon |
| 4672 | Special logon with elevated privileges |
| 4768 | Kerberos TGT request |
| 4769 | Kerberos service ticket (TGS) request |
| 4770 | Kerberos service ticket renewal |
| 4771 | Kerberos pre-authentication failure |



| Technique | Detection Approach |
| --- | --- |
| Mimikatz OtH | Same as Pass-the-Hash (monitor LSASS memory access, Event ID 4624 with LogonType 9, etc.) |
| Rubeus OtH | Monitor Kerberos TGT requests (Event ID 4768), especially if:  • Requests originate from unusual processes  • Communication occurs on TCP/UDP port 88 from unexpected hosts or executables |



| Folder | Purpose |
| --- | --- |
| /bin | Store scripts |
| /default | Configuration, views, dashboards, navigation files |
| /local | User-modified versions of default files |
| /metadata | Permissions files |

