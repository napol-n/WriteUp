# The Crime Lab

Category: [Endpoint Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=endpoint-forensics)

Tools: [ALEAPP](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=aleapp)[DB , Browser for SQLite](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=db-browser-for-sqlite)

**Scenario**

We're currently in the midst of a murder investigation, and we've obtained the victim's phone as a key piece of evidence. After conducting interviews with witnesses and those in the victim's inner circle, your objective is to meticulously analyze the information we've gathered and diligently trace the evidence to piece together the sequence of events leading up to the incident.

#### Q1 Based on the accounts of the witnesses and individuals close to the victim, it has become clear that the victim was interested in trading. This has led him to invest all of his money and acquire debt. Can you identify the `SHA256` of the trading application the victim primarily used on his phone?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FsU9gISnFWx05MVmpn7bA%2FScreenshot%202025-10-05%20at%2010.12.22%E2%80%AFPM.png?alt=media&#x26;token=53888add-008a-4ce4-abf1-d646aa41a11d" alt=""><figcaption></figcaption></figure>

1. In the **Installed Apps** section, you see a table with:
   * **Bundle ID**
   * **Version Code**
   * **SHA-256 Hash**
2. Look for apps that are trading-related. In your list:

   ```
   com.ticno.olymptrade    672    4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c
   ```

   * `com.ticno.olymptrade` → this is the victim’s trading app (Olymp Trade).
3. Read off the **SHA-256 Hash** column for this entry:

   ```
   4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c
   ```

-\
**SHA256 of the trading app:**\
`4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c`

Answer **`4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c`**

#### Q2 According to the testimony of the victim's best friend, he said, "`While we were together, my friend got several calls he avoided. He said he owed the caller a lot of money but couldn't repay now`". How much does the victim owe this person?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2F8JxlHUzyRRUJdtNuDSyH%2FScreenshot%202025-10-05%20at%2010.14.34%E2%80%AFPM.png?alt=media&#x26;token=2500996d-2340-4670-881d-e129e268356e" alt=""><figcaption></figcaption></figure>

**250,000 EGP** (shown in the SMS body).

Found in ALEAPP → **SMS messages** (mmssms.db) — message dated **2023-09-20 20:09:49**:\
"It's time for you to pay back the money you owe me... Prepare the sum of **250,000 EGP**..."

Answer **`250000`**

#### Q3 What is the name of the person to whom the victim owes money?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FHkQ8qFd0E2PtP4PtfHPc%2FScreenshot%202025-10-05%20at%2010.20.15%E2%80%AFPM.png?alt=media&#x26;token=deed4a7d-6656-4d6e-a33e-5223be644a5e" alt=""><figcaption></figcaption></figure>

* Go to **Contacts** in ALEAPP.
* Search for the phone number **+201172137258**.
* The corresponding contact name is shown.

Answer **`Shady Wahab`**

#### Q4 Based on the statement from the victim's family, they said that on `September 20, 2023`, he departed from his residence without informing anyone of his destination. Where was the victim located at that moment?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhtiUfPEumUsIAvIcl4LK%2FScreenshot%202025-10-05%20at%2010.22.37%E2%80%AFPM.png?alt=media&#x26;token=6b9d41ee-bb9a-410d-8dcd-392c23b3b777" alt=""><figcaption></figcaption></figure>

* Check **Recent Activity\_0** in ALEAPP:
  * This section logs app usage and interactions with maps or location services.
  * Look for entries around **2023-09-20**.
* Identify any Google Maps activity or screenshots in Recent Activity.
* From the lab report / write-up, the relevant entry shows the victim was at:

**Answer** `The Nile Ritz-Carlton`

#### Q5 The detective continued his investigation by questioning the hotel lobby. She informed him that the victim had reserved the room for 10 days and had a flight scheduled thereafter. The investigator believes that the victim may have stored his ticket information on his phone. Look for where the victim intended to travel.

**Answer** `Las Vegas`

#### Q6 After examining the victim's Discord conversations, we discovered he had arranged to meet a friend at a specific location. Can you determine where this meeting was supposed to occur?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fp9eIuQF9wZCzSCNV5QBC%2FScreenshot%202025-10-05%20at%2010.28.03%E2%80%AFPM.png?alt=media&#x26;token=9ce26a0b-8652-4dca-a17d-b6bb08f0c36d" alt=""><figcaption></figcaption></figure>

Answer **`The Mob Museum`**\
\
[https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/the-crime/ ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/the-crime/)
