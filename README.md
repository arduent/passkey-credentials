# Passkey-Based Authentication Example

---

## Introduction

This is a minimal PHP example showing how to add **Passkey** (FIDO2/WebAuthn) registration and login flows to your app using the [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) library.

The registration-op.php script generates a random challenge and sends to the client. The client signs the challenge and sends back the signed data and key id to the server. The server stores the key id and public key. When the user logs in, the server sends a list of keys for that user account (the user can register as many as they wish). The documentation for webauthn-framework recommends sending random data mixed with keys to prevent key enumeration. When the user wants to login, they enter their email address (anonymous setup is also possible), and the server sends the list of public keys and a random challenge. The user decideds which public key they have / want to use and signs the challenge, and sends the signature and public key back to the server. The client also keeps track of how many times the key was used to authenticate, as well as any other changes the user may make to their public key info, so it's a good idea to store the updated public key data in the credentials database. (you may wish to use an immutable database and/or record changes)

---

## Features

- Passwordless “register” & “login” via passkeys (platform authenticators or security keys)  
- CSRF protection  
- Can add Per-user management of multiple credentials  

---

## Prerequisites

- **PHP 8.0+** with `ext-openssl` & `ext-json`  
- **Composer** for dependency management  
- **HTTPS** (WebAuthn requires a secure origin)  
- A web server (Apache, Nginx, PHP-FPM, etc.)  
- optional - A PDO-enabled database (MySQL, MariaDB, SQLite, etc.)

---

## Project Structure

```
composer.json          . composer refs
composer.lock          . composer bits
index.php              . example home controller
layout.html            . basic layout HTML
login-op.php           . emits JSON/HTML for Passkey login
login.php              . validates assertion for login
pk-login.html          . HTML + JS for Passkey login
pk-reg.html            . HTML + JS for Passkey registration
register.php           . validates attestation and stores
registration-op.php    . emits WebAuthn creation options (JSON)
schema.sql             . example SQL schema
```

---

## Usage

### 1. Register a Passkey

1. Browse to registration URL, example: `https://yourdomain/pk-reg`.  
2. Fill in form including **Email**, **Name**
3. Click **Sign up & Register Passkey**.  
4. Approve the OS/device prompt.  
5. You’ll be redirected to `/pk-login`.

### 2. Login with Passkey

1. Go to your login URL, for example: `https://yourdomain/pk-login`.  
2. Enter your **Email** and click **Login with Passkey**.  
3. Approve the OS/device prompt.  
4. You’re logged in and your session is established.

## CSRF Protection

All state-changing endpoints (PHP scripts) require a valid per-session CSRF token:

1. `config.php` bootstraps `session_start()` and generates `$_SESSION['csrf_token']`.  
2. `register.html` & `login.html` include:
   ```html
   <meta name="csrf-token" content="<?= $_SESSION['csrf_token'] ?>">
   ```
3. JS reads it and sends it in the `X-CSRF-Token` header (or JSON body).  
4. PHP endpoints verify via:
   ```php
   if (!hash_equals($_SESSION['csrf_token'], $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
     http_response_code(403); exit('Invalid CSRF');
   }
   ```

---

## Configuration

Edit `index.php` to set:

```php

define('MYSERVICENAME','My Fancy Fun Example');
define('MYDOMAINNAME','myfancyfun.example.com');

$conn=mysqli_connect('127.0.0.1','user','pass','database') or die('no connecto');

```

---

## Further Reading

- Official WebAuthn spec & guides  
  https://webauthn-doc.spomky-labs.com/  
- web-auth/webauthn-framework library  
  https://github.com/web-auth/webauthn-framework  
- FIDO Alliance & MDN overview  
  https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API  

---

## License

This example code is released under the **MIT License**. 

Contact Waitman Gobble <waitman@quantificant.com> if you need help.


