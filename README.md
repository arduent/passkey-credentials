```markdown
# Passkey-Based Authentication Example

This is a minimal PHP example showing how to add **Passkey** (FIDO2/WebAuthn) registration and login flows to your app using the [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) library.

---

## Features

- Passwordless “register” & “login” via passkeys (platform authenticators or security keys)  
- Email-OTP fallback (no passwords stored)  
- TOTP (“authenticator app”) optional  
- CSRF protection  
- Per-user management of multiple credentials  
- Recovery codes & email reset flows  

---

## Prerequisites

- **PHP 8.0+** with `ext-openssl` & `ext-json`  
- **Composer** for dependency management  
- **HTTPS** (WebAuthn requires a secure origin)  
- A web server (Apache, Nginx, PHP-FPM, etc.)  
- optional - A PDO-enabled database (MySQL, MariaDB, SQLite, etc.)

---

## Installation

1. **Clone this repo**  
   ```bash
   git clone https://github.com/your-org/webauthn-example.git
   cd webauthn-example
   ```

2. **Install dependencies**  
   ```bash
   composer install
   ```

3. **Configure your web server**  
   - Point your DocumentRoot at the `public/` folder.  
   - Enable HTTPS with a valid certificate.  
   - Ensure PHP sessions & JSON requests work correctly.

4. **Set up the database**  
   - Create your `users` and `credentials` tables as shown below.  
   - Update your DSN / DB credentials in `config.php`.

   ```sql
   CREATE TABLE users (
     id            INT AUTO_INCREMENT PRIMARY KEY,
     email         VARCHAR(255)    UNIQUE NOT NULL,
     display_name  VARCHAR(255)    NOT NULL,
     password_hash VARCHAR(255)    NULL,
     totp_secret   VARCHAR(64)     NULL,
     totp_enabled  TINYINT(1)      NOT NULL DEFAULT 0,
     created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
   );

   CREATE TABLE credentials (
     id            BINARY(36)      PRIMARY KEY,
     user_id       INT             NOT NULL
       REFERENCES users(id) ON DELETE CASCADE,
     public_key    BLOB            NOT NULL,
     sign_count    BIGINT          NOT NULL,
     transports    VARCHAR(255)    DEFAULT NULL,
     nickname      VARCHAR(100)    DEFAULT NULL,
     created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
   );
   ```

---


composer.json          ← composer refs
composer.lock          ← composer bits
index.php              ← example home controller
layout.html            ← basic layout HTML
login-op.php           ← emits JSON/HTML for Passkey login
login.php              ← validates assertion for login
pk-login.html          ← HTML + JS for Passkey login
pk-reg.html            ← HTML + JS for Passkey registration
register.php           ← validates attestation and stores
registration-op.php    ← emits WebAuthn creation options (JSON)
schema.sql             ← example SQL schema


## Project Structure

```
composer.json          ← composer refs
composer.lock          ← composer bits
index.php              ← example home controller
layout.html            ← basic layout HTML
login-op.php           ← emits JSON/HTML for Passkey login
login.php              ← validates assertion for login
pk-login.html          ← HTML + JS for Passkey login
pk-reg.html            ← HTML + JS for Passkey registration
register.php           ← validates attestation and stores
registration-op.php    ← emits WebAuthn creation options (JSON)
schema.sql             ← example SQL schema
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

This example code is released under the **MIT License**. Feel free to adapt it for your own projects!
```

