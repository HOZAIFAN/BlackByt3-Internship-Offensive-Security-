# Browser Password Extraction & Analysis

**Black Byt3 — Offensive Security + AI Fellowship**
Cohort 1.0 | Muhammad Hozaifa Naeem

---

## Overview

This report covers two tasks completed as part of the Black Byt3 fellowship. The work explores how browsers store saved passwords, demonstrates a practical extraction technique in an authorized lab environment, and analyzes the security implications from an adversarial perspective.

---

## Task 1 — Extracting Saved Browser Passwords

The goal was to bypass Chrome's built-in password protection pop-up and extract all saved credentials without requiring any system or lock-screen password.

**Tool used:** WebBrowserPassView by NirSoft

**What I did:**
- Located and downloaded the portable `.exe` utility
- Temporarily disabled Windows Defender (standard lab procedure)
- Ran the tool — all saved passwords appeared in plaintext instantly
- Captured screenshots as evidence

**Key finding:** No admin rights were needed. Chrome's encryption is tied to the Windows user session, meaning any process running as the same user can decrypt saved passwords silently.

---

## Task 2 — Technical Explanation & Red Team Analysis

### Where Chrome Stores Passwords

Chrome uses a SQLite database called `Login Data` stored at:

```
C:\Users\[Username]\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

Passwords are encrypted using **Windows DPAPI** (Data Protection API). The AES master key lives in a companion file called `Local State`. Any process running as the logged-in user can call `CryptUnprotectData()` and get the plaintext back — by design.

### Red Team Perspective

| Attack Vector | What an Attacker Can Do |
|---|---|
| Physical access | Copy two files to USB, decrypt offline in under a minute |
| Malware / phishing | Silent extraction + HTTP exfiltration to C2 server |
| Credential stuffing | Reuse extracted passwords across VPN, email, cloud |
| Insider threat | No technical skill needed, leaves no obvious log trail |

### Defensive Measures

- Use a dedicated password manager (Bitwarden, 1Password)
- Disable browser password saving via Group Policy
- Enable BitLocker + TPM for full-disk encryption
- Lock your screen whenever you step away
- Enable MFA on every account
- Monitor non-Chrome processes accessing `Login Data` (Windows Event ID 4663)

---

## Environment

- **Lab type:** Authorized isolated test environment
- **OS:** Windows
- **Browser:** Google Chrome
- **Accounts used:** Test accounts only — no real credentials involved

---

## Disclaimer

All testing was performed in an authorized lab environment using dummy test accounts. This work is submitted purely for educational purposes as part of the Black Byt3 fellowship curriculum. Running these techniques on any system without explicit written permission is illegal.

---

*Black Byt3 — Offensive Security + AI Fellowship, Cohort 1.0*
