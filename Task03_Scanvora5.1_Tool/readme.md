# 🛡️ Scanvora — Subdomain Scanner Made Simple

> **Find hidden subdomains of any website — no technical experience required.**

---

## What Is Scanvora?

Scanvora is a tool that helps you **discover subdomains** — the hidden parts of a website like `mail.example.com`, `api.example.com`, or `admin.example.com`.

It's used by:
- 🔐 Security professionals checking if a company's network is exposed
- 🐛 Bug bounty hunters looking for vulnerabilities to report
- 🏢 IT teams auditing their own infrastructure
- 🎓 Students learning about cybersecurity

**The best part?** You don't need to know any complex commands. Scanvora walks you through everything step by step.

---

## ✨ What Makes This Version Special

The original Scanvora required you to type long, complicated commands. This new version is different:

| Old Way | New Way (This Version) |
|--------|------------------------|
| You had to memorize commands | It asks you questions |
| Easy to make mistakes | It checks your answers |
| No guidance | Step-by-step help |
| Confusing for beginners | Friendly for everyone |

---

## 🚀 Get Started in Under a Minute

**Step 1 — Install dependencies** (one-time only)
```bash
pip install aiohttp aiodns
```

**Step 2 — Run Scanvora**
```bash
python scanvora_wizard.py
```

**Step 3 — Answer the questions**

The tool will ask you things like:
- What website do you want to scan?
- How fast do you want to scan?
- Do you want to save the results?

Just answer and press Enter. That's it!

---

## 🎯 The 4 Scan Modes

Scanvora has 4 different modes depending on what you need:

### 1. 🔍 Full Recon
The most thorough scan. Checks everything.
- **Best for:** Full security audits
- **Time:** 10–30 minutes
- **Coverage:** Maximum

### 2. ⚡ Fast Scan
A quick overview. Gets results fast.
- **Best for:** Quick checks
- **Time:** 1–5 minutes
- **Coverage:** Good (not complete)

### 3. 🔨 Brute Force Only
Tries thousands of common subdomain names.
- **Best for:** When you have a specific wordlist
- **Time:** 5–20 minutes
- **Coverage:** Depends on your wordlist

### 4. 👁️ Passive OSINT
Gathers info without touching the target.
- **Best for:** Staying completely undetected
- **Time:** Under 2 minutes
- **Coverage:** Public info only

---

## 📊 What It Searches

Scanvora checks **10 different sources** to find subdomains:

**Free sources (always available):**
- Certificate Transparency logs
- DNS brute-forcing
- Web scraping search engines
- Archive.org records
- And more...

**Premium sources (optional, need API keys):**
- Shodan — finds exposed servers
- SecurityTrails — massive subdomain database
- VirusTotal — threat intelligence data

---

## 📄 What You Get as Output

After scanning, Scanvora creates two report files:

**JSON Report** — machine-readable data
```
scanvora_example.com_2024-01-15.json
```

**Text Report** — easy to read
```
scanvora_example.com_2024-01-15.txt
```

The reports include:
- All discovered subdomains
- IP addresses
- Open ports
- Priority scores (which ones to look at first)
- CVE data (if you have a Shodan key)

---

## 🏗️ How It's Built

```
┌──────────────────────────────┐
│    Interactive Wizard        │  ← Asks you questions
│    (the friendly part)       │
└──────────────┬───────────────┘
               │
         Your answers
               │
┌──────────────▼───────────────┐
│    Scanner Engine            │  ← Does the actual work
│    (the powerful part)       │
└──────────────────────────────┘
```

The two parts are kept completely separate. This means the powerful scanning engine was not changed — only the way you interact with it was improved.

---

## 🙋 Who Is This For?

**Beginners** — You don't need to know programming. Just run it and answer questions.

**Professionals** — All advanced options are still there. You can tune concurrency, rate limits, wordlists, and API keys.

**Students** — Great for learning how subdomain enumeration works in a practical, hands-on way.

---

## ⚠️ Use Responsibly

Only scan domains you own or have **explicit written permission** to test. Unauthorized scanning may be illegal in your country.

---

## 📚 Learn More

| If you want to... | Read this |
|-------------------|-----------|
| Just get started quickly | `QUICK_START.md` |
| See real examples | `USAGE_EXAMPLES.md` |
| Understand how it works | `ARCHITECTURE_DIAGRAMS.md` |
| Modify the code | `REFACTORING_GUIDE.md` |
| Navigate everything | `INDEX.md` |

---

*Scanvora Interactive Wizard — v5.1 | Production Ready*
