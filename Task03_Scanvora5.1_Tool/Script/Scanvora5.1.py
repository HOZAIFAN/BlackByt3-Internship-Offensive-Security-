#!/usr/bin/env python3
r"""
╔══════════════════════════════════════════════════════════════════════╗
║  ____                                                                ║
║ / ___|  ___ __ _ _ ____   _____  _ __ __ _                          ║
║ \___ \ / __/ _` | '_ \ \ / / _ \| '__/ _` |                         ║
║  ___) | (_| (_| | | | \ V / (_) | | | (_| |                         ║
║ |____/ \___\__,_|_| |_|\_/ \___/|_|  \__,_|                         ║
║                                                                      ║
║  Professional Subdomain Enumeration & Recon Engine  v5.1            ║
║  Author : hyena11-MHN                                                ║
║  Arch   : Fully Async · Modular · Production-Grade                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ─── stdlib ──────────────────────────────────────────────────────────
import asyncio
import json
import logging
import os
import random
import re
import signal
import string
import sys
import time
import ipaddress
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ─── third-party (install: pip install aiohttp aiodns) ───────────────
try:
    import aiohttp
    import aiodns
except ImportError as exc:
    sys.exit(f"[!] Missing dependency: {exc}\n    pip install aiohttp aiodns")

# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS & SCORING
# ══════════════════════════════════════════════════════════════════════

VERSION = "5.1"

BANNER = f"""
\033[91m╔══════════════════════════════════════════════════════════════════════╗
║  ____                                                                ║
║ / ___|  ___ __ _ _ ____   _____  _ __ __ _                          ║
║ \\___ \\ / __/ _` | '_ \\ \\ / / _ \\| '__/ _` |                         ║
║  ___) | (_| (_| | | | \\ V / (_) | | | (_| |                         ║
║ |____/ \\___\\__,_|_| |_|\\_/ \\___/|_|  \\__,_|                         ║
║\033[0m                                                                      \033[91m║
║\033[93m  Professional Subdomain Enumeration & Recon Engine  v{VERSION}           \033[91m║
║\033[93m  Author : hyena11-MHN                                                \033[91m║
║\033[96m  Arch   : Fully Async · Modular · Production-Grade                  \033[91m║
╚══════════════════════════════════════════════════════════════════════╝\033[0m
"""

# Priority scoring keywords
PRIORITY_MAP: Dict[str, int] = {
    # CRITICAL
    "admin": 100, "administrator": 100, "internal": 100, "intranet": 100,
    "auth": 95, "login": 95, "sso": 95, "oauth": 95,
    "api": 90, "graphql": 90, "rest": 90,
    # HIGH
    "dev": 80, "development": 80, "staging": 80, "stage": 80,
    "test": 75, "testing": 75, "qa": 75, "uat": 75,
    "vpn": 85, "remote": 80, "citrix": 85,
    "portal": 80, "dashboard": 80, "panel": 80,
    "git": 85, "gitlab": 85, "jenkins": 85, "jira": 80, "confluence": 80,
    "grafana": 75, "kibana": 75, "elastic": 75, "prometheus": 70,
    # MEDIUM
    "app": 60, "web": 55, "www": 50, "mobile": 55, "m": 50,
    "mail": 60, "smtp": 55, "pop": 50, "imap": 50,
    "shop": 60, "store": 60, "checkout": 65,
    "support": 55, "help": 50, "docs": 50, "wiki": 55,
    # LOW
    "cdn": 20, "static": 20, "assets": 20, "img": 20, "images": 20,
    "media": 25, "video": 25, "cache": 20,
}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
    ]
]

# ══════════════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════════════

def setup_logger(verbose: bool = False) -> logging.Logger:
    lvl = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s"
    logging.basicConfig(level=lvl, format=fmt, datefmt="%H:%M:%S")
    # suppress aiohttp noise
    logging.getLogger("aiohttp").setLevel(logging.ERROR)
    return logging.getLogger("Scanvora")

logger = setup_logger()


def normalize(subdomain: str) -> str:
    """Lowercase, strip whitespace, remove wildcard prefix."""
    return subdomain.strip().lower().lstrip("*.").rstrip(".")


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def score_subdomain(subdomain: str) -> int:
    """Return priority score 0-100 based on keyword match."""
    label = subdomain.split(".")[0]
    return PRIORITY_MAP.get(label, 30)


def random_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ══════════════════════════════════════════════════════════════════════
#  INTERACTIVE WIZARD (NEW)
# ══════════════════════════════════════════════════════════════════════

class ScanvoraWizard:
    """
    Interactive CLI wizard to guide users step-by-step through
    configuration before starting the scan.
    """

    def __init__(self):
        self.config: Dict = {
            "domain": None,
            "mode": None,
            "wordlist": None,
            "max_words": 50_000,
            "skip_brute": False,
            "skip_api": False,
            "concurrency": 40,
            "rpm": 120,
            "vt_key": None,
            "shodan_key": None,
            "st_key": None,
            "verbose": False,
        }

    def _clear(self):
        """Clear screen (works on Unix/Linux and Windows)."""
        os.system("cls" if os.name == "nt" else "clear")

    def _prompt(self, question: str, default: Optional[str] = None) -> str:
        """
        Ask user a question and get response. Type 'exit' to quit.
        """
        if default:
            q = f"\n{question} [{default}]: "
        else:
            q = f"\n{question}: "

        try:
            response = input(q).strip()
            if response.lower() == "exit":
                print("\n\033[93m[!] Exiting.\033[0m")
                sys.exit(0)
            return response if response else (default or "")
        except KeyboardInterrupt:
            print("\n\033[93m[!] Cancelled by user.\033[0m")
            sys.exit(0)

    def _prompt_yn(self, question: str, default: bool = True) -> bool:
        """Ask yes/no question. Default True shows [Y/n], False shows [y/N]."""
        default_str = "Y/n" if default else "y/N"
        response = self._prompt(f"{question} [{default_str}]", "").lower()
        if response in ("yes", "y"):
            return True
        elif response in ("no", "n"):
            return False
        else:
            return default

    def _prompt_int(self, question: str, default: int, min_val: int = 1) -> int:
        """Ask for integer input with validation."""
        while True:
            response = self._prompt(f"{question}", str(default)).strip()
            try:
                val = int(response)
                if val >= min_val:
                    return val
                print(f"  \033[91m[!] Must be >= {min_val}\033[0m")
            except ValueError:
                print(f"  \033[91m[!] Invalid number. Try again.\033[0m")

    def _prompt_choice(self, question: str, choices: List[str]) -> int:
        """
        Display numbered choices and ask user to pick one.
        Returns 0-indexed choice.
        """
        print(f"\n{question}")
        for i, choice in enumerate(choices, 1):
            print(f"  {i}) {choice}")

        while True:
            try:
                response = input("\nEnter choice [1]: ").strip() or "1"
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return idx
                print(f"\033[91m[!] Invalid choice. Try 1-{len(choices)}.\033[0m")
            except ValueError:
                print(f"\033[91m[!] Please enter a number.\033[0m")
            except KeyboardInterrupt:
                print("\n\033[93m[!] Cancelled.\033[0m")
                sys.exit(0)

    def run(self) -> Dict:
        """Run the wizard and return final config dict."""
        print(BANNER)
        print("\n\033[96m✨ Welcome to Scanvora Interactive Setup!\033[0m")
        print("\033[96m This wizard will guide you through configuring your subdomain scan.\033[0m")

        # Step 1: Choose mode
        self._step_choose_mode()

        # Step 2: Ask target domain (always needed)
        self._step_domain()

        # Step 3: Mode-specific configuration
        if self.config["mode"] == "full":
            self._step_full_recon()
        elif self.config["mode"] == "fast":
            self._step_fast_scan()
        elif self.config["mode"] == "brute":
            self._step_brute_force()
        elif self.config["mode"] == "osint":
            self._step_passive_osint()

        # Step 4: API keys (optional)
        self._step_api_keys()

        # Step 5: Review and confirm
        self._step_review()

        return self.config

    # ── STEP 1: Choose Mode ───────────────────────────────────────────

    def _step_choose_mode(self):
        """Ask user which scan mode they want."""
        choices = [
            "Full Recon Scan (all sources, brute force, APIs)",
            "Fast Scan (quick, limited sources)",
            "Brute Force Only",
            "Passive OSINT Only",
            "Exit",
        ]
        idx = self._prompt_choice(
            "\n\033[94mWhat do you want to do?\033[0m",
            choices
        )

        modes = ["full", "fast", "brute", "osint", "exit"]
        selected = modes[idx]

        if selected == "exit":
            print("\n\033[93m[!] Exiting.\033[0m")
            sys.exit(0)

        self.config["mode"] = selected
        print(f"\n  ✅ Mode: \033[92m{choices[idx]}\033[0m")

    # ── STEP 2: Domain ───────────────────────────────────────────────

    def _step_domain(self):
        """Ask for target domain with validation."""
        while True:
            domain = self._prompt(
                "\n\033[94mEnter target domain\033[0m (e.g., example.com)",
                None
            ).lower().strip()

            if not domain:
                print("  \033[91m[!] Domain cannot be empty.\033[0m")
                continue

            # Basic validation: must have at least one dot and valid chars
            if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
                print("  \033[91m[!] Invalid domain format. Try: example.com\033[0m")
                continue

            self.config["domain"] = domain
            print(f"  ✅ Domain: \033[92m{domain}\033[0m")
            break

    # ── STEP 3.1: Full Recon ──────────────────────────────────────────

    def _step_full_recon(self):
        """Configure Full Recon mode."""
        print(f"\n\033[94m=== Full Recon Configuration ===\033[0m")

        # Brute force
        enable_brute = self._prompt_yn(
            "Enable subdomain brute force?",
            default=True
        )

        if enable_brute:
            self.config["skip_brute"] = False
            wordlist = self._prompt(
                "Wordlist path (leave empty for default)",
                None
            )
            if wordlist:
                if not Path(wordlist).exists():
                    print(f"  \033[93m[⚠] Warning: wordlist not found at {wordlist}\033[0m")
                self.config["wordlist"] = wordlist
            max_words = self._prompt_int(
                "Max words to use from wordlist",
                50_000,
                min_val=100
            )
            self.config["max_words"] = max_words
        else:
            self.config["skip_brute"] = True

        # APIs
        enable_api = self._prompt_yn(
            "Enable API-based sources (crt.sh, Wayback, AlienVault, etc.)?",
            default=True
        )
        self.config["skip_api"] = not enable_api

        # Concurrency and rate limit
        self.config["concurrency"] = self._prompt_int(
            "Concurrency level (workers)",
            40,
            min_val=5
        )

        self.config["rpm"] = self._prompt_int(
            "HTTP requests per minute",
            120,
            min_val=10
        )

        print(f"\n  ✅ Full Recon configured")

    # ── STEP 3.2: Fast Scan ───────────────────────────────────────────

    def _step_fast_scan(self):
        """Configure Fast Scan mode (minimal options)."""
        print(f"\n\033[94m=== Fast Scan Configuration ===\033[0m")
        print("  ℹ️  Fast mode: brute force disabled, limited API sources")

        self.config["skip_brute"] = True
        self.config["skip_api"] = False  # Use fast APIs only
        self.config["concurrency"] = self._prompt_int(
            "Concurrency level (workers)",
            30,
            min_val=5
        )
        # Keep default rpm=120

        print(f"\n  ✅ Fast Scan configured")

    # ── STEP 3.3: Brute Force Only ────────────────────────────────────

    def _step_brute_force(self):
        """Configure Brute Force Only mode."""
        print(f"\n\033[94m=== Brute Force Only Configuration ===\033[0m")

        wordlist = self._prompt(
            "Wordlist path (required)",
            None
        )
        while not wordlist:
            print("  \033[91m[!] Wordlist path is required for brute force mode.\033[0m")
            wordlist = self._prompt(
                "Wordlist path",
                None
            )

        if not Path(wordlist).exists():
            print(f"  \033[93m[⚠] Warning: wordlist not found at {wordlist}\033[0m")
            confirm = self._prompt_yn("Continue anyway?", default=False)
            if not confirm:
                print("\n\033[93m[!] Exiting.\033[0m")
                sys.exit(0)

        self.config["wordlist"] = wordlist
        self.config["skip_brute"] = False
        self.config["skip_api"] = True

        max_words = self._prompt_int(
            "Max words to use",
            50_000,
            min_val=100
        )
        self.config["max_words"] = max_words

        self.config["concurrency"] = self._prompt_int(
            "Concurrency level (workers)",
            40,
            min_val=5
        )

        print(f"\n  ✅ Brute Force mode configured")

    # ── STEP 3.4: Passive OSINT Only ──────────────────────────────────

    def _step_passive_osint(self):
        """Configure Passive OSINT Only mode."""
        print(f"\n\033[94m=== Passive OSINT Configuration ===\033[0m")
        print("  ℹ️  Passive OSINT: no brute force, no Shodan/paid APIs\n")

        # Individual OSINT sources
        use_crt = self._prompt_yn("Enable crt.sh?", default=True)
        use_wayback = self._prompt_yn("Enable Wayback Machine?", default=True)
        use_alienvault = self._prompt_yn("Enable AlienVault OTX?", default=True)

        # We'll store these as flags (advanced feature, stored in config)
        self.config["osint_sources"] = {
            "crt_sh": use_crt,
            "wayback": use_wayback,
            "alienvault": use_alienvault,
        }

        self.config["skip_brute"] = True
        self.config["skip_api"] = False  # But limited to free sources

        print(f"\n  ✅ Passive OSINT configured")

    # ── STEP 4: API Keys ──────────────────────────────────────────────

    def _step_api_keys(self):
        """Optionally ask for premium API keys."""
        print(f"\n\033[94m=== Optional API Keys ===\033[0m")
        print("  ℹ️  Leave blank to skip (scans work without these)\n")

        add_keys = self._prompt_yn(
            "Add premium API keys?",
            default=False
        )

        if add_keys:
            vt = self._prompt(
                "VirusTotal API key",
                None
            )
            if vt:
                self.config["vt_key"] = vt

            shodan = self._prompt(
                "Shodan API key",
                None
            )
            if shodan:
                self.config["shodan_key"] = shodan

            st = self._prompt(
                "SecurityTrails API key",
                None
            )
            if st:
                self.config["st_key"] = st

            print(f"\n  ✅ API keys stored")

    # ── STEP 5: Review & Confirm ──────────────────────────────────────

    def _step_review(self):
        """Show config summary and ask for final confirmation."""
        print(f"\n\033[91m{'═'*70}")
        print(f"  SCAN CONFIGURATION SUMMARY")
        print(f"{'═'*70}\033[0m\n")

        print(f"  🎯 Domain             : \033[92m{self.config['domain']}\033[0m")
        print(f"  📋 Mode               : \033[92m{self.config['mode'].upper()}\033[0m")
        print(f"  💪 Concurrency        : \033[92m{self.config['concurrency']}\033[0m")
        print(f"  ⏱️  Rate limit (RPM)   : \033[92m{self.config['rpm']}\033[0m")

        if not self.config["skip_brute"]:
            wl = self.config.get("wordlist") or "(built-in)"
            print(f"  🔨 Brute force        : \033[92mEnabled\033[0m ({wl})")
            print(f"  📦 Max wordlist size  : \033[92m{self.config['max_words']:,}\033[0m")
        else:
            print(f"  🔨 Brute force        : \033[93mDisabled\033[0m")

        if not self.config["skip_api"]:
            print(f"  🌐 API sources        : \033[92mEnabled\033[0m")
            if self.config.get("vt_key"):
                print(f"     └─ VirusTotal      : \033[92m✓\033[0m")
            if self.config.get("shodan_key"):
                print(f"     └─ Shodan          : \033[92m✓\033[0m")
            if self.config.get("st_key"):
                print(f"     └─ SecurityTrails  : \033[92m✓\033[0m")
        else:
            print(f"  🌐 API sources        : \033[93mDisabled\033[0m")

        print(f"\n\033[91m{'═'*70}\033[0m")

        confirmed = self._prompt_yn(
            "\n\033[94mStart scan with this configuration?\033[0m",
            default=True
        )

        if not confirmed:
            print("\n\033[93m[!] Cancelled. Configuration discarded.\033[0m")
            sys.exit(0)

        print("\n\033[92m✨ Starting scan…\033[0m\n")


# ══════════════════════════════════════════════════════════════════════
#  RATE LIMITER  (FIX #1: proper await, not context manager)
# ══════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Token-bucket rate limiter using a semaphore + fixed delay."""

   def __init__(self, rpm: int = 300, concurrency: int = 15):
        self.delay = 1.0 / 5
        self.sem = asyncio.Semaphore(concurrency)
        self._last: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        await self.sem.acquire()
        async with self._lock:
            now = time.monotonic()
            wait = self.delay - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    def release(self):
        self.sem.release()


# ══════════════════════════════════════════════════════════════════════
#  DNS RESOLVER  (FIX #5: caching + retry/backoff)
# ══════════════════════════════════════════════════════════════════════

class DNSResolver:
    """Async DNS with LRU cache and exponential-backoff retry."""

    def __init__(self, retries: int = 3, sem_size: int = 200):
        self._resolver = aiodns.DNSResolver(timeout=3)
        self._cache: Dict[str, Optional[str]] = {}
        self._sem = asyncio.Semaphore(sem_size)
        self.retries = retries

    async def resolve(self, host: str) -> Optional[str]:
        host = normalize(host)
        if host in self._cache:
            return self._cache[host]

        async with self._sem:
            ip = await self._resolve_with_retry(host)
            self._cache[host] = ip
            return ip

    async def _resolve_with_retry(self, host: str) -> Optional[str]:
        backoff = 0.5
        for attempt in range(self.retries):
            try:
                result = await self._resolver.query(host, "A")
                return result[0].host if result else None
            except aiodns.error.DNSError:
                return None          # NXDOMAIN / no answer — don't retry
            except Exception:
                if attempt < self.retries - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
        return None


# ══════════════════════════════════════════════════════════════════════
#  HTTP PROBER  (FIX #6: full fingerprinting + retry/backoff)
# ══════════════════════════════════════════════════════════════════════

class HTTPProber:
    """Async HTTP probing with retry, redirect chain, security headers."""

    def __init__(self, session: aiohttp.ClientSession,
                 rate_limiter: RateLimiter, retries: int = 2):
        self.session = session
        self.rl = rate_limiter
        self.retries = retries

    async def probe(self, subdomain: str) -> Dict:
        result = {
            "live": False, "status": None, "title": None,
            "server": None, "content_length": None,
            "redirect_chain": [], "security_headers": {},
            "technologies": [],
        }

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            data = await self._get_with_retry(url)
            if data:
                result.update(data)
                result["live"] = result["status"] is not None and result["status"] < 500
                break

        return result

    async def _get_with_retry(self, url: str) -> Optional[Dict]:
        backoff = 1.0
        for attempt in range(self.retries + 1):
            try:
                await self.rl.acquire()
                try:
                    return await self._fetch(url)
                finally:
                    self.rl.release()
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < self.retries:
                    await asyncio.sleep(backoff)
                    backoff *= 2
            except Exception:
                break
        return None

    async def _fetch(self, url: str) -> Optional[Dict]:
        redirect_chain = []

        async with self.session.get(
            url, ssl=False, allow_redirects=True,
            max_redirects=10,
        ) as resp:
            redirect_chain = [str(h.url) for h in resp.history]
            status = resp.status
            server = resp.headers.get("Server")
            cl = resp.headers.get("Content-Length")

            sec_hdrs = {
                h: resp.headers.get(h)
                for h in SECURITY_HEADERS
                if resp.headers.get(h)
            }

            title = None
            techs: List[str] = []
            if status < 400:
                try:
                    raw = await asyncio.wait_for(resp.text(), timeout=6)
                    m = re.search(r"<title[^>]*>([^<]{1,200})", raw, re.I)
                    title = m.group(1).strip() if m else None
                    techs = self._fingerprint(raw, resp.headers)
                except Exception:
                    pass

            return {
                "status": status,
                "server": server,
                "content_length": int(cl) if cl and cl.isdigit() else None,
                "redirect_chain": redirect_chain,
                "title": title,
                "security_headers": sec_hdrs,
                "technologies": techs,
            }

    @staticmethod
    def _fingerprint(body: str, headers) -> List[str]:
        techs = []
        checks = [
            (r"wp-content|wp-includes", "WordPress"),
            (r"drupal\.js|Drupal\.settings", "Drupal"),
            (r"joomla", "Joomla"),
            (r"<meta.*generator.*Django", "Django"),
            (r"laravel_session|csrftoken", "Laravel"),
            (r"__rails", "Ruby on Rails"),
            (r"x-powered-by.*php", "PHP"),
            (r"react\.production|__REACT", "React"),
            (r"angular\.min\.js|ng-version", "Angular"),
            (r"vue\.runtime|__vue__", "Vue.js"),
            (r"shopify", "Shopify"),
        ]
        combined = body[:4096].lower()
        for pattern, name in checks:
            if re.search(pattern, combined, re.I):
                techs.append(name)
        powered = headers.get("X-Powered-By", "")
        if powered and powered not in techs:
            techs.append(powered)
        return list(set(techs))


# ══════════════════════════════════════════════════════════════════════
#  WILDCARD DETECTOR  (FIX #3: random-probe, CDN-aware)
# ══════════════════════════════════════════════════════════════════════

class WildcardDetector:
    """
    Detect wildcard DNS by resolving random labels.
    If PROBE_COUNT random subdomains all resolve to the same IP(s),
    the domain is wildcard. CDN ranges are NOT automatically excluded —
    we compare consistency instead of blacklisting IPs.
    """

    PROBE_COUNT = 5

    def __init__(self, resolver: DNSResolver):
        self.resolver = resolver
        self.wildcard_ips: Set[str] = set()

    async def detect(self, domain: str) -> bool:
        probes = [f"{random_label()}.{domain}" for _ in range(self.PROBE_COUNT)]
        ips = await asyncio.gather(*[self.resolver.resolve(p) for p in probes])
        resolved = [ip for ip in ips if ip]

        if len(resolved) < self.PROBE_COUNT:
            # At least some probes returned NXDOMAIN → not a full wildcard
            return False

        ip_set = set(resolved)
        if len(ip_set) <= 2:
            # All random labels resolve to the same 1-2 IPs → wildcard
            self.wildcard_ips = ip_set
            logger.warning(f"🎭 Wildcard detected for {domain} → {ip_set}")
            return True

        return False

    def is_wildcard_ip(self, ip: Optional[str]) -> bool:
        return bool(ip and ip in self.wildcard_ips)


# ══════════════════════════════════════════════════════════════════════
#  ENUMERATION SOURCES
# ══════════════════════════════════════════════════════════════════════

class EnumSource:
    """Base class for all enumeration sources."""
    name: str = "base"

    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain

    async def enumerate(self) -> Set[str]:
        raise NotImplementedError

    def _filter(self, names: Set[str]) -> Set[str]:
        """Normalize and keep only subdomains of target domain."""
        out = set()
        for n in names:
            n = normalize(n)
            if n.endswith(f".{self.domain}") and n != self.domain:
                out.add(n)
        return out


# ── Source: Brute Force ───────────────────────────────────────────────

class BruteForceSource(EnumSource):
    name = "brute_force"

    def __init__(self, session, domain, wordlist_path: Optional[str],
                 resolver: DNSResolver, max_words: int = 50_000,
                 sem_size: int = 300):
        super().__init__(session, domain)
        self.wordlist_path = wordlist_path
        self.resolver = resolver
        self.max_words = max_words
        self._sem = asyncio.Semaphore(sem_size)

    async def enumerate(self) -> Set[str]:
        if not self.wordlist_path:
            logger.info("[-] Brute force: no wordlist provided")
            return set()

        words = self._load_wordlist()
        if not words:
            return set()

        logger.info(f"💥 Brute force: {len(words):,} words against {self.domain}")

        async def try_word(word: str) -> Optional[str]:
            sub = f"{word}.{self.domain}"
            async with self._sem:
                ip = await self.resolver.resolve(sub)
                return sub if ip else None

        tasks = [try_word(w) for w in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found = {r for r in results if isinstance(r, str)}
        logger.info(f"✅ Brute force: {len(found)} resolved")
        return found

    def _load_wordlist(self) -> List[str]:
        try:
            p = Path(self.wordlist_path)
            with p.open(encoding="utf-8", errors="ignore") as f:
                words = []
                for i, line in enumerate(f):
                    if i >= self.max_words:
                        break
                    w = line.strip()
                    if w and not w.startswith("#"):
                        words.append(w)
            logger.info(f"📁 Loaded {len(words):,} words from {p.name}")
            return words
        except FileNotFoundError:
            logger.error(f"Wordlist not found: {self.wordlist_path}")
            return []


# ── Source: crt.sh ────────────────────────────────────────────────────

class CrtShSource(EnumSource):
    name = "crt.sh"
    URL = "https://crt.sh/?q=%25.{domain}&output=json"

    async def enumerate(self) -> Set[str]:
        logger.info("🔍 Querying crt.sh …")
        url = self.URL.format(domain=self.domain)
        for attempt in range(3):
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as resp:
                    if resp.status != 200:
                        return set()
                    data = await resp.json(content_type=None)
                    raw = set()
                    for entry in data:
                        for name in entry.get("name_value", "").splitlines():
                            raw.add(name)
                    found = self._filter(raw)
                    logger.info(f"✅ crt.sh: {len(found)} subdomains")
                    return found
            except asyncio.TimeoutError:
                logger.warning(f"crt.sh timeout (attempt {attempt+1}/3)")
                await asyncio.sleep(2 ** attempt)
            except Exception as exc:
                logger.error(f"crt.sh error: {exc}")
                return set()
        return set()


# ── Source: HackerTarget ─────────────────────────────────────────────

class HackerTargetSource(EnumSource):
    name = "hackertarget"
    URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

    async def enumerate(self) -> Set[str]:
        logger.info("🔍 Querying HackerTarget …")
        url = self.URL.format(domain=self.domain)
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                text = await resp.text()
                if "error" in text[:30].lower() or resp.status != 200:
                    logger.warning(f"HackerTarget: {text[:80]}")
                    return set()
                raw = set()
                for line in text.strip().splitlines():
                    parts = line.split(",")
                    if parts:
                        raw.add(parts[0].strip())
                found = self._filter(raw)
                logger.info(f"✅ HackerTarget: {len(found)} subdomains")
                return found
        except Exception as exc:
            logger.error(f"HackerTarget error: {exc}")
            return set()


# ── Source: AlienVault OTX ───────────────────────────────────────────

class AlienVaultSource(EnumSource):
    name = "alienvault"
    URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    async def enumerate(self) -> Set[str]:
        logger.info("🔍 Querying AlienVault OTX …")
        url = self.URL.format(domain=self.domain)
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json()
                raw = {r.get("hostname", "") for r in data.get("passive_dns", [])}
                found = self._filter(raw)
                logger.info(f"✅ AlienVault OTX: {len(found)} subdomains")
                return found
        except Exception as exc:
            logger.error(f"AlienVault error: {exc}")
            return set()


# ── Source: Wayback Machine ──────────────────────────────────────────

class WaybackSource(EnumSource):
    name = "wayback"
    URL = "http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000"

    async def enumerate(self) -> Set[str]:
        logger.info("🔍 Querying Wayback Machine …")
        url = self.URL.format(domain=self.domain)
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json(content_type=None)
                raw = set()
                for row in data[1:]:  # skip header
                    m = re.match(r"https?://([^/:?#]+)", row[0])
                    if m:
                        raw.add(m.group(1))
                found = self._filter(raw)
                logger.info(f"✅ Wayback: {len(found)} subdomains")
                return found
        except Exception as exc:
            logger.error(f"Wayback error: {exc}")
            return set()


# ── Source: VirusTotal ───────────────────────────────────────────────

class VirusTotalSource(EnumSource):
    name = "virustotal"
    URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

    def __init__(self, session, domain, api_key: str):
        super().__init__(session, domain)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return set()
        logger.info("🔍 Querying VirusTotal …")
        headers = {"x-apikey": self.api_key}
        found: Set[str] = set()
        cursor = None
        for _ in range(20):  # max 20 pages
            params: Dict = {"limit": 40}
            if cursor:
                params["cursor"] = cursor
            try:
                async with self.session.get(
                    self.URL.format(domain=self.domain),
                    headers=headers, params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 401:
                        logger.error("VirusTotal: invalid API key")
                        break
                    if resp.status == 429:
                        logger.warning("VirusTotal: rate limited, sleeping 15s")
                        await asyncio.sleep(15)
                        continue
                    if resp.status != 200:
                        break
                    data = await resp.json()
                    for item in data.get("data", []):
                        sub = normalize(item.get("id", ""))
                        if sub.endswith(f".{self.domain}"):
                            found.add(sub)
                    cursor = data.get("meta", {}).get("cursor")
                    if not cursor:
                        break
            except Exception as exc:
                logger.error(f"VirusTotal error: {exc}")
                break
            await asyncio.sleep(0.3)
        logger.info(f"✅ VirusTotal: {len(found)} subdomains")
        return found


# ── Source: SecurityTrails ───────────────────────────────────────────

class SecurityTrailsSource(EnumSource):
    name = "securitytrails"
    URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    def __init__(self, session, domain, api_key: str):
        super().__init__(session, domain)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return set()
        logger.info("🔍 Querying SecurityTrails …")
        headers = {"APIKEY": self.api_key, "Accept": "application/json"}
        try:
            async with self.session.get(
                self.URL.format(domain=self.domain),
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"SecurityTrails: HTTP {resp.status}")
                    return set()
                data = await resp.json()
                found = {
                    f"{s}.{self.domain}"
                    for s in data.get("subdomains", [])
                    if s
                }
                logger.info(f"✅ SecurityTrails: {len(found)} subdomains")
                return found
        except Exception as exc:
            logger.error(f"SecurityTrails error: {exc}")
            return set()


# ── Source: Passive OSINT via external tools ──────────────────────────
# (FIX #2: subprocess with asyncio.wait_for, proper kill on timeout)

class PassiveOSINTSource(EnumSource):
    name = "osint_tools"

    TOOLS = {
        "subfinder": "subfinder -d {domain} -silent",
        "amass":     "amass enum -passive -d {domain}",
        "assetfinder": "assetfinder --subs-only {domain}",
    }
    TIMEOUT_SEC = 60

    async def enumerate(self) -> Set[str]:
        found: Set[str] = set()
        for tool, cmd_tpl in self.TOOLS.items():
            cmd = cmd_tpl.format(domain=self.domain)
            subs = await self._run_tool(tool, cmd)
            found.update(subs)
        return self._filter(found)

    async def _run_tool(self, name: str, cmd: str) -> Set[str]:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.TIMEOUT_SEC
                )
                lines = stdout.decode(errors="ignore").splitlines()
                found = {l.strip() for l in lines if l.strip()}
                logger.info(f"✅ {name}: {len(found)} lines")
                return found
            except asyncio.TimeoutError:
                logger.warning(f"⏰ {name} timed out — killing process")
                proc.kill()
                await proc.communicate()
                return set()
        except FileNotFoundError:
            logger.debug(f"{name} not installed, skipping")
            return set()
        except Exception as exc:
            logger.error(f"{name} error: {exc}")
            return set()


# ── Source: Shodan (hostname search) ─────────────────────────────────

class ShodanSource(EnumSource):
    name = "shodan"

    def __init__(self, session, domain, api_key: str):
        super().__init__(session, domain)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return set()
        logger.info("🌐 Querying Shodan for subdomains …")
        try:
            url = "https://api.shodan.io/shodan/host/search"
            params = {"key": self.api_key, "query": f"hostname:{self.domain}", "facets": "hostname"}
            async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json()
                raw = set()
                for match in data.get("matches", []):
                    for h in match.get("hostnames", []):
                        raw.add(h)
                found = self._filter(raw)
                logger.info(f"✅ Shodan enum: {len(found)} subdomains")
                return found
        except Exception as exc:
            logger.error(f"Shodan enum error: {exc}")
            return set()


# ══════════════════════════════════════════════════════════════════════
#  SHODAN IP ENRICHMENT
# ══════════════════════════════════════════════════════════════════════

class ShodanEnricher:
    """Query Shodan for open ports and CVEs per public IP."""

    HOST_URL = "https://api.shodan.io/shodan/host/{ip}"

    def __init__(self, session: aiohttp.ClientSession, api_key: str):
        self.session = session
        self.api_key = api_key
        self._cache: Dict[str, Dict] = {}

    async def enrich(self, ip: str) -> Dict:
        if ip in self._cache:
            return self._cache[ip]
        if is_private_ip(ip):
            return {"error": "private IP, skipped"}

        for attempt in range(3):
            try:
                async with self.session.get(
                    self.HOST_URL.format(ip=ip),
                    params={"key": self.api_key},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = {
                            "org":       data.get("org", "N/A"),
                            "country":   data.get("country_name", "N/A"),
                            "os":        data.get("os", "N/A"),
                            "hostnames": data.get("hostnames", []),
                            "ports":     data.get("ports", []),
                            "vulns":     [
                                {"id": cve, "cvss": meta.get("cvss"), "summary": meta.get("summary", "")[:120]}
                                for cve, meta in data.get("vulns", {}).items()
                            ],
                            "isp":       data.get("isp", "N/A"),
                        }
                        self._cache[ip] = result
                        return result
                    elif resp.status == 404:
                        self._cache[ip] = {"error": "not indexed"}
                        return self._cache[ip]
                    elif resp.status == 401:
                        return {"error": "invalid Shodan API key"}
                    elif resp.status == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return {"error": f"HTTP {resp.status}"}
            except asyncio.TimeoutError:
                await asyncio.sleep(2 ** attempt)
            except Exception as exc:
                return {"error": str(exc)}
        return {"error": "max retries exceeded"}


# ══════════════════════════════════════════════════════════════════════
#  MAIN SCANNER ENGINE
# ══════════════════════════════════════════════════════════════════════

class Scanvora:

    def __init__(self, config: Dict):
        self.cfg = config
        self.domain = config["domain"].lower().strip()
        self.results: Dict[str, Dict] = {}
        self._shutdown = False
        self._start = time.monotonic()

    # ── Lifecycle ────────────────────────────────────────────────────

    async def run(self):
        self._install_signal_handlers()

        connector = aiohttp.TCPConnector(
            limit=150, limit_per_host=15, ssl=False, force_close=False
        )
        timeout = aiohttp.ClientTimeout(total=15, connect=5)

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout,
            headers={"User-Agent": f"Scanvora/{VERSION}"}
        ) as session:

            self.resolver = DNSResolver(retries=3)
            self.wildcard_det = WildcardDetector(self.resolver)
            self.rate_limiter = RateLimiter(
                rpm=self.cfg.get("rpm", 120),
                concurrency=self.cfg.get("concurrency", 40),
            )
            self.prober = HTTPProber(session, self.rate_limiter, retries=2)
            self.shodan_enricher = (
                ShodanEnricher(session, self.cfg["shodan_key"])
                if self.cfg.get("shodan_key") else None
            )

            # 1. Wildcard pre-check
            await self.wildcard_det.detect(self.domain)

            # 2. Enumerate from all sources
            all_subs = await self._enumerate_all(session)

            if not all_subs:
                logger.warning("No subdomains found. Exiting.")
                return

            logger.info(f"📊 Total unique (pre-probe): {len(all_subs):,}")

            # 3. Resolve + probe concurrently
            await self._probe_all(all_subs)

            # 4. Shodan enrichment on public IPs
            if self.shodan_enricher:
                await self._enrich_shodan()

            # 5. Report
            self._print_summary()
            self._save_report()

    # ── Enumeration orchestration ─────────────────────────────────────

    async def _enumerate_all(self, session) -> Set[str]:
        sources = []

        if not self.cfg.get("skip_brute"):
            sources.append(BruteForceSource(
                session, self.domain,
                self.cfg.get("wordlist"),
                self.resolver,
                max_words=self.cfg.get("max_words", 50_000),
            ))

        if not self.cfg.get("skip_api"):
            sources += [
                CrtShSource(session, self.domain),
                HackerTargetSource(session, self.domain),
                AlienVaultSource(session, self.domain),
                WaybackSource(session, self.domain),
                PassiveOSINTSource(session, self.domain),
            ]
            if self.cfg.get("vt_key"):
                sources.append(VirusTotalSource(session, self.domain, self.cfg["vt_key"]))
            if self.cfg.get("st_key"):
                sources.append(SecurityTrailsSource(session, self.domain, self.cfg["st_key"]))
            if self.cfg.get("shodan_key"):
                sources.append(ShodanSource(session, self.domain, self.cfg["shodan_key"]))

        tasks = [s.enumerate() for s in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged: Set[str] = set()
        for src, res in zip(sources, results):
            if isinstance(res, set):
                merged.update(res)
            else:
                logger.error(f"Source {src.name} failed: {res}")

        return merged

    # ── Probing ──────────────────────────────────────────────────────

    async def _probe_all(self, subs: Set[str]):
        sem = asyncio.Semaphore(self.cfg.get("concurrency", 40))

        async def probe_one(sub: str):
            if self._shutdown:
                return
            async with sem:
                ip = await self.resolver.resolve(sub)
                if not ip:
                    return  # DNS failure → skip HTTP

                is_wc = self.wildcard_det.is_wildcard_ip(ip)
                http = await self.prober.probe(sub)
                ip_type = "private" if is_private_ip(ip) else "public"
                priority = score_subdomain(sub)
                confidence = self._confidence(ip, http)

                self.results[sub] = {
                    "ip": ip,
                    "ip_type": ip_type,
                    "wildcard": is_wc,
                    "priority": priority,
                    "confidence": confidence,
                    "source": "multi",
                    **http,
                }

                if http["live"] and not is_wc:
                    tag = "\033[91m[CRIT]\033[0m" if priority >= 90 else \
                          "\033[93m[HIGH]\033[0m" if priority >= 70 else \
                          "\033[92m[LIVE]\033[0m"
                    print(
                        f"  {tag} {sub:<45} {ip:<18} "
                        f"HTTP {http['status']} | {(http['title'] or '')[:50]}"
                    )

        await asyncio.gather(*[probe_one(s) for s in subs], return_exceptions=True)

    @staticmethod
    def _confidence(ip: Optional[str], http: Dict) -> int:
        score = 0
        if ip:
            score += 30
        if http.get("live"):
            score += 40
        if http.get("title"):
            score += 15
        if http.get("server"):
            score += 10
        if http.get("technologies"):
            score += 5
        return min(score, 100)

    # ── Shodan enrichment ─────────────────────────────────────────────

    async def _enrich_shodan(self):
        if not self.shodan_enricher:
            return
        public_ips = {
            d["ip"] for d in self.results.values()
            if d.get("ip") and d.get("ip_type") == "public"
        }
        logger.info(f"🌐 Enriching {len(public_ips)} public IPs via Shodan …")

        for ip in public_ips:
            data = await self.shodan_enricher.enrich(ip)
            # Attach to all subdomains sharing this IP
            for sub, rec in self.results.items():
                if rec.get("ip") == ip:
                    rec["shodan"] = data
            await asyncio.sleep(1.1)  # Shodan free tier ≈ 1 req/s

    # ── Report ────────────────────────────────────────────────────────

    def _print_summary(self):
        live = [r for r in self.results.values() if r.get("live") and not r.get("wildcard")]
        critical = [s for s, r in self.results.items() if r.get("priority", 0) >= 90 and r.get("live")]
        public = [r for r in self.results.values() if r.get("ip_type") == "public"]
        private = [r for r in self.results.values() if r.get("ip_type") == "private"]
        elapsed = time.monotonic() - self._start

        print(f"\n\033[91m{'═'*70}")
        print(f"  SCANVORA SUMMARY — {self.domain}")
        print(f"{'═'*70}\033[0m")
        print(f"  ⏱  Duration          : {elapsed:.1f}s")
        print(f"  🌐 Total resolved    : {len(self.results):,}")
        print(f"  ✅ Live (no wildcard): {len(live):,}")
        print(f"  🔴 Critical priority : {len(critical):,}")
        print(f"  🟢 Public IPs        : {len(public):,}")
        print(f"  🟡 Private IPs       : {len(private):,}")
        print(f"  🎭 Wildcard IPs      : {len(self.wildcard_det.wildcard_ips)}")

        if critical:
            print(f"\n\033[91m  🔴 CRITICAL SUBDOMAINS:\033[0m")
            for sub in sorted(critical)[:20]:
                r = self.results[sub]
                print(f"     {sub:<45} {r.get('ip',''):18} HTTP {r.get('status','?')}")

        print(f"\033[91m{'═'*70}\033[0m\n")

    def _save_report(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"scanvora_{self.domain}_{ts}.json"
        txt_file  = f"scanvora_{self.domain}_{ts}.txt"

        live_results = {
            sub: data for sub, data in self.results.items()
            if data.get("live") and not data.get("wildcard")
        }

        report = {
            "tool": f"Scanvora v{VERSION}",
            "author": "hyena11-MHN",
            "target": self.domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": round(time.monotonic() - self._start, 2),
            "wildcard_ips": list(self.wildcard_det.wildcard_ips),
            "stats": {
                "total_resolved": len(self.results),
                "live_non_wildcard": len(live_results),
                "public_ips": sum(1 for r in self.results.values() if r.get("ip_type") == "public"),
                "private_ips": sum(1 for r in self.results.values() if r.get("ip_type") == "private"),
            },
            "all_subdomains": self.results,
            "live_subdomains": live_results,
        }

        with open(json_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        # Human-readable text report
        with open(txt_file, "w") as f:
            f.write(f"Scanvora v{VERSION} | Target: {self.domain} | {datetime.utcnow().isoformat()}Z\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Total resolved : {len(self.results)}\n")
            f.write(f"Live (no wc)   : {len(live_results)}\n\n")
            f.write("LIVE SUBDOMAINS (sorted by priority)\n")
            f.write("-" * 70 + "\n")
            sorted_live = sorted(
                live_results.items(),
                key=lambda kv: kv[1].get("priority", 0),
                reverse=True
            )
            for sub, data in sorted_live:
                vuln_count = len(data.get("shodan", {}).get("vulns", []))
                vuln_tag = f" [{vuln_count} CVEs]" if vuln_count else ""
                f.write(
                    f"{sub:<50} {data.get('ip',''):18} "
                    f"HTTP {data.get('status','?'):>4}  "
                    f"P={data.get('priority',0):>3}  "
                    f"C={data.get('confidence',0):>3}%"
                    f"{vuln_tag}\n"
                )

        logger.info(f"📄 JSON report  → {json_file}")
        logger.info(f"📄 Text report  → {txt_file}")

    # ── Graceful shutdown ─────────────────────────────────────────────

    def _install_signal_handlers(self):
        def _handler(sig, frame):
            print("\n\033[93m[!] Interrupted — saving progress…\033[0m")
            self._shutdown = True
            self._print_summary()
            self._save_report()
            sys.exit(0)

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)


# ══════════════════════════════════════════════════════════════════════
#  REFACTORED MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    """
    Refactored main() that uses interactive wizard.
    No args parsing — just the wizard.
    """
    # Run the interactive wizard to build config
    wizard = ScanvoraWizard()
    config = wizard.run()

    # Create scanner with final config and run
    scanner = Scanvora(config)
    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
