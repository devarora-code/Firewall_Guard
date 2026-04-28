"""
🛡️ LOCAL FIREWALL GUARD - RULES ENGINE
Runs locally as EXE/executable
Manages firewall rules and performs threat detection
"""

import json
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_RULES = {
    "blocked_domains": [
        "malicious.com", "evil.net", "badware.io", "malwarehost.xyz",
        "phishing-site.io", "fake-bank.com", "amazon-verify.xyz",
        "botnet-c2.ru", "ransomware-pay.xyz", "exploit-kit.ru",
        "tech-support-scam.xyz", "adware-host.xyz", "malware.ml",
        "exploitkit.ru", "malwarepack.tk", "virusden.ml", "trojan-host.ga",
        "apple-id-verify.ml", "microsoft-verify.ga", "google-signin.cf",
        "botmaster.ga", "c2-command.tk", "zombie-controller.ml",
        "ransomware-portal.ga", "decrypt-payment.tk", "ransom-portal.ml",
        "exploit-kit.ru", "drive-by-download.tk", "malvertising.ml",
        "tech-support-scam.xyz", "fake-support.tk", "virus-warning.ml",
        "spyware-download.tk", "adware-network.ml", "pup-installer.ga",
    ],
    "whitelisted_domains": [
        "google.com", "github.com", "github.io", "stackoverflow.com",
        "youtube.com", "wikipedia.org", "reddit.com"
    ],
    "dangerous_extensions": [
        ".exe", ".msi", ".dll", ".bat", ".cmd", ".scr", ".pif", ".vbs",
        ".ps1", ".reg", ".jar", ".com"
    ],
    "suspicious_patterns": [
        "suspicious_tld", "excessive_hyphens", "long_domain"
    ],
    "version": 1,
    "last_updated": datetime.now().isoformat()
}

class FirewallRulesEngine:
    def __init__(self):
        self.rules_file = Path('firewall_rules.json')
        self.rules = self.load_rules()
        self.active = True
        self.update_interval = 300  # 5 minutes
        self.startup_time = datetime.now()

    def parse_version(self, value, fallback=1):
        try:
            if isinstance(value, bool):
                return fallback
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str) and value.strip():
                return int(float(value.strip()))
        except (TypeError, ValueError):
            return fallback
        return fallback

    def normalize_rule_list(self, values, *, extensions=False):
        if not isinstance(values, list):
            return []

        normalized = []
        seen = set()

        for value in values:
            item = str(value).strip().lower()
            if not item:
                continue
            if extensions and not item.startswith('.'):
                item = f'.{item.lstrip(".")}'
            if item in seen:
                continue
            seen.add(item)
            normalized.append(item)

        return normalized

    def normalize_rules(self, raw_rules):
        source = raw_rules if isinstance(raw_rules, dict) else {}

        return {
            "blocked_domains": self.normalize_rule_list(
                source.get('blocked_domains', DEFAULT_RULES['blocked_domains'])
            ) or list(DEFAULT_RULES['blocked_domains']),
            "whitelisted_domains": self.normalize_rule_list(
                source.get('whitelisted_domains', DEFAULT_RULES['whitelisted_domains'])
            ) or list(DEFAULT_RULES['whitelisted_domains']),
            "dangerous_extensions": self.normalize_rule_list(
                source.get('dangerous_extensions', DEFAULT_RULES['dangerous_extensions']),
                extensions=True
            ) or list(DEFAULT_RULES['dangerous_extensions']),
            "suspicious_patterns": self.normalize_rule_list(
                source.get('suspicious_patterns', DEFAULT_RULES['suspicious_patterns'])
            ) or list(DEFAULT_RULES['suspicious_patterns']),
            "version": self.parse_version(source.get('version'), DEFAULT_RULES['version']),
            "declared_version": self.parse_version(
                source.get('declared_version'),
                self.parse_version(source.get('version'), DEFAULT_RULES['version'])
            ),
            "last_updated": source.get('last_updated') or datetime.now().isoformat()
        }

    def extract_hostname(self, url):
        candidate = str(url or '').strip()
        if not candidate:
            return ''

        parsed = urlparse(candidate if '://' in candidate else f'http://{candidate}')
        return (parsed.hostname or '').lower()

    def domain_matches(self, hostname, rule_domain):
        host = str(hostname or '').strip('.').lower()
        rule = str(rule_domain or '').strip('.').lower()
        return bool(host and rule) and (host == rule or host.endswith(f'.{rule}'))

    def match_domain(self, hostname, domains):
        for domain in domains:
            if self.domain_matches(hostname, domain):
                return domain
        return ''

    def load_rules(self):
        """Load rules from local file"""
        if self.rules_file.exists():
            try:
                loaded_rules = json.loads(self.rules_file.read_text())
                normalized_rules = self.normalize_rules(loaded_rules)
                if normalized_rules != loaded_rules:
                    self.save_rules(normalized_rules)
                return normalized_rules
            except Exception as e:
                print(f"[Error] Failed to load rules: {e}")
                normalized_rules = self.normalize_rules(DEFAULT_RULES)
                self.save_rules(normalized_rules)
                return normalized_rules
        else:
            normalized_rules = self.normalize_rules(DEFAULT_RULES)
            self.save_rules(normalized_rules)
            return normalized_rules

    def save_rules(self, rules):
        """Save rules to local file"""
        self.rules_file.write_text(json.dumps(self.normalize_rules(rules), indent=2))

    def update_rules(self, new_rules):
        """Update rules from server"""
        self.rules = self.normalize_rules(new_rules)
        self.rules['last_updated'] = datetime.now().isoformat()
        self.save_rules(self.rules)
        print(f"[{datetime.now()}] Rules updated from server!")
        return True

    def check_url(self, url):
        """Check URL against rules"""
        domain = self.extract_hostname(url)
        if not domain:
            return {'status': 'blocked', 'reason': 'invalid_url', 'risk': 'high'}

        # Check whitelist
        whitelisted = self.rules.get('whitelisted_domains', [])
        if self.match_domain(domain, whitelisted):
            return {'status': 'allowed', 'reason': 'whitelisted', 'risk': 'low'}

        # Check blocklist
        blocked = self.rules.get('blocked_domains', [])
        if self.match_domain(domain, blocked):
            return {'status': 'blocked', 'reason': 'malicious_domain', 'risk': 'high'}

        # Check domain patterns
        if self.check_suspicious_domain(domain):
            return {'status': 'warning', 'reason': 'suspicious_pattern', 'risk': 'medium'}

        return {'status': 'allowed', 'reason': 'safe', 'risk': 'low'}

    def check_suspicious_domain(self, domain):
        """Check for suspicious patterns"""
        patterns = set(self.rules.get('suspicious_patterns', []))
        suspicious_tlds = ['.ml', '.tk', '.ga', '.cf', '.xyz', '.top', '.club']

        if 'suspicious_tld' in patterns and any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        if 'long_domain' in patterns and len(domain) > 50:
            return True
        if 'excessive_hyphens' in patterns and domain.count('-') > 3:
            return True
        return False

    def check_file(self, filename):
        """Check file against rules"""
        ext = Path(filename).suffix.lower()
        dangerous_exts = self.rules.get('dangerous_extensions', [])
        if ext in dangerous_exts:
            return {'status': 'blocked', 'reason': 'dangerous_extension', 'risk': 'high'}
        return {'status': 'allowed', 'reason': 'safe', 'risk': 'low'}

    def get_status(self):
        """Get engine status"""
        return {
            'engine': 'running',
            'uptime': str(datetime.now() - self.startup_time),
            'rules_version': self.rules.get('version', 0),
            'last_updated': self.rules.get('last_updated'),
            'blocked_domains': len(self.rules.get('blocked_domains', [])),
            'whitelisted': len(self.rules.get('whitelisted_domains', []))
        }

def main():
    engine = FirewallRulesEngine()

    print("="*80)
    print("🛡️  LOCAL FIREWALL GUARD - RULES ENGINE")
    print("="*80)
    print(f"Started: {datetime.now()}")
    print(f"Rules loaded: {len(engine.rules.get('blocked_domains', []))} domains")
    print(f"Version: {engine.rules.get('version')}")
    print()

    test_urls = [
        'https://google.com',
        'https://malicious.com',
        'https://suspicious-site-with-long-name.xyz'
    ]

    print("Testing URLs with local engine:")
    for url in test_urls:
        result = engine.check_url(url)
        print(f"  {url} -> {result}")
    print()

    print("[Engine Ready]")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{datetime.now()}] Shutting down...")

if __name__ == '__main__':
    main()
